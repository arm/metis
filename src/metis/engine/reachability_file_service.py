# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import logging
import os
import re
import threading

from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path

from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate

from metis.usage import submit_with_current_context
from metis.utils import parse_json_output, read_file_content

from .reachability_service import (
    Deduplicator,
    FunctionNode,
    GlobalConstruct,
    GraphBuilder,
    PathTracer,
    ReachabilityGraph,
    ReachabilityPath,
    VulnerabilityFinding,
    _VULN_TO_CWE,
    _dedupe_paths,
    _normalise_vuln_type,
    _post_filter_findings,
    _read_function_body,
    _read_line_context,
    _safe_int,
    _same_file_ref,
    _severity_title,
)
from .repository import EngineRepository
from .runtime import EngineConfig

logger = logging.getLogger("metis")


_C_CPP_EXTS = frozenset({".c", ".h", ".cc", ".cpp", ".hpp", ".hh", ".hxx", ".cxx"})
_CONTROL_CALLS = frozenset({
    "if", "for", "while", "switch", "return", "sizeof", "alignof", "_Generic",
    "case", "do", "else", "typedef", "defined",
})
_COMMON_LIBC_CALLS = frozenset({
    "malloc", "calloc", "realloc", "free", "memcpy", "memmove", "memset",
    "strcpy", "strncpy", "strcat", "snprintf", "sprintf", "printf", "fprintf",
    "vfprintf", "fopen", "open", "close", "read", "write", "stat", "lstat",
    "access", "system", "popen",
})
_SECURITY_API_RE = re.compile(
    r"\b(?:memcpy|memmove|strcpy|strcat|strncpy|sprintf|vsprintf|snprintf|"
    r"malloc|calloc|realloc|free|fopen|open|stat|lstat|access|unlink|rename|"
    r"system|popen|exec(?:l|le|lp|lpe|v|ve|vp|vpe)?|printf|fprintf|vprintf|"
    r"vfprintf|recv|read|write|send|ioctl)\s*\(",
    re.IGNORECASE,
)
_SOURCE_RE = re.compile(
    r"\b(?:ioctl|sysfs|debugfs|netlink|recv|read|fread|argv|argc|getenv|"
    r"copy_from_user|user|request|packet|socket|interrupt|irq|firmware|fw)\b",
    re.IGNORECASE,
)
_SINK_KIND_RE = re.compile(
    r"\b(?:memcpy|memmove|strcpy|strcat|sprintf|vsprintf|system|popen|exec|"
    r"fopen|open|stat|lstat|access|free|kfree|vfree|mutex_destroy|"
    r"spin_lock|mutex_lock|ioctl|mmio|dma|doorbell|register|reset)\b",
    re.IGNORECASE,
)
_FIELD_RE = re.compile(r"(?:->|\.)\s*([A-Za-z_][A-Za-z0-9_]*)")
_CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_GLOBAL_REF_RE = re.compile(
    r"\.(?:open|release|ioctl|poll|flush|callback|fn|worker|data|probe|remove|"
    r"shutdown|suspend|resume|read|write)\s*=\s*&?\s*([A-Za-z_][A-Za-z0-9_]*)"
)
_GLOBAL_START_RE = re.compile(
    r"\b(?:struct\s+\w*(?:file_operations|ops|fops)\w*|timer|work|watchdog|ops|fops)\b",
    re.IGNORECASE,
)
_FUNCTION_DEF_RE = re.compile(
    r"(?m)^[ \t]*(?P<signature>(?:[A-Za-z_][A-Za-z0-9_]*[ \t\*\&]+)+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}]*\)\s*"
    r"(?:const\s*)?(?:noexcept\s*)?)\{"
)
_LIFECYCLE_WORDS = frozenset({
    "create", "destroy", "alloc", "free", "init", "term", "setup", "cleanup",
    "open", "release", "close", "flush", "get", "put", "ref", "unref", "map",
    "unmap", "load", "unload", "reload", "enable", "disable", "start", "stop",
    "register", "unregister", "add", "remove", "insert", "erase", "grow",
    "shrink", "suspend", "resume", "schedule", "cancel", "arm", "disarm",
})
_CALLBACK_WORDS = frozenset({
    "callback", "cb", "timer", "work", "worker", "watchdog", "fops", "ops",
    "file_operations", "fn", "poll", "ioctl", "flush", "release",
})
_IMPORTANT_FIELDS = frozenset({
    "nr_pages", "pages", "alias_count", "gpu_mappings", "gpu_mappings_total",
    "ctx_count", "regions", "active", "ready", "state", "flags", "refcount",
    "data", "len", "size", "raw_len", "data_len", "enabled", "loaded",
    "initialized", "powered", "phys_addr", "fault_addr", "permission",
})
_GENERIC_FIELDS = frozenset({"next", "prev", "list", "node", "data", "name", "id"})
_VULN_TYPES = (
    "buffer_overflow, out_of_bounds, integer_overflow, use_after_free, "
    "double_free, double_close, null_deref, command_injection, format_string, "
    "path_traversal, toctou, missing_auth, permission_mismatch, wrong_constant, "
    "wrong_flag_semantic, type_confusion, stale_length, width_mismatch, info_leak, uninitialized_memory, "
    "stale_after_unlock, missing_lock, lock_order, state_order, ordering_gap, "
    "teardown_race, deferred_uaf, callback_lifecycle, refcount_imbalance, "
    "accounting_drift, partial_cleanup, rollback_gap, cleanup_symmetry, "
    "file_ops_lifecycle_gap, stale_pointer, other"
)
_STATE_FIELD_RE = re.compile(
    r"\b(?:(?:[A-Za-z_][A-Za-z0-9_]*(?:->|\.))?"
    r"(?:gpu_ready|ready|enabled|active|initialized|loaded|online|powered|runtime_active|state))\s*=\s*"
    r"(?:1|true|TRUE|[A-Z0-9_]*(?:ON|ACTIVE|READY|LOADED|ENABLED|POWERED)[A-Z0-9_]*)",
    re.IGNORECASE,
)
_STATE_RESET_RE = re.compile(
    r"\b(?:gpu_ready|ready|enabled|active|initialized|loaded|online|powered|runtime_active|state)\s*=\s*"
    r"(?:0|false|FALSE|[A-Z0-9_]*(?:OFF|DISABLED|IDLE|INVALID)[A-Z0-9_]*)",
    re.IGNORECASE,
)
_ERROR_PATH_RE = re.compile(r"\b(?:return\s+(?:-\d+|NULL|nullptr)|goto\s+(?:err|fail|out|cleanup)\w*)\b", re.IGNORECASE)
_PUBLISH_CALL_RE = re.compile(
    r"\b(?:rb_link_node|list_add|hash_add|insert|register|publish|xarray_insert|"
    r"xa_insert|idr_alloc|id_alloc|add)\s*\(",
    re.IGNORECASE,
)
_ROLLBACK_CALL_RE = re.compile(r"\b(?:rb_erase|list_del|hash_del|unregister|remove|erase|delete|del)\s*\(", re.IGNORECASE)
_ALLOC_ARITH_RE = re.compile(
    r"\b(?:malloc|kmalloc|realloc|krealloc|calloc|kcalloc|vzalloc|kvcalloc)\s*\([^;\n]*"
    r"(?:\*|sizeof)\s*[^;\n]*\)|\b[A-Za-z_][A-Za-z0-9_]*(?:count|cap|num|nr|n|len|size)[A-Za-z0-9_]*\s*\*\s*sizeof\s*\(",
    re.IGNORECASE,
)
_OVERFLOW_GUARD_RE = re.compile(r"\b(?:SIZE_MAX|__builtin_mul_overflow|check_mul_overflow|array_size|struct_size|kmalloc_array|kcalloc|kvcalloc)\b|/\s*sizeof\s*\(", re.IGNORECASE)
_LOG_CALL_RE = re.compile(
    r"\b(?:fprintf|printf|snprintf|sprintf|vfprintf|util_log|debug_log|trace|printk|"
    r"dev_info|dev_warn|dev_err|gpu_debug_log|gpu_debug)\s*\(",
    re.IGNORECASE,
)
_SENSITIVE_TOKEN_RE = re.compile(r"\b(?:phys|phys_addr|paddr|dma|addr|fault_addr|pointer|token|key|secret)\b", re.IGNORECASE)
_SENSITIVE_FORMAT_RE = re.compile(r"%(?:0?\d+)?(?:llx|lx|p|x)", re.IGNORECASE)
_VARIADIC_WRAPPER_RE = re.compile(r"\b(?:vfprintf|vprintf|vsprintf|vsnprintf|printf|fprintf|sprintf|snprintf)\s*\(", re.IGNORECASE)
_LOCK_CALL_RE = re.compile(
    r"\b(?P<fn>pthread_mutex_lock|pthread_mutex_unlock|mutex_lock|mutex_unlock|"
    r"spin_lock(?:_irqsave|_irq)?|spin_unlock(?:_irqrestore|_irq)?)\s*\(\s*(?P<arg>[^,\)]+)",
    re.IGNORECASE,
)
_UNLOCK_WORD_RE = re.compile(r"unlock", re.IGNORECASE)
_ASSIGN_FROM_FIELD_RE = re.compile(r"\b(?P<var>(?:cached|saved|old|tmp)[A-Za-z0-9_]*)\s*=\s*[^;\n]*(?:->|\.)[A-Za-z_][A-Za-z0-9_]*")
_DISABLE_NAME_RE = re.compile(r"(?:disable|stop|clear|term|shutdown|release)", re.IGNORECASE)
_DISABLE_STATE_RE = re.compile(
    r"\b(?:enabled|active|powered|ready|pending|state)\s*=\s*(?:0|false|FALSE|[A-Z0-9_]*(?:OFF|DISABLED|IDLE)[A-Z0-9_]*)",
    re.IGNORECASE,
)
_CALLBACK_STORE_RE = re.compile(
    r"(?:callback|work|timer|watchdog)\s*(?:->|\.)\s*(?:data|ctx|fn)\s*=|"
    r"(?:queue|alias|ctx|grp|obj|task|session)\s*(?:->|\.)\s*(?:ctx|pages|data|callback|work|timer)\s*=",
    re.IGNORECASE,
)
_CANCEL_OR_REF_RE = re.compile(r"\b(?:cancel|flush|drain|unregister|del_timer|destroy_workqueue|refcount|kref|get|put|pin|unpin|clear|NULL)\b", re.IGNORECASE)
_PROTOCOL_TOKEN_WORDS = frozenset({
    "protected", "protm", "active", "enable", "enabled", "disable", "disabled",
    "enter", "entered", "exit", "ack", "wait", "flush", "ready", "pending",
    "state", "resume", "suspend", "start", "stop", "mmu", "scheduler", "sched",
    "firmware", "fw", "hwcnt", "counter", "clock", "clk", "power", "reset",
    "doorbell", "gpu", "fault", "irq", "interrupt", "completion", "event",
    "fence", "serialize", "serialise", "sync", "transition",
})
_PROTOCOL_TOKEN_ALIASES = {
    "enabled": "enable",
    "disabled": "disable",
    "entered": "enter",
    "sched": "scheduler",
    "fw": "firmware",
    "clk": "clock",
    "serialise": "serialize",
    "sync": "serialize",
}
_WAIT_ACK_TOKENS = frozenset({"wait", "ack", "completion", "event", "fence"})
_STATE_VERIFY_TOKENS = frozenset({"active", "protected", "protm", "ready", "state", "enter", "enable"})
_TRANSITION_TOKENS = frozenset({
    "protected", "protm", "active", "enable", "disable", "enter", "exit",
    "ready", "pending", "state", "resume", "suspend", "start", "stop",
})
_SUBSYSTEM_TOKENS = frozenset({
    "mmu", "scheduler", "firmware", "hwcnt", "counter", "clock", "power",
    "doorbell", "gpu", "irq", "interrupt",
})
_NOTIFIER_WORDS = frozenset({
    "notifier", "notify", "notification", "event", "completion", "wait",
    "ack", "irq", "interrupt", "workqueue", "work", "callback",
})
_PROTOCOL_TOKEN_RE = re.compile(
    r"\b(?:protected|protm|active|enabled?|disabled?|enter(?:ed)?|exit|ack|wait|"
    r"flush|ready|pending|state|resume|suspend|start|stop|mmu|sched(?:uler)?|"
    r"firmware|fw|hwcnt|counter|clock|clk|power|reset|doorbell|gpu|fault|irq|"
    r"interrupt|completion|event|fence|seriali[sz]e|sync|transition)\w*\b",
    re.IGNORECASE,
)
_NOTIFIER_RE = re.compile(
    r"\b(?:notifier|notify|notification|event|completion|wait|ack|irq|interrupt|workqueue)\w*\b",
    re.IGNORECASE,
)
_PARTIAL_VULN_ALIASES = {
    "wrong_flag_semantic": "wrong_constant",
    "callback_lifecycle": "teardown_race",
    "file_ops_lifecycle_gap": "file_ops_lifecycle_gap",
    "allocation_overflow": "integer_overflow",
}
_PARTIAL_CWE_OVERRIDES = {
    "width_mismatch": "CWE-681",
    "stale_length": "CWE-131",
    "info_leak": "CWE-532",
    "wrong_constant": "CWE-697",
    "wrong_flag_semantic": "CWE-697",
    "missing_lock": "CWE-820",
    "state_order": "CWE-696",
    "ordering_gap": "CWE-696",
    "teardown_race": "CWE-362",
    "callback_lifecycle": "CWE-362",
    "deferred_uaf": "CWE-416",
    "integer_overflow": "CWE-190",
    "partial_cleanup": "CWE-459",
    "rollback_gap": "CWE-460",
    "file_ops_lifecycle_gap": "CWE-362",
    "format_string": "CWE-134",
    "path_traversal": "CWE-22",
    "command_injection": "CWE-78",
}
_PARTIAL_PASS_PRIORITY = {
    "partial_format_and_info_leak": 0,
    "partial_state_publication": 1,
    "partial_publish_rollback": 2,
    "partial_allocation_arithmetic": 3,
    "partial_fops_lifecycle": 4,
    "partial_cross_file_lock_cycle": 5,
    "partial_state_transition_protocol": 6,
    "partial_lock_and_stale": 7,
    "partial_lifecycle": 8,
    "partial_shared_state": 9,
    "partial_inbound_contract": 10,
    "partial_outbound_misuse": 11,
    "partial_target_intra": 12,
    "partial_concurrency": 13,
}


@dataclass
class SymbolDef:
    name: str
    file_path: str
    line_number: int
    signature: str = ""
    body_start: int = 0
    body_end: int = 0


@dataclass
class SymbolMeta:
    has_security_api: bool = False
    has_lifecycle_words: bool = False
    has_callback_words: bool = False
    has_lock_api: bool = False
    has_protocol_words: bool = False
    has_notifier_words: bool = False
    is_source_like: bool = False
    is_sink_like: bool = False
    sink_type_hint: str = ""


@dataclass
class CallSite:
    caller_name: str
    caller_file: str
    caller_line: int
    callee_name: str
    line_number: int
    line_text: str = ""


@dataclass
class FieldUse:
    field: str
    file_path: str
    function_name: str
    line_number: int
    line_text: str = ""


@dataclass(frozen=True)
class LockOrderEdge:
    first_lock: str
    second_lock: str
    file_path: str
    function_name: str
    line_number: int
    line_text: str = ""


@dataclass
class SymbolIndex:
    definitions: dict[str, list[SymbolDef]]
    callsites: dict[str, list[CallSite]]
    field_uses: dict[str, list[FieldUse]]
    globals: list[GlobalConstruct]
    files_indexed: int = 0
    defs_by_file: dict[str, list[SymbolDef]] = field(default_factory=dict)
    defs_by_file_and_name: dict[tuple[str, str], SymbolDef] = field(default_factory=dict)
    calls_by_caller: dict[tuple[str, str], list[str]] = field(default_factory=dict)
    field_uses_by_file: dict[str, list[FieldUse]] = field(default_factory=dict)
    locks_by_symbol: dict[str, list[str]] = field(default_factory=dict)
    lock_edges_by_symbol: dict[str, list[LockOrderEdge]] = field(default_factory=dict)
    symbols_by_lock: dict[str, list[SymbolDef]] = field(default_factory=dict)
    state_tokens_by_symbol: dict[str, list[str]] = field(default_factory=dict)
    symbols_by_state_token: dict[str, list[SymbolDef]] = field(default_factory=dict)
    meta_by_symbol: dict[str, SymbolMeta] = field(default_factory=dict)
    lifecycle_symbols: list[SymbolDef] = field(default_factory=list)
    callback_symbols: list[SymbolDef] = field(default_factory=list)
    notifier_related_symbols: list[SymbolDef] = field(default_factory=list)
    security_symbols: list[SymbolDef] = field(default_factory=list)


@dataclass
class PartialReviewContext:
    target_file: str
    target_nodes: list[FunctionNode]
    inbound_callers: list[FunctionNode]
    outbound_callees: list[FunctionNode]
    shared_state_nodes: list[FunctionNode]
    lifecycle_pair_nodes: list[FunctionNode]
    callback_nodes: list[FunctionNode]
    companion_nodes: list[FunctionNode]
    globals: list[GlobalConstruct]
    candidate_paths: list[ReachabilityPath]


@dataclass
class PartialDetectorResult:
    state_publication_notes: list[str] = None
    publish_rollback_notes: list[str] = None
    allocation_arithmetic_notes: list[str] = None
    format_notes: list[str] = None
    info_leak_notes: list[str] = None
    fops_notes: list[str] = None
    lock_order_notes: list[str] = None
    stale_after_unlock_notes: list[str] = None
    disable_stale_notes: list[str] = None
    callback_lifetime_notes: list[str] = None
    cross_file_lock_notes: list[str] = None
    protocol_notes: list[str] = None
    nodes: list[FunctionNode] = None
    globals: list[GlobalConstruct] = None

    def __post_init__(self):
        for name in (
            "state_publication_notes", "publish_rollback_notes",
            "allocation_arithmetic_notes", "format_notes", "info_leak_notes",
            "fops_notes", "lock_order_notes", "stale_after_unlock_notes",
            "disable_stale_notes", "callback_lifetime_notes",
            "cross_file_lock_notes", "protocol_notes", "nodes", "globals",
        ):
            if getattr(self, name) is None:
                setattr(self, name, [])

    def count(self, name: str) -> int:
        return len(getattr(self, name, []) or [])


@dataclass
class PartialPostFilterStats:
    suppressed_null: int = 0
    suppressed_lock: int = 0
    suppressed_generic: int = 0
    suppressed_non_target: int = 0


@dataclass
class PartialContextCaps:
    max_inbound: int = 80
    max_outbound: int = 80
    max_shared: int = 120
    max_lifecycle: int = 80
    max_callbacks: int = 80
    max_companions: int = 48
    max_total_context_functions: int = 250


def _rel_path(path: str, codebase_path: str) -> str:
    base = os.path.abspath(codebase_path)
    abs_path = path if os.path.isabs(path) else os.path.join(base, path)
    return os.path.relpath(os.path.abspath(abs_path), base).replace("\\", "/")


def _abs_path(rel_or_abs: str, codebase_path: str) -> str:
    if os.path.isabs(rel_or_abs):
        return os.path.abspath(rel_or_abs)
    return os.path.abspath(os.path.join(codebase_path, rel_or_abs))


def _line_number_at(text: str, index: int) -> int:
    return text[:index].count("\n") + 1


def _find_body_end(text: str, open_brace_index: int) -> tuple[int, int]:
    depth = 0
    quote = None
    escape = False
    for idx in range(open_brace_index, len(text)):
        ch = text[idx]
        if quote:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = None
            continue
        if ch in ("'", '"'):
            quote = ch
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth <= 0:
                return idx, _line_number_at(text, idx)
    return len(text), text.count("\n") + 1


def _body_lines(content: str, sym: SymbolDef) -> list[str]:
    lines = content.splitlines()
    return _body_lines_from_lines(lines, sym)


def _body_lines_from_lines(lines: list[str], sym: SymbolDef) -> list[str]:
    start = max(0, sym.body_start - 1)
    end = min(len(lines), max(sym.body_end, sym.body_start))
    return lines[start:end]


def _symbol_unique_name(sym: SymbolDef) -> str:
    return f"{sym.file_path}::{sym.name}"


def _tokens(name: str) -> list[str]:
    return [t for t in re.split(r"[^a-z0-9]+", str(name or "").lower()) if t]


def _module_stem(name: str) -> str:
    parts = _tokens(name)
    while parts and parts[-1] in _LIFECYCLE_WORDS:
        parts.pop()
    return "_".join(parts[:3]) if parts else str(name or "").lower()


def _name_has_any(name: str, words: set[str] | frozenset[str]) -> bool:
    lowered = str(name or "").lower()
    return any(word in lowered for word in words)


def _canonical_protocol_token(token: str) -> str:
    token = str(token or "").lower()
    if token.endswith("ing") and token[:-3] in _PROTOCOL_TOKEN_WORDS:
        token = token[:-3]
    elif token.endswith("ed") and token[:-2] in _PROTOCOL_TOKEN_WORDS:
        token = token[:-2]
    return _PROTOCOL_TOKEN_ALIASES.get(token, token)


def _protocol_tokens_from_text(text: str) -> list[str]:
    tokens = []
    for match in _PROTOCOL_TOKEN_RE.finditer(str(text or "")):
        raw = match.group(0).lower()
        for token in _tokens(raw):
            canonical = _canonical_protocol_token(token)
            if canonical in _PROTOCOL_TOKEN_WORDS:
                tokens.append(canonical)
    return list(dict.fromkeys(tokens))


def _notifier_related_text(text: str) -> bool:
    return bool(_NOTIFIER_RE.search(str(text or "")))


def _function_body_from_symbol(codebase_path: str, sym: SymbolDef, max_chars: int = 5000) -> str:
    node = FunctionNode(
        unique_name=f"{sym.file_path}::{sym.name}",
        file_path=sym.file_path,
        name=sym.name,
        line_number=sym.line_number,
        is_source=False,
        is_sink=False,
    )
    return _read_function_body(codebase_path, node, max_chars=max_chars)


def _normalise_partial_vuln_type(raw) -> str:
    text = str(raw or "other").strip().lower().replace("-", "_").replace(" ", "_")
    return _PARTIAL_VULN_ALIASES.get(text, _normalise_vuln_type(text))


def _split_args(args_text: str) -> list[str]:
    args, current = [], []
    depth = 0
    quote = None
    escape = False
    for ch in str(args_text or ""):
        if quote:
            current.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = None
            continue
        if ch in ("'", '"'):
            quote = ch
            current.append(ch)
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}" and depth > 0:
            depth -= 1
        if ch == "," and depth == 0:
            args.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
    if current or args_text:
        args.append("".join(current).strip())
    return args


def _first_call_args(line: str, fn_name: str) -> list[str]:
    match = re.search(r"\b" + re.escape(fn_name) + r"\s*\((.*)\)", line)
    return _split_args(match.group(1)) if match else []


def _is_string_literal(expr: str) -> bool:
    expr = str(expr or "").strip()
    return bool(re.match(r'^(?:L|u8|u|U)?"(?:\\.|[^"\\])*"$', expr))


def _line_excerpt(line: str, limit: int = 180) -> str:
    text = " ".join(str(line or "").strip().split())
    return text[:limit]


def _normalise_lock_expr(expr: str) -> str:
    expr = re.sub(r"/\*.*?\*/", "", str(expr or ""))
    expr = re.sub(r"\s+", "", expr).strip("&()")
    expr = re.sub(r"^\([^)]*\)", "", expr)
    expr = expr.replace("->", ".").strip("&()")
    if not expr:
        return ""
    for stable in ("hwaccess_lock", "scheduler_lock", "ctx.lock", "queue.lock", "pm.lock", "mmu.lock"):
        if stable in expr:
            return stable
    if expr.endswith(".lock"):
        return ".".join(expr.split(".")[-2:])
    return expr


def _partial_note_tokens(text: str) -> set[str]:
    return {
        t for t in re.split(r"[^a-z0-9]+", str(text or "").lower())
        if len(t) > 2 and t not in {"the", "and", "for", "with", "from", "this", "that"}
    }


class PartialAnalysisCache:
    """Shared per-review cache for partial single-file analysis."""

    def __init__(self, codebase_path: str, index: SymbolIndex | None = None):
        self._cb = os.path.abspath(codebase_path)
        self._index = index
        self._lock = threading.RLock()
        self._content_by_file: dict[str, str] = {}
        self._lines_by_file: dict[str, list[str]] = {}
        self._body_by_symbol: dict[tuple[str, int, bool], str] = {}
        self._node_by_symbol: dict[str, FunctionNode] = {}
        self._fallback_body_by_node: dict[tuple[str, int], str] = {}

    def bind_index(self, index: SymbolIndex | None):
        if index is not None:
            with self._lock:
                if self._index is None:
                    self._index = index

    def content(self, rel_file: str) -> str:
        rel = self._normalise_rel(rel_file)
        with self._lock:
            cached = self._content_by_file.get(rel)
        if cached is not None:
            return cached
        content = read_file_content(_abs_path(rel, self._cb)) or ""
        with self._lock:
            return self._content_by_file.setdefault(rel, content)

    def file_lines(self, rel_file: str) -> list[str]:
        rel = self._normalise_rel(rel_file)
        with self._lock:
            cached = self._lines_by_file.get(rel)
        if cached is not None:
            return cached
        lines = self.content(rel).splitlines()
        with self._lock:
            return self._lines_by_file.setdefault(rel, lines)

    def symbol_lines(self, sym: SymbolDef) -> list[tuple[int, str]]:
        lines = self.file_lines(sym.file_path)
        if sym.body_start > 0 and sym.body_end >= sym.body_start:
            start = max(0, sym.body_start - 1)
            end = min(len(lines), max(sym.body_end, sym.body_start))
            return [(start + offset + 1, line) for offset, line in enumerate(lines[start:end])]
        body = self.symbol_body(sym, max_chars=12000, numbered=False)
        return [(sym.line_number + offset, line) for offset, line in enumerate(body.splitlines())]

    def symbol_body(self, sym: SymbolDef, max_chars: int | None = None, *, numbered: bool = False) -> str:
        unique = _symbol_unique_name(sym)
        limit = -1 if max_chars is None else int(max_chars)
        key = (unique, limit, numbered)
        with self._lock:
            cached = self._body_by_symbol.get(key)
        if cached is not None:
            return cached

        if sym.body_start > 0 and sym.body_end >= sym.body_start:
            pairs = self.symbol_lines(sym)
            if numbered:
                body = "\n".join(f"{line_no}: {line}" for line_no, line in pairs)
            else:
                body = "\n".join(line for _, line in pairs)
            if max_chars is not None and len(body) > max_chars:
                body = body[:max_chars] + "\n"
        else:
            node = FunctionNode(
                unique_name=unique,
                file_path=sym.file_path,
                name=sym.name,
                line_number=sym.line_number,
                is_source=False,
                is_sink=False,
            )
            body = _read_function_body(self._cb, node, max_chars=max_chars or 3000)
            if not numbered:
                body = re.sub(r"(?m)^\s*\d+:\s?", "", body)

        with self._lock:
            return self._body_by_symbol.setdefault(key, body)

    def symbol_for_node(self, index: SymbolIndex | None, node: FunctionNode) -> SymbolDef | None:
        index = index or self._index
        if index is None:
            return None
        return _lookup_symbol(index, self._normalise_rel(node.file_path), node.name)

    def node_body(self, node: FunctionNode, *, max_chars: int = 3000) -> str:
        sym = self.symbol_for_node(self._index, node)
        if sym:
            return self.symbol_body(sym, max_chars=max_chars, numbered=True)
        unique = node.unique_name or f"{node.file_path}::{node.name}"
        key = (unique, int(max_chars))
        with self._lock:
            cached = self._fallback_body_by_node.get(key)
        if cached is not None:
            return cached
        body = _read_function_body(self._cb, node, max_chars=max_chars)
        with self._lock:
            return self._fallback_body_by_node.setdefault(key, body)

    def node_for_symbol(self, index: SymbolIndex | None, sym: SymbolDef) -> FunctionNode:
        index = index or self._index
        unique = _symbol_unique_name(sym)
        with self._lock:
            cached = self._node_by_symbol.get(unique)
        if cached is not None:
            return cached

        calls = _symbol_calls(index, sym) if index else []
        meta = index.meta_by_symbol.get(unique) if index else None
        if meta:
            is_source = meta.is_source_like
            is_sink = meta.is_sink_like
            sink_type = meta.sink_type_hint if is_sink else ""
        else:
            body = self.symbol_body(sym, max_chars=8000, numbered=False)
            match_text = f"{sym.name} {' '.join(calls)} {body}"
            is_source = bool(_SOURCE_RE.search(match_text))
            is_sink = bool(_SINK_KIND_RE.search(match_text) or _SECURITY_API_RE.search(match_text))
            sink_type = _sink_type_for_text(match_text) if is_sink else ""
        node = FunctionNode(
            unique_name=unique,
            file_path=sym.file_path,
            name=sym.name,
            line_number=sym.line_number,
            is_source=is_source,
            is_sink=is_sink,
            calls=calls,
            source_reason="deterministic source-like entry or external input use" if is_source else "",
            sink_type=sink_type,
            sink_reason="deterministic sink-like API/state/lifecycle use" if is_sink else "",
        )
        with self._lock:
            return self._node_by_symbol.setdefault(unique, node)

    def _normalise_rel(self, rel_file: str) -> str:
        rel = str(rel_file or "").replace("\\", "/")
        if os.path.isabs(rel):
            return _rel_path(rel, self._cb)
        return rel


class SymbolIndexBuilder:
    def build(self, files, codebase_path) -> SymbolIndex:
        definitions: dict[str, list[SymbolDef]] = defaultdict(list)
        callsites: dict[str, list[CallSite]] = defaultdict(list)
        field_uses: dict[str, list[FieldUse]] = defaultdict(list)
        field_uses_by_file: dict[str, list[FieldUse]] = defaultdict(list)
        defs_by_file: dict[str, list[SymbolDef]] = defaultdict(list)
        defs_by_file_and_name: dict[tuple[str, str], SymbolDef] = {}
        calls_by_caller: dict[tuple[str, str], list[str]] = {}
        locks_by_symbol: dict[str, list[str]] = {}
        lock_edges_by_symbol: dict[str, list[LockOrderEdge]] = {}
        symbols_by_lock: dict[str, list[SymbolDef]] = defaultdict(list)
        state_tokens_by_symbol: dict[str, list[str]] = {}
        symbols_by_state_token: dict[str, list[SymbolDef]] = defaultdict(list)
        meta_by_symbol: dict[str, SymbolMeta] = {}
        lifecycle_symbols: list[SymbolDef] = []
        callback_symbols: list[SymbolDef] = []
        notifier_related_symbols: list[SymbolDef] = []
        security_symbols: list[SymbolDef] = []
        globals_: list[GlobalConstruct] = []
        files_indexed = 0

        for file_path in files:
            rel = _rel_path(file_path, codebase_path)
            if os.path.splitext(rel)[1].lower() not in _C_CPP_EXTS:
                continue
            content = read_file_content(_abs_path(file_path, codebase_path))
            if not content:
                continue
            files_indexed += 1
            file_lines = content.splitlines()
            defs = self._extract_definitions(content, rel)
            for sym in defs:
                definitions[sym.name].append(sym)
                defs_by_file[sym.file_path].append(sym)
                defs_by_file_and_name.setdefault((sym.file_path, sym.name), sym)
                body_lines = _body_lines_from_lines(file_lines, sym)
                calls = self._extract_function_uses(body_lines, sym, callsites, field_uses, field_uses_by_file)
                caller_key = (sym.file_path, sym.name)
                calls_by_caller[caller_key] = list(dict.fromkeys(
                    calls_by_caller.get(caller_key, []) + calls
                ))
                locks, lock_edges, state_tokens = self._symbol_lock_and_protocol_metadata(sym, body_lines)
                unique = _symbol_unique_name(sym)
                locks_by_symbol[unique] = locks
                lock_edges_by_symbol[unique] = lock_edges
                state_tokens_by_symbol[unique] = state_tokens
                for lock in locks:
                    symbols_by_lock[lock].append(sym)
                for token in state_tokens:
                    symbols_by_state_token[token].append(sym)
                body_text = "\n".join(body_lines)
                meta = self._symbol_meta(sym, calls, body_text, locks, state_tokens)
                meta_by_symbol[unique] = meta
                if meta.has_lifecycle_words:
                    lifecycle_symbols.append(sym)
                if meta.has_callback_words:
                    callback_symbols.append(sym)
                if meta.has_notifier_words:
                    notifier_related_symbols.append(sym)
                if meta.has_security_api:
                    security_symbols.append(sym)
            globals_.extend(self._extract_globals(content, rel))

        return SymbolIndex(
            definitions=dict(definitions),
            callsites=dict(callsites),
            field_uses=dict(field_uses),
            globals=globals_,
            files_indexed=files_indexed,
            defs_by_file=dict(defs_by_file),
            defs_by_file_and_name=defs_by_file_and_name,
            calls_by_caller=calls_by_caller,
            field_uses_by_file=dict(field_uses_by_file),
            locks_by_symbol=locks_by_symbol,
            lock_edges_by_symbol=lock_edges_by_symbol,
            symbols_by_lock=dict(symbols_by_lock),
            state_tokens_by_symbol=state_tokens_by_symbol,
            symbols_by_state_token=dict(symbols_by_state_token),
            meta_by_symbol=meta_by_symbol,
            lifecycle_symbols=lifecycle_symbols,
            callback_symbols=callback_symbols,
            notifier_related_symbols=notifier_related_symbols,
            security_symbols=security_symbols,
        )

    def _extract_definitions(self, content: str, rel_file: str) -> list[SymbolDef]:
        defs: list[SymbolDef] = []
        consumed_until = -1
        for match in _FUNCTION_DEF_RE.finditer(content):
            if match.start() < consumed_until:
                continue
            name = match.group("name")
            if name in _CONTROL_CALLS:
                continue
            signature = " ".join(match.group("signature").split())
            line = _line_number_at(content, match.start())
            end_idx, end_line = _find_body_end(content, match.end() - 1)
            consumed_until = max(consumed_until, end_idx)
            defs.append(SymbolDef(
                name=name,
                file_path=rel_file,
                line_number=line,
                signature=signature,
                body_start=line,
                body_end=end_line,
            ))
        return defs

    def _extract_function_uses(self, lines, sym, callsites, field_uses, field_uses_by_file):
        calls = []
        for offset, line_text in enumerate(lines):
            line_number = sym.body_start + offset
            for call in _CALL_RE.findall(line_text):
                if call in _CONTROL_CALLS:
                    continue
                if line_number == sym.body_start and call == sym.name:
                    continue
                calls.append(call)
                callsites[call].append(CallSite(
                    caller_name=sym.name,
                    caller_file=sym.file_path,
                    caller_line=sym.line_number,
                    callee_name=call,
                    line_number=line_number,
                    line_text=line_text.strip(),
                ))
            for field in _FIELD_RE.findall(line_text):
                use = FieldUse(
                    field=field,
                    file_path=sym.file_path,
                    function_name=sym.name,
                    line_number=line_number,
                    line_text=line_text.strip(),
                )
                field_uses[field].append(use)
                field_uses_by_file[sym.file_path].append(use)
        return list(dict.fromkeys(calls))

    def _symbol_lock_and_protocol_metadata(self, sym: SymbolDef, lines: list[str]) -> tuple[list[str], list[LockOrderEdge], list[str]]:
        locks = []
        edges: list[LockOrderEdge] = []
        held: list[str] = []
        for offset, line_text in enumerate(lines):
            line_number = sym.body_start + offset
            for match in _LOCK_CALL_RE.finditer(line_text):
                lock = _normalise_lock_expr(match.group("arg"))
                if not lock:
                    continue
                locks.append(lock)
                if _UNLOCK_WORD_RE.search(match.group("fn")):
                    if lock in held:
                        held.remove(lock)
                    continue
                for prior in held:
                    if prior == lock:
                        continue
                    edges.append(LockOrderEdge(
                        first_lock=prior,
                        second_lock=lock,
                        file_path=sym.file_path,
                        function_name=sym.name,
                        line_number=line_number,
                        line_text=line_text.strip(),
                    ))
                if lock not in held:
                    held.append(lock)
        text = f"{sym.name}\n{sym.signature}\n" + "\n".join(lines)
        state_tokens = _protocol_tokens_from_text(text)
        return list(dict.fromkeys(locks)), list(dict.fromkeys(edges)), state_tokens

    def _symbol_meta(
        self,
        sym: SymbolDef,
        calls: list[str],
        body: str,
        locks: list[str],
        state_tokens: list[str],
    ) -> SymbolMeta:
        match_text = f"{sym.name} {' '.join(calls)} {body}"
        call_text = " ".join(calls)
        has_security_api = bool(_SECURITY_API_RE.search(match_text))
        has_lifecycle_words = (
            _name_has_any(sym.name, _LIFECYCLE_WORDS)
            or _name_has_any(call_text, _LIFECYCLE_WORDS)
        )
        has_callback_words = (
            _name_has_any(sym.name, _CALLBACK_WORDS)
            or _name_has_any(call_text, _CALLBACK_WORDS)
            or _name_has_any(body, _CALLBACK_WORDS)
        )
        has_lock_api = bool(locks)
        has_protocol_words = bool(state_tokens)
        has_notifier_words = _name_has_any(sym.name, _NOTIFIER_WORDS) or _notifier_related_text(match_text)
        is_source_like = bool(_SOURCE_RE.search(match_text))
        is_sink_like = bool(_SINK_KIND_RE.search(match_text) or has_security_api)
        return SymbolMeta(
            has_security_api=has_security_api,
            has_lifecycle_words=has_lifecycle_words,
            has_callback_words=has_callback_words,
            has_lock_api=has_lock_api,
            has_protocol_words=has_protocol_words,
            has_notifier_words=has_notifier_words,
            is_source_like=is_source_like,
            is_sink_like=is_sink_like,
            sink_type_hint=_sink_type_for_text(match_text) if is_sink_like else "",
        )

    def _extract_globals(self, content: str, rel_file: str) -> list[GlobalConstruct]:
        lines = content.splitlines()
        globals_: list[GlobalConstruct] = []
        idx = 0
        while idx < len(lines):
            line = lines[idx]
            if not _GLOBAL_START_RE.search(line):
                idx += 1
                continue
            start = idx
            block = [line]
            while idx + 1 < len(lines) and "};" not in lines[idx] and idx - start < 80:
                idx += 1
                block.append(lines[idx])
                if "};" in lines[idx]:
                    break
            text = "\n".join(block)
            refs = list(dict.fromkeys(_GLOBAL_REF_RE.findall(text)))
            if refs or any(word in text.lower() for word in _CALLBACK_WORDS):
                name = self._global_name(text, start + 1)
                kind = "callback_table"
                if "file_operations" in text or "fops" in text.lower():
                    kind = "file_operations"
                elif "timer" in text.lower():
                    kind = "timer"
                elif "work" in text.lower() or "worker" in text.lower():
                    kind = "work"
                elif "watchdog" in text.lower():
                    kind = "watchdog"
                globals_.append(GlobalConstruct(
                    unique_name=f"{rel_file}::{name}",
                    file_path=rel_file,
                    name=name,
                    line_number=start + 1,
                    kind=kind,
                    initializer=text[:3000],
                    referenced_functions=refs,
                ))
            idx += 1
        return globals_

    def _global_name(self, text: str, fallback_line: int) -> str:
        match = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*(?:=\s*)?\{", text)
        if match:
            return match.group(1)
        return f"global_{fallback_line}"


def _symbol_calls(index: SymbolIndex, sym: SymbolDef) -> list[str]:
    if not index:
        return []
    if index.calls_by_caller:
        return list(index.calls_by_caller.get((sym.file_path, sym.name), []))
    calls = []
    for callee, sites in index.callsites.items():
        for site in sites:
            if site.caller_file == sym.file_path and site.caller_name == sym.name:
                calls.append(callee)
                break
    return list(dict.fromkeys(calls))


def _symbols_for_file(index: SymbolIndex, file_path: str) -> list[SymbolDef]:
    file_path = file_path.replace("\\", "/")
    if index.defs_by_file:
        return list(index.defs_by_file.get(file_path, []))
    return [
        sym for defs in index.definitions.values()
        for sym in defs if sym.file_path == file_path
    ]


def _lookup_symbol(index: SymbolIndex, file_path: str, name: str) -> SymbolDef | None:
    file_path = file_path.replace("\\", "/")
    sym = index.defs_by_file_and_name.get((file_path, name))
    if sym:
        return sym
    if index.defs_by_file:
        for candidate in index.defs_by_file.get(file_path, []):
            if candidate.name == name:
                return candidate
        return None
    for candidate in index.definitions.get(name, []):
        if candidate.file_path == file_path:
            return candidate
    return None


def _field_uses_for_file(index: SymbolIndex, file_path: str) -> list[FieldUse]:
    file_path = file_path.replace("\\", "/")
    if index.field_uses_by_file:
        return list(index.field_uses_by_file.get(file_path, []))
    return [
        use for uses in index.field_uses.values()
        for use in uses if use.file_path == file_path
    ]


def _all_symbols(index: SymbolIndex) -> list[SymbolDef]:
    if index.defs_by_file:
        return [sym for symbols in index.defs_by_file.values() for sym in symbols]
    return [sym for defs in index.definitions.values() for sym in defs]


def _lifecycle_symbol_candidates(index: SymbolIndex) -> list[SymbolDef]:
    if index.lifecycle_symbols or index.meta_by_symbol:
        return list(index.lifecycle_symbols)
    return [sym for sym in _all_symbols(index) if _name_has_any(sym.name, _LIFECYCLE_WORDS)]


def _callback_symbol_candidates(index: SymbolIndex) -> list[SymbolDef]:
    if index.callback_symbols or index.meta_by_symbol:
        return list(index.callback_symbols)
    return [sym for sym in _all_symbols(index) if _name_has_any(sym.name, _CALLBACK_WORDS)]


def _notifier_symbol_candidates(index: SymbolIndex) -> list[SymbolDef]:
    if index.notifier_related_symbols or index.meta_by_symbol:
        return list(index.notifier_related_symbols)
    return [sym for sym in _all_symbols(index) if _name_has_any(sym.name, _NOTIFIER_WORDS)]


def _security_symbol_candidates(index: SymbolIndex) -> list[SymbolDef]:
    if index.security_symbols or index.meta_by_symbol:
        return list(index.security_symbols)
    return _all_symbols(index)


def _symbol_locks(index: SymbolIndex, sym: SymbolDef) -> set[str]:
    return set(index.locks_by_symbol.get(_symbol_unique_name(sym), []))


def _symbol_state_tokens(index: SymbolIndex, sym: SymbolDef) -> set[str]:
    return set(index.state_tokens_by_symbol.get(_symbol_unique_name(sym), []))


def _symbol_lock_edges(index: SymbolIndex, sym: SymbolDef) -> list[LockOrderEdge]:
    return list(index.lock_edges_by_symbol.get(_symbol_unique_name(sym), []))


def _sink_type_for_text(text: str) -> str:
    tl = text.lower()
    if re.search(r"\b(system|popen|exec)", tl):
        return "command_injection"
    if re.search(r"\b(v?fprintf|printf|sprintf|snprintf)\s*\(", tl):
        return "format_string"
    if re.search(r"\b(fopen|open|stat|lstat|access|unlink|rename)\s*\(", tl):
        return "path_traversal"
    if re.search(r"\b(memcpy|memmove|strcpy|strcat|sprintf|vsprintf)\s*\(", tl):
        return "buffer_overflow"
    if re.search(r"\b(free|kfree|vfree|release|destroy)\b", tl):
        return "use_after_free"
    if re.search(r"\b(mutex|spin|lock|unlock|work|timer|watchdog|callback)\b", tl):
        return "teardown_race"
    if re.search(r"\b(power|ready|enabled|active|mmu|dma|flush|fence)\b", tl):
        return "state_order"
    return "other"


def _symbol_to_node(
    index: SymbolIndex,
    codebase_path: str,
    sym: SymbolDef,
    cache: PartialAnalysisCache | None = None,
) -> FunctionNode:
    if cache is not None:
        return cache.node_for_symbol(index, sym)
    calls = _symbol_calls(index, sym)
    meta = index.meta_by_symbol.get(_symbol_unique_name(sym)) if index else None
    if meta:
        is_source = meta.is_source_like
        is_sink = meta.is_sink_like
        sink_type = meta.sink_type_hint if is_sink else ""
    else:
        body = _function_body_from_symbol(codebase_path, sym, max_chars=8000)
        match_text = f"{sym.name} {' '.join(calls)} {body}"
        is_source = bool(_SOURCE_RE.search(match_text))
        is_sink = bool(_SINK_KIND_RE.search(match_text) or _SECURITY_API_RE.search(match_text))
        sink_type = _sink_type_for_text(match_text) if is_sink else ""
    return FunctionNode(
        unique_name=_symbol_unique_name(sym),
        file_path=sym.file_path,
        name=sym.name,
        line_number=sym.line_number,
        is_source=is_source,
        is_sink=is_sink,
        calls=calls,
        source_reason="deterministic source-like entry or external input use" if is_source else "",
        sink_type=sink_type,
        sink_reason="deterministic sink-like API/state/lifecycle use" if is_sink else "",
    )


class PartialContextBuilder:
    def __init__(
        self,
        codebase_path: str,
        caps: PartialContextCaps | None = None,
        cache: PartialAnalysisCache | None = None,
    ):
        self._cb = os.path.abspath(codebase_path)
        self._caps = caps or PartialContextCaps()
        self._cache = cache or PartialAnalysisCache(codebase_path)

    def build_for_file(
        self,
        target_file: str,
        target_nodes: list[FunctionNode],
        symbol_index: SymbolIndex,
    ) -> PartialReviewContext:
        target_file = target_file.replace("\\", "/")
        self._cache.bind_index(symbol_index)
        target_symbols = _symbols_for_file(symbol_index, target_file)
        if not target_nodes:
            target_nodes = [self._node_for_symbol(symbol_index, sym) for sym in target_symbols]

        target_names = {node.name for node in target_nodes}
        target_calls = self._target_calls(target_nodes, symbol_index, target_symbols)
        target_fields = self._target_fields(target_file, symbol_index)
        target_prefixes = {_module_stem(name) for name in target_names if name}
        target_dir = str(Path(target_file).parent).replace("\\", "/")

        outbound_syms = self._cap_ranked_symbols(
            self._outbound_callees(target_calls, symbol_index, target_file, target_dir, target_prefixes),
            self._caps.max_outbound,
        )
        inbound_syms = self._cap_ranked_symbols(
            self._inbound_callers(target_names, symbol_index, target_file, target_dir, target_prefixes),
            self._caps.max_inbound,
        )
        shared_syms = self._cap_ranked_symbols(
            self._shared_state_nodes(target_fields, symbol_index, target_file, target_dir, target_prefixes),
            self._caps.max_shared,
        )
        lifecycle_syms = self._cap_ranked_symbols(
            self._lifecycle_pair_nodes(target_names, symbol_index, target_file, target_dir, target_prefixes),
            self._caps.max_lifecycle,
        )
        callback_ranked, globals_ = self._callback_context(
            target_file, target_names, symbol_index, target_dir, target_prefixes)
        callback_syms = self._cap_ranked_symbols(callback_ranked, self._caps.max_callbacks)
        inbound_syms, outbound_syms, shared_syms, lifecycle_syms, callback_syms = self._cap_total_symbols(
            inbound_syms, outbound_syms, shared_syms, lifecycle_syms, callback_syms)

        inbound = self._materialize_symbols(symbol_index, inbound_syms)
        outbound = self._materialize_symbols(symbol_index, outbound_syms)
        shared = self._materialize_symbols(symbol_index, shared_syms)
        lifecycle = self._materialize_symbols(symbol_index, lifecycle_syms)
        callbacks = self._materialize_symbols(symbol_index, callback_syms)

        paths = self._candidate_paths(target_nodes, inbound, outbound, shared, lifecycle, callbacks)
        return PartialReviewContext(
            target_file=target_file,
            target_nodes=target_nodes,
            inbound_callers=inbound,
            outbound_callees=outbound,
            shared_state_nodes=shared,
            lifecycle_pair_nodes=lifecycle,
            callback_nodes=callbacks,
            companion_nodes=[],
            globals=globals_,
            candidate_paths=paths,
        )

    def expand_companions(
        self,
        context: PartialReviewContext,
        index: SymbolIndex,
        *,
        progress_callback=None,
    ) -> int:
        selected = {_symbol_unique_name(sym): sym for sym in _symbols_for_file(index, context.target_file)}
        selected.update({_symbol_unique_name(sym): sym for sym in self._context_symbols(index, context)})
        selected_syms = list(selected.values())
        signal = self._companion_signal(index, context, selected_syms)
        if not signal["enabled"]:
            return 0
        if progress_callback:
            progress_callback({
                "event": "partial_companion_expansion_start",
                "locks": len(signal["locks"]),
                "state_tokens": len(signal["state_tokens"]),
                "callback_or_notifier": bool(signal["callback_or_notifier"]),
            })
        ranked = self._companion_candidates(index, context, signal)
        limit = max(0, int(self._caps.max_companions or 0))
        companions = self._cap_ranked_symbols(ranked, limit)
        existing = {node.unique_name for node in self._all_context_nodes(context)}
        companions = [sym for sym in companions if _symbol_unique_name(sym) not in existing]
        context.companion_nodes = self._dedupe_nodes(
            list(context.companion_nodes or []) + self._materialize_symbols(index, companions)
        )
        context.candidate_paths = _dedupe_paths(
            list(context.candidate_paths or []) + self._companion_paths(index, context)
        )
        if progress_callback:
            progress_callback({
                "event": "partial_companion_expansion_done",
                "companions": len(context.companion_nodes),
                "candidate_symbols": len(ranked),
            })
        return len(context.companion_nodes)

    def _context_symbols(self, index: SymbolIndex, context: PartialReviewContext) -> list[SymbolDef]:
        symbols = {}
        for node in self._all_context_nodes(context):
            sym = _lookup_symbol(index, node.file_path, node.name)
            if sym:
                symbols[_symbol_unique_name(sym)] = sym
        return list(symbols.values())

    def _all_context_nodes(self, context: PartialReviewContext) -> list[FunctionNode]:
        nodes = {}
        for group in (
            context.target_nodes, context.inbound_callers, context.outbound_callees,
            context.shared_state_nodes, context.lifecycle_pair_nodes,
            context.callback_nodes, context.companion_nodes,
        ):
            for node in group or []:
                nodes[node.unique_name] = node
        return list(nodes.values())

    def _companion_signal(self, index: SymbolIndex, context: PartialReviewContext, symbols: list[SymbolDef]) -> dict:
        locks: set[str] = set()
        state_tokens: set[str] = set()
        has_lock_edges = False
        callback_or_notifier = False
        lifecycle_concurrency = False
        for sym in symbols:
            unique = _symbol_unique_name(sym)
            meta = index.meta_by_symbol.get(unique)
            sym_locks = _symbol_locks(index, sym)
            sym_tokens = _symbol_state_tokens(index, sym)
            locks.update(sym_locks)
            state_tokens.update(sym_tokens)
            has_lock_edges = has_lock_edges or bool(_symbol_lock_edges(index, sym))
            callback_or_notifier = callback_or_notifier or bool(
                meta and (meta.has_callback_words or meta.has_notifier_words)
            )
            lifecycle_concurrency = lifecycle_concurrency or bool(
                meta and meta.has_lifecycle_words and (sym_locks or (sym_tokens & _TRANSITION_TOKENS))
            )
        strong_protocol = bool(state_tokens & (_WAIT_ACK_TOKENS | _STATE_VERIFY_TOKENS | _SUBSYSTEM_TOKENS))
        enabled = bool(has_lock_edges or callback_or_notifier or strong_protocol or lifecycle_concurrency)
        return {
            "enabled": enabled,
            "locks": locks,
            "state_tokens": state_tokens,
            "has_lock_edges": has_lock_edges,
            "callback_or_notifier": callback_or_notifier,
            "lifecycle_concurrency": lifecycle_concurrency,
        }

    def _companion_candidates(self, index: SymbolIndex, context: PartialReviewContext, signal: dict) -> list:
        target_file = context.target_file
        target_dir = str(Path(target_file).parent).replace("\\", "/")
        target_names = {node.name for node in context.target_nodes}
        target_prefixes = {_module_stem(name) for name in target_names if name}
        existing = {node.unique_name for node in self._all_context_nodes(context)}
        ranked = {}

        for lock in signal["locks"]:
            for sym in index.symbols_by_lock.get(lock, [])[:160]:
                self._remember_companion_candidate(
                    ranked, index, sym, target_file, target_dir, target_prefixes,
                    signal, existing, bonus=42,
                )
        for token in signal["state_tokens"]:
            for sym in index.symbols_by_state_token.get(token, [])[:180]:
                self._remember_companion_candidate(
                    ranked, index, sym, target_file, target_dir, target_prefixes,
                    signal, existing, bonus=32,
                )
        if signal["callback_or_notifier"]:
            for sym in (_callback_symbol_candidates(index) + _notifier_symbol_candidates(index))[:220]:
                self._remember_companion_candidate(
                    ranked, index, sym, target_file, target_dir, target_prefixes,
                    signal, existing, bonus=26,
                )
        if signal["lifecycle_concurrency"]:
            for sym in _lifecycle_symbol_candidates(index)[:220]:
                self._remember_companion_candidate(
                    ranked, index, sym, target_file, target_dir, target_prefixes,
                    signal, existing, bonus=18,
                )
        return list(ranked.values())

    def _remember_companion_candidate(
        self,
        ranked_by_unique,
        index: SymbolIndex,
        sym: SymbolDef,
        target_file: str,
        target_dir: str,
        target_prefixes: set[str],
        signal: dict,
        existing: set[str],
        *,
        bonus: int,
    ):
        unique = _symbol_unique_name(sym)
        if unique in existing:
            return
        sym_dir = str(Path(sym.file_path).parent).replace("\\", "/")
        sym_stem = _module_stem(sym.name)
        lock_overlap = len(_symbol_locks(index, sym) & signal["locks"])
        token_overlap = len(_symbol_state_tokens(index, sym) & signal["state_tokens"])
        if not lock_overlap and not token_overlap and sym_dir != target_dir and sym_stem not in target_prefixes:
            return
        score_bonus = bonus + min(30, lock_overlap * 12) + min(24, token_overlap * 8)
        if sym_dir == target_dir:
            score_bonus += 28
        elif sym_dir.startswith(target_dir) or target_dir.startswith(sym_dir):
            score_bonus += 14
        if sym_stem in target_prefixes or any(
            sym_stem.startswith(prefix) or prefix.startswith(sym_stem)
            for prefix in target_prefixes if prefix
        ):
            score_bonus += 18
        meta = index.meta_by_symbol.get(unique)
        if meta and (meta.has_callback_words or meta.has_notifier_words):
            score_bonus += 10
        rank = self._rank_symbol(index, sym, target_file, target_dir, target_prefixes, bonus=score_bonus)
        self._remember_ranked_symbol(ranked_by_unique, rank, sym)

    def _companion_paths(self, index: SymbolIndex, context: PartialReviewContext) -> list[ReachabilityPath]:
        paths = []
        for target_node in context.target_nodes:
            target_sym = _lookup_symbol(index, target_node.file_path, target_node.name)
            target_locks = _symbol_locks(index, target_sym) if target_sym else set()
            target_tokens = _symbol_state_tokens(index, target_sym) if target_sym else set()
            for node in context.companion_nodes:
                sym = _lookup_symbol(index, node.file_path, node.name)
                if not sym:
                    continue
                if (
                    target_node.name in node.calls
                    or node.name in target_node.calls
                    or target_locks & _symbol_locks(index, sym)
                    or target_tokens & _symbol_state_tokens(index, sym)
                    or _module_stem(target_node.name) == _module_stem(node.name)
                ):
                    paths.append(ReachabilityPath(
                        target_node.unique_name,
                        node.unique_name,
                        [target_node.unique_name, node.unique_name],
                        node.sink_type,
                    ))
        return paths

    def _dedupe_nodes(self, nodes: list[FunctionNode]) -> list[FunctionNode]:
        seen, out = set(), []
        for node in nodes:
            if node.unique_name in seen:
                continue
            seen.add(node.unique_name)
            out.append(node)
        return out

    def _target_calls(self, target_nodes, index, target_symbols):
        calls = []
        for node in target_nodes:
            calls.extend(node.calls or [])
        for sym in target_symbols:
            calls.extend(_symbol_calls(index, sym))
        return list(dict.fromkeys(c for c in calls if c not in _CONTROL_CALLS))

    def _target_fields(self, target_file, index):
        return {use.field for use in _field_uses_for_file(index, target_file)}

    def _rank_symbol(self, index: SymbolIndex, sym: SymbolDef, target_file, target_dir, target_prefixes, bonus=0):
        score = bonus
        if sym.file_path == target_file:
            score += 100
        if str(Path(sym.file_path).parent).replace("\\", "/") == target_dir:
            score += 45
        stem = _module_stem(sym.name)
        if stem in target_prefixes or any(stem.startswith(p) or p.startswith(stem) for p in target_prefixes if p):
            score += 30
        calls = _symbol_calls(index, sym)
        meta = index.meta_by_symbol.get(_symbol_unique_name(sym))
        if (meta and meta.has_security_api) or any(
            _SECURITY_API_RE.search(f"{call}(") or call in _COMMON_LIBC_CALLS for call in calls
        ):
            score += 12
        if (meta and meta.has_lifecycle_words) or _name_has_any(sym.name, _LIFECYCLE_WORDS):
            score += 8
        if (meta and meta.has_callback_words) or _name_has_any(sym.name, _CALLBACK_WORDS):
            score += 10
        if "\\test\\" in sym.file_path.lower() or "/test/" in sym.file_path.lower():
            score -= 15
        return (-score, sym.file_path, int(sym.line_number or 0), sym.name)

    def _cap_ranked_symbols(self, ranked, limit):
        seen = set()
        result = []
        for _, sym in sorted(ranked, key=lambda item: item[0]):
            unique = _symbol_unique_name(sym)
            if unique in seen:
                continue
            seen.add(unique)
            result.append(sym)
            if len(result) >= limit:
                break
        return result

    def _cap_total_symbols(self, *groups):
        cap = self._caps.max_total_context_functions
        selected = []
        seen = set()
        output = []
        for group in groups:
            kept = []
            for sym in group:
                unique = _symbol_unique_name(sym)
                if unique in seen:
                    continue
                if len(selected) >= cap:
                    break
                seen.add(unique)
                selected.append(sym)
                kept.append(sym)
            output.append(kept)
        return output

    def _materialize_symbols(self, index: SymbolIndex, symbols: list[SymbolDef]) -> list[FunctionNode]:
        return [self._node_for_symbol(index, sym) for sym in symbols]

    def _node_for_symbol(self, index: SymbolIndex, sym: SymbolDef) -> FunctionNode:
        return _symbol_to_node(index, self._cb, sym, self._cache)

    def _remember_ranked_symbol(self, ranked_by_unique, rank, sym: SymbolDef):
        unique = _symbol_unique_name(sym)
        current = ranked_by_unique.get(unique)
        if current is None or rank < current[0]:
            ranked_by_unique[unique] = (rank, sym)

    def _outbound_callees(self, calls, index, target_file, target_dir, target_prefixes):
        ranked = {}
        for call in calls:
            if call in _COMMON_LIBC_CALLS:
                continue
            for sym in index.definitions.get(call, []):
                rank = self._rank_symbol(index, sym, target_file, target_dir, target_prefixes, bonus=20)
                self._remember_ranked_symbol(ranked, rank, sym)
        return list(ranked.values())

    def _caller_symbol_for_site(self, site: CallSite, index: SymbolIndex) -> SymbolDef | None:
        for sym in _symbols_for_file(index, site.caller_file):
            if sym.name == site.caller_name and sym.body_start <= site.line_number <= sym.body_end:
                return sym
        return _lookup_symbol(index, site.caller_file, site.caller_name)

    def _inbound_callers(self, target_names, index, target_file, target_dir, target_prefixes):
        ranked = {}
        for name in target_names:
            for site in index.callsites.get(name, []):
                sym = self._caller_symbol_for_site(site, index)
                if not sym:
                    continue
                rank = self._rank_symbol(index, sym, target_file, target_dir, target_prefixes, bonus=35)
                self._remember_ranked_symbol(ranked, rank, sym)
        return list(ranked.values())

    def _shared_state_nodes(self, fields, index, target_file, target_dir, target_prefixes):
        ranked = {}
        for field_name in fields:
            if field_name in _GENERIC_FIELDS and field_name not in _IMPORTANT_FIELDS:
                continue
            rarity_bonus = max(0, 30 - len(index.field_uses.get(field_name, [])))
            if field_name in _IMPORTANT_FIELDS:
                rarity_bonus += 20
            for use in index.field_uses.get(field_name, []):
                if use.file_path == target_file:
                    continue
                sym = self._symbol_for_function(index, use.file_path, use.function_name)
                if not sym:
                    continue
                rank = self._rank_symbol(index, sym, target_file, target_dir, target_prefixes, bonus=rarity_bonus)
                self._remember_ranked_symbol(ranked, rank, sym)
        return list(ranked.values())

    def _symbol_for_function(self, index, file_path, name):
        return _lookup_symbol(index, file_path, name)

    def _lifecycle_pair_nodes(self, target_names, index, target_file, target_dir, target_prefixes):
        wanted = set()
        for name in target_names:
            parts = _tokens(name)
            stem = _module_stem(name)
            for action in _LIFECYCLE_WORDS:
                if action in parts or name.lower().endswith("_" + action):
                    for pair in self._paired_actions(action):
                        wanted.add((stem, pair))
        ranked = {}
        if not wanted:
            return []
        for sym in _lifecycle_symbol_candidates(index):
            sym_l = sym.name.lower()
            sym_stem = _module_stem(sym.name)
            for stem, action in wanted:
                if action in sym_l and (sym_stem == stem or sym_stem.startswith(stem) or stem.startswith(sym_stem)):
                    rank = self._rank_symbol(index, sym, target_file, target_dir, target_prefixes, bonus=28)
                    self._remember_ranked_symbol(ranked, rank, sym)
                    break
        return list(ranked.values())

    def _paired_actions(self, action):
        pairs = {
            "create": ("destroy", "free", "release"),
            "destroy": ("create", "alloc", "init"),
            "alloc": ("free", "destroy"),
            "free": ("alloc", "create"),
            "init": ("term", "cleanup", "shutdown"),
            "term": ("init", "setup"),
            "setup": ("cleanup", "term"),
            "cleanup": ("setup", "init"),
            "open": ("release", "close", "flush"),
            "release": ("open", "flush", "poll", "ioctl"),
            "close": ("open", "flush"),
            "flush": ("open", "release", "close"),
            "get": ("put", "release"),
            "put": ("get", "ref"),
            "ref": ("unref", "put"),
            "unref": ("ref", "get"),
            "map": ("unmap",),
            "unmap": ("map",),
            "load": ("unload", "verify"),
            "unload": ("load",),
            "enable": ("disable", "reset"),
            "disable": ("enable", "reset"),
            "start": ("stop",),
            "stop": ("start",),
            "register": ("unregister",),
            "unregister": ("register",),
            "add": ("remove", "erase"),
            "remove": ("add", "insert"),
            "insert": ("erase", "remove"),
            "erase": ("insert", "add"),
            "grow": ("shrink",),
            "shrink": ("grow",),
            "suspend": ("resume",),
            "resume": ("suspend",),
            "schedule": ("cancel", "flush"),
            "cancel": ("schedule", "flush"),
            "arm": ("disarm", "cancel"),
            "disarm": ("arm",),
        }
        return pairs.get(action, ())

    def _callback_context(self, target_file, target_names, index, target_dir, target_prefixes):
        ranked = {}
        globals_ = []
        selected_names = set(target_names)
        for g in index.globals:
            gl = f"{g.name} {g.kind} {g.initializer}".lower()
            refs_target = bool(set(g.referenced_functions) & target_names)
            same_file = g.file_path == target_file
            if same_file or refs_target or any(word in gl for word in _CALLBACK_WORDS):
                if same_file or refs_target or str(Path(g.file_path).parent).replace("\\", "/") == target_dir:
                    globals_.append(g)
                    selected_names.update(g.referenced_functions)
        for name in selected_names:
            for sym in index.definitions.get(name, []):
                rank = self._rank_symbol(index, sym, target_file, target_dir, target_prefixes, bonus=30)
                self._remember_ranked_symbol(ranked, rank, sym)
        for sym in _callback_symbol_candidates(index) + _lifecycle_symbol_candidates(index):
            if str(Path(sym.file_path).parent).replace("\\", "/") != target_dir and sym.file_path != target_file:
                continue
            rank = self._rank_symbol(index, sym, target_file, target_dir, target_prefixes, bonus=18)
            self._remember_ranked_symbol(ranked, rank, sym)
        return list(ranked.values()), globals_[:40]

    def _candidate_paths(self, target_nodes, inbound, outbound, shared, lifecycle, callbacks):
        target_by_name = {n.name: n for n in target_nodes}
        paths = []
        for caller in inbound:
            for target in target_nodes:
                if target.name in caller.calls:
                    paths.append(ReachabilityPath(caller.unique_name, target.unique_name, [caller.unique_name, target.unique_name], target.sink_type))
        for target in target_nodes:
            for callee in outbound:
                if callee.name in target.calls:
                    paths.append(ReachabilityPath(target.unique_name, callee.unique_name, [target.unique_name, callee.unique_name], callee.sink_type))
        related = shared + lifecycle + callbacks
        for target in target_nodes:
            for node in related:
                if node.unique_name == target.unique_name:
                    continue
                if _module_stem(node.name) == _module_stem(target.name) or target.name in node.calls or node.name in target.calls:
                    paths.append(ReachabilityPath(target.unique_name, node.unique_name, [target.unique_name, node.unique_name], node.sink_type))
                    if node.name in target_by_name:
                        paths.append(ReachabilityPath(node.unique_name, target.unique_name, [node.unique_name, target.unique_name], target.sink_type))
        return _dedupe_paths(paths)


class PartialGraphBuilder:
    def build(self, context: PartialReviewContext, symbol_index: SymbolIndex, codebase_path: str) -> ReachabilityGraph:
        graph = ReachabilityGraph()
        for node in self._all_nodes(context):
            graph.add_node(node)
        for g in context.globals:
            graph.add_global(g)
        graph.resolve_all_calls()
        return graph

    def candidate_paths(self, context: PartialReviewContext, graph: ReachabilityGraph) -> list[ReachabilityPath]:
        paths = list(context.candidate_paths)
        if graph.node_count() <= 260:
            paths.extend(PathTracer(graph, max_path_length=8, max_paths_per_source=80).find_all_paths())
        return _dedupe_paths(paths)

    def _all_nodes(self, context: PartialReviewContext) -> list[FunctionNode]:
        nodes = {}
        for group in (
            context.target_nodes, context.inbound_callers, context.outbound_callees,
            context.shared_state_nodes, context.lifecycle_pair_nodes,
            context.callback_nodes, context.companion_nodes,
        ):
            for node in group:
                nodes[node.unique_name] = node
        return list(nodes.values())


class PartialCandidateDetector:
    def __init__(self, codebase_path: str, cache: PartialAnalysisCache | None = None):
        self._cb = os.path.abspath(codebase_path)
        self._cache = cache or PartialAnalysisCache(codebase_path)

    def detect(
        self,
        index: SymbolIndex,
        target_file: str,
        target_nodes: list[FunctionNode],
        context: PartialReviewContext,
    ) -> PartialDetectorResult:
        self._cache.bind_index(index)
        result = PartialDetectorResult()
        target_names = {node.name for node in target_nodes}
        target_syms = _symbols_for_file(index, target_file)
        target_prefixes = {_module_stem(name) for name in target_names if name}
        context_syms = self._context_symbols(index, context, target_syms)

        self._detect_state_publication(index, result, target_syms, target_prefixes)
        self._detect_publish_rollback(index, result, target_syms)
        self._detect_allocation_arithmetic(index, result, target_syms)
        wrappers = self._detect_format_wrappers(index, result, target_syms, target_prefixes)
        self._detect_info_leaks(index, result, target_syms)
        self._detect_fops(index, result, target_file, target_names)
        self._detect_lock_order(index, result, context_syms, target_file)
        self._detect_cross_file_lock_cycles(index, result, context, target_file)
        self._detect_stale_after_unlock(index, result, target_syms)
        self._detect_disable_stale(index, result, target_syms)
        self._detect_callback_lifetime(index, result, target_syms, target_prefixes)
        self._detect_state_transition_protocol(index, result, target_syms, context, target_file)
        self._detect_target_calls_wrappers(index, result, target_syms, wrappers)
        result.nodes = self._dedupe_nodes(result.nodes)
        result.globals = list({g.unique_name: g for g in result.globals}.values())
        return result

    def _lines(self, sym: SymbolDef) -> list[tuple[int, str]]:
        return self._cache.symbol_lines(sym)

    def _body_text(self, sym: SymbolDef) -> str:
        return self._cache.symbol_body(sym, numbered=False)

    def _node(self, index: SymbolIndex, sym: SymbolDef) -> FunctionNode:
        return _symbol_to_node(index, self._cb, sym, self._cache)

    def _add_node(self, index: SymbolIndex, result: PartialDetectorResult, sym: SymbolDef | None):
        if sym:
            result.nodes.append(self._node(index, sym))

    def _dedupe_nodes(self, nodes: list[FunctionNode]) -> list[FunctionNode]:
        seen, out = set(), []
        for node in nodes:
            if node.unique_name in seen:
                continue
            seen.add(node.unique_name)
            out.append(node)
        return out

    def _symbol_for_function(self, index: SymbolIndex, file_path: str, name: str) -> SymbolDef | None:
        return _lookup_symbol(index, file_path, name)

    def _context_symbols(self, index, context, target_syms):
        syms = {f"{sym.file_path}::{sym.name}": sym for sym in target_syms}
        for node in (
            context.target_nodes + context.inbound_callers + context.outbound_callees
            + context.shared_state_nodes + context.lifecycle_pair_nodes
            + context.callback_nodes + context.companion_nodes
        ):
            sym = self._symbol_for_function(index, node.file_path, node.name)
            if sym:
                syms[f"{sym.file_path}::{sym.name}"] = sym
        return list(syms.values())

    def _field_name_from_state_write(self, line: str) -> str:
        match = re.search(
            r"(gpu_ready|runtime_active|ready|enabled|active|initialized|loaded|online|powered|state)",
            line,
            re.IGNORECASE,
        )
        return match.group(1) if match else ""

    def _detect_state_publication(self, index, result, target_syms, target_prefixes):
        for sym in target_syms:
            lines = self._lines(sym)
            for idx, (line_no, line) in enumerate(lines):
                if not _STATE_FIELD_RE.search(line):
                    continue
                later = lines[idx + 1:idx + 45]
                error = next(((ln, txt) for ln, txt in later if _ERROR_PATH_RE.search(txt)), None)
                if not error:
                    continue
                field = self._field_name_from_state_write(line)
                rollback = any(_STATE_RESET_RE.search(txt) and field.lower() in txt.lower() for _, txt in later)
                if rollback:
                    continue
                result.state_publication_notes.append(
                    f"{sym.file_path}::{sym.name} line {line_no} publishes `{_line_excerpt(line)}` "
                    f"before later error path line {error[0]} `{_line_excerpt(error[1])}` without rollback."
                )
                self._add_node(index, result, sym)
                for use in index.field_uses.get(field, [])[:30]:
                    other = self._symbol_for_function(index, use.file_path, use.function_name)
                    if other and other.file_path != sym.file_path:
                        self._add_node(index, result, other)
                for candidate in self._paired_lifecycle_symbols(index, sym.name, target_prefixes, {"disable", "shutdown", "term", "destroy", "unload"}):
                    self._add_node(index, result, candidate)

    def _detect_publish_rollback(self, index, result, target_syms):
        rollback_names = {"rb_erase", "list_del", "hash_del", "unregister", "remove", "erase"}
        for sym in target_syms:
            lines = self._lines(sym)
            for idx, (line_no, line) in enumerate(lines):
                if not _PUBLISH_CALL_RE.search(line):
                    continue
                later = lines[idx + 1:idx + 60]
                error = next(((ln, txt) for ln, txt in later if _ERROR_PATH_RE.search(txt) or "capacity" in txt.lower() or "fail" in txt.lower()), None)
                if not error:
                    continue
                rollback = any(_ROLLBACK_CALL_RE.search(txt) for _, txt in later[:max(1, error[0] - line_no)])
                if rollback:
                    continue
                result.publish_rollback_notes.append(
                    f"{sym.file_path}::{sym.name} line {line_no} publishes `{_line_excerpt(line)}`, "
                    f"then line {error[0]} can fail via `{_line_excerpt(error[1])}` with no rollback before return."
                )
                self._add_node(index, result, sym)
                for name in rollback_names:
                    for helper in index.definitions.get(name, [])[:5]:
                        self._add_node(index, result, helper)

    def _detect_allocation_arithmetic(self, index, result, target_syms):
        for sym in target_syms:
            lines = self._lines(sym)
            for idx, (line_no, line) in enumerate(lines):
                if not _ALLOC_ARITH_RE.search(line):
                    continue
                window = "\n".join(txt for _, txt in lines[max(0, idx - 6):idx + 4])
                if _OVERFLOW_GUARD_RE.search(window):
                    continue
                result.allocation_arithmetic_notes.append(
                    f"{sym.file_path}::{sym.name} line {line_no} uses allocation arithmetic `{_line_excerpt(line)}` "
                    "without an obvious checked multiplication or SIZE_MAX guard nearby."
                )
                self._add_node(index, result, sym)

    def _detect_info_leaks(self, index, result, target_syms):
        for sym in target_syms:
            for line_no, line in self._lines(sym):
                if not _LOG_CALL_RE.search(line):
                    continue
                if not _SENSITIVE_TOKEN_RE.search(line):
                    continue
                if not (_SENSITIVE_FORMAT_RE.search(line) or "phys" in line.lower() or "token" in line.lower() or "secret" in line.lower()):
                    continue
                result.info_leak_notes.append(
                    f"{sym.file_path}::{sym.name} line {line_no} logs sensitive-looking data `{_line_excerpt(line)}`."
                )
                self._add_node(index, result, sym)

    def _detect_format_wrappers(self, index, result, target_syms, target_prefixes):
        wrappers: dict[str, SymbolDef] = {}
        target_dir = str(Path(target_syms[0].file_path).parent).replace("\\", "/") if target_syms else ""
        for sym in _security_symbol_candidates(index):
            same_module = (
                sym.file_path == (target_syms[0].file_path if target_syms else "")
                or str(Path(sym.file_path).parent).replace("\\", "/") == target_dir
                or _module_stem(sym.name) in target_prefixes
            )
            if not same_module and not _name_has_any(sym.name, {"log", "debug", "trace"}):
                continue
            signature = sym.signature.lower()
            if not re.search(r"(const\s+char\s*\*\s*(?:fmt|format|msg)|char\s*\*\s*(?:fmt|format|msg))", signature):
                continue
            body = self._body_text(sym)
            if not _VARIADIC_WRAPPER_RE.search(body):
                continue
            if not re.search(r"\b(?:fmt|format|msg)\b", body):
                continue
            wrappers[sym.name] = sym
            result.format_notes.append(
                f"{sym.file_path}::{sym.name} wraps a variable format parameter and calls printf-family output."
            )
            self._add_node(index, result, sym)
        return wrappers

    def _detect_target_calls_wrappers(self, index, result, target_syms, wrappers):
        if not wrappers:
            return
        for sym in target_syms:
            for line_no, line in self._lines(sym):
                for wrapper_name, wrapper_sym in wrappers.items():
                    if not re.search(r"\b" + re.escape(wrapper_name) + r"\s*\(", line):
                        continue
                    args = _first_call_args(line, wrapper_name)
                    if not args or _is_string_literal(args[0]):
                        continue
                    result.format_notes.append(
                        f"{sym.file_path}::{sym.name} line {line_no} passes non-literal `{args[0]}` "
                        f"to variadic format wrapper {wrapper_sym.file_path}::{wrapper_sym.name}."
                    )
                    self._add_node(index, result, sym)
                    self._add_node(index, result, wrapper_sym)

    def _detect_fops(self, index, result, target_file, target_names):
        for g in index.globals:
            text = g.initializer
            lower = text.lower()
            refs = set(g.referenced_functions)
            if g.file_path != target_file and not refs & target_names:
                continue
            if "file_operations" not in lower and "fops" not in lower and ".release" not in lower:
                continue
            has_open = ".open" in lower
            has_release = ".release" in lower
            has_activity = any(token in lower for token in (".poll", ".ioctl", ".read", ".write"))
            has_flush = ".flush" in lower
            if has_open and has_release and has_activity and not has_flush:
                result.fops_notes.append(
                    f"{g.file_path}::{g.name} line {g.line_number} has open/release plus poll/ioctl/read/write but no .flush."
                )
                result.globals.append(g)
                for ref in g.referenced_functions:
                    for sym in index.definitions.get(ref, [])[:4]:
                        self._add_node(index, result, sym)

    def _detect_lock_order(self, index, result, syms, target_file):
        edges: dict[tuple[str, str], list[tuple[SymbolDef, int]]] = defaultdict(list)
        for sym in syms:
            held: list[str] = []
            for line_no, line in self._lines(sym):
                for match in _LOCK_CALL_RE.finditer(line):
                    lock = _normalise_lock_expr(match.group("arg"))
                    if not lock:
                        continue
                    if _UNLOCK_WORD_RE.search(match.group("fn")):
                        if lock in held:
                            held.remove(lock)
                        continue
                    for prior in held:
                        if prior != lock:
                            edges[(prior, lock)].append((sym, line_no))
                    if lock not in held:
                        held.append(lock)
        seen = set()
        for (a, b), first_edges in edges.items():
            reverse_edges = edges.get((b, a))
            if not reverse_edges:
                continue
            for sym_a, line_a in first_edges:
                for sym_b, line_b in reverse_edges:
                    if sym_a.name == sym_b.name and sym_a.file_path == sym_b.file_path:
                        continue
                    if sym_a.file_path != target_file and sym_b.file_path != target_file:
                        continue
                    key = tuple(sorted((f"{sym_a.file_path}::{sym_a.name}", f"{sym_b.file_path}::{sym_b.name}", a, b)))
                    if key in seen:
                        continue
                    seen.add(key)
                    result.lock_order_notes.append(
                        f"{a}->{b}: {sym_a.file_path}::{sym_a.name} line {line_a}; "
                        f"{b}->{a}: {sym_b.file_path}::{sym_b.name} line {line_b}."
                    )
                    self._add_node(index, result, sym_a)
                    self._add_node(index, result, sym_b)
                    if len(result.lock_order_notes) >= 20:
                        return

    def _detect_cross_file_lock_cycles(self, index, result, context, target_file):
        syms = self._context_symbols(index, context, _symbols_for_file(index, target_file))
        edge_map: dict[tuple[str, str], list[LockOrderEdge]] = defaultdict(list)
        for sym in syms:
            for edge in _symbol_lock_edges(index, sym):
                edge_map[(edge.first_lock, edge.second_lock)].append(edge)
        if not edge_map:
            return
        seen = set()
        for (a, b), forward_edges in edge_map.items():
            reverse_edges = edge_map.get((b, a), [])
            for e1 in forward_edges:
                for e2 in reverse_edges:
                    if not self._cross_file_cycle_is_relevant(e1, e2, target_file):
                        continue
                    key = tuple(sorted((
                        f"{e1.file_path}:{e1.function_name}:{e1.first_lock}>{e1.second_lock}",
                        f"{e2.file_path}:{e2.function_name}:{e2.first_lock}>{e2.second_lock}",
                    )))
                    if key in seen:
                        continue
                    seen.add(key)
                    result.cross_file_lock_notes.append(self._lock_cycle_note(index, [e1, e2], target_file))
                    self._add_edge_nodes(index, result, [e1, e2])
                    if len(result.cross_file_lock_notes) >= 16:
                        return
        locks = sorted({lock for edge in edge_map for lock in edge})[:24]
        for a in locks:
            for b in locks:
                if b == a:
                    continue
                for c in locks:
                    if c in {a, b}:
                        continue
                    if not (edge_map.get((a, b)) and edge_map.get((b, c)) and edge_map.get((c, a))):
                        continue
                    for e1 in edge_map[(a, b)]:
                        for e2 in edge_map[(b, c)]:
                            for e3 in edge_map[(c, a)]:
                                if not self._cross_file_cycle_is_relevant(e1, e2, target_file, extra=e3):
                                    continue
                                key = tuple(sorted((
                                    f"{e1.file_path}:{e1.function_name}:{e1.first_lock}>{e1.second_lock}",
                                    f"{e2.file_path}:{e2.function_name}:{e2.first_lock}>{e2.second_lock}",
                                    f"{e3.file_path}:{e3.function_name}:{e3.first_lock}>{e3.second_lock}",
                                )))
                                if key in seen:
                                    continue
                                seen.add(key)
                                result.cross_file_lock_notes.append(self._lock_cycle_note(index, [e1, e2, e3], target_file))
                                self._add_edge_nodes(index, result, [e1, e2, e3])
                                if len(result.cross_file_lock_notes) >= 16:
                                    return

    def _cross_file_cycle_is_relevant(self, first: LockOrderEdge, second: LockOrderEdge, target_file: str, *, extra: LockOrderEdge | None = None) -> bool:
        edges = [first, second] + ([extra] if extra else [])
        files = {edge.file_path for edge in edges}
        if target_file not in files or len(files) < 2:
            return False
        return any(edge.file_path == target_file for edge in edges)

    def _lock_cycle_note(self, index: SymbolIndex, edges: list[LockOrderEdge], target_file: str) -> str:
        parts = []
        async_hint = False
        for edge in edges:
            sym = _lookup_symbol(index, edge.file_path, edge.function_name)
            meta = index.meta_by_symbol.get(_symbol_unique_name(sym)) if sym else None
            async_hint = async_hint or bool(meta and (meta.has_callback_words or meta.has_notifier_words))
            role = "target" if edge.file_path == target_file else "companion"
            parts.append(
                f"{edge.first_lock}->{edge.second_lock} in {role} "
                f"{edge.file_path}::{edge.function_name} line {edge.line_number}"
            )
        suffix = " Callback/notifier/asynchronous linkage is present." if async_hint else ""
        return "Cross-file lock cycle candidate: " + "; ".join(parts) + "." + suffix

    def _add_edge_nodes(self, index: SymbolIndex, result: PartialDetectorResult, edges: list[LockOrderEdge]):
        for edge in edges:
            self._add_node(index, result, _lookup_symbol(index, edge.file_path, edge.function_name))

    def _detect_stale_after_unlock(self, index, result, target_syms):
        for sym in target_syms:
            held = False
            cached_vars: dict[str, tuple[int, str]] = {}
            for line_no, line in self._lines(sym):
                if _LOCK_CALL_RE.search(line) and not _UNLOCK_WORD_RE.search(line):
                    held = True
                if held:
                    match = _ASSIGN_FROM_FIELD_RE.search(line)
                    if match:
                        cached_vars[match.group("var")] = (line_no, line)
                if _LOCK_CALL_RE.search(line) and _UNLOCK_WORD_RE.search(line):
                    held = False
                    continue
                if held:
                    continue
                for var, (assign_line, assign_text) in list(cached_vars.items()):
                    if line_no <= assign_line + 1:
                        continue
                    if re.search(r"\b" + re.escape(var) + r"\b", line):
                        result.stale_after_unlock_notes.append(
                            f"{sym.file_path}::{sym.name} caches `{_line_excerpt(assign_text)}` under lock at line {assign_line}, "
                            f"then uses {var} after unlock at line {line_no}: `{_line_excerpt(line)}`."
                        )
                        self._add_node(index, result, sym)
                        cached_vars.pop(var, None)

    def _detect_disable_stale(self, index, result, target_syms):
        for sym in target_syms:
            if not _DISABLE_NAME_RE.search(sym.name):
                continue
            body = self._body_text(sym)
            if not _DISABLE_STATE_RE.search(body):
                continue
            lower = body.lower()
            stale_bits = []
            if "doorbell" in lower and "invalid" not in lower:
                stale_bits.append("doorbell")
            if "pending" in lower and not re.search(r"pending\s*=\s*0", lower):
                stale_bits.append("pending")
            if ("callback" in lower or "work" in lower or "timer" in lower) and not _CANCEL_OR_REF_RE.search(lower):
                stale_bits.append("callback/work/timer")
            if not stale_bits:
                continue
            result.disable_stale_notes.append(
                f"{sym.file_path}::{sym.name} disables state but does not clear {', '.join(stale_bits)}."
            )
            self._add_node(index, result, sym)

    def _detect_callback_lifetime(self, index, result, target_syms, target_prefixes):
        for sym in target_syms:
            body = self._body_text(sym)
            if not _CALLBACK_STORE_RE.search(body):
                continue
            if _CANCEL_OR_REF_RE.search(body):
                continue
            note_line = next((item for item in self._lines(sym) if _CALLBACK_STORE_RE.search(item[1])), None)
            if not note_line:
                continue
            result.callback_lifetime_notes.append(
                f"{sym.file_path}::{sym.name} line {note_line[0]} stores object/context pointer `{_line_excerpt(note_line[1])}` "
                "without nearby refcount, unregister, cancel, or clear evidence."
            )
            self._add_node(index, result, sym)
            for candidate in self._paired_lifecycle_symbols(index, sym.name, target_prefixes, {"destroy", "release", "term", "shutdown", "disable"}):
                self._add_node(index, result, candidate)

    def _detect_state_transition_protocol(self, index, result, target_syms, context, target_file):
        context_syms = self._context_symbols(index, context, target_syms)
        companions = [sym for sym in context_syms if sym.file_path != target_file]
        companion_by_token: dict[str, list[SymbolDef]] = defaultdict(list)
        for sym in companions:
            for token in _symbol_state_tokens(index, sym):
                companion_by_token[token].append(sym)

        for sym in target_syms:
            tokens = _symbol_state_tokens(index, sym)
            if not tokens & (_WAIT_ACK_TOKENS | _TRANSITION_TOKENS | _SUBSYSTEM_TOKENS):
                continue
            self._detect_wait_ack_without_verify(index, result, sym, companions)
            self._detect_protocol_lock_mismatch(index, result, sym, companion_by_token)
            if len(result.protocol_notes) >= 24:
                return

    def _detect_wait_ack_without_verify(self, index, result, sym: SymbolDef, companions: list[SymbolDef]):
        tokens = _symbol_state_tokens(index, sym)
        if not (tokens & _WAIT_ACK_TOKENS):
            return
        if not (tokens & (_STATE_VERIFY_TOKENS | _SUBSYSTEM_TOKENS)):
            return
        lines = self._lines(sym)
        for idx, (line_no, line) in enumerate(lines):
            lower = line.lower()
            if not any(token in lower for token in _WAIT_ACK_TOKENS):
                continue
            later = "\n".join(txt for _, txt in lines[idx + 1:idx + 16])
            later_tokens = set(_protocol_tokens_from_text(later))
            if later_tokens and (_STATE_VERIFY_TOKENS & later_tokens):
                continue
            companion = self._best_protocol_companion(index, sym, companions)
            note = (
                f"{sym.file_path}::{sym.name} line {line_no} waits for ack/event `{_line_excerpt(line)}` "
                "without a nearby final active/protected/ready state verification."
            )
            if companion:
                note += f" Companion transition context: {companion.file_path}::{companion.name}."
                self._add_node(index, result, companion)
            result.protocol_notes.append(note)
            self._add_node(index, result, sym)
            return

    def _detect_protocol_lock_mismatch(self, index, result, sym: SymbolDef, companion_by_token: dict[str, list[SymbolDef]]):
        tokens = _symbol_state_tokens(index, sym)
        if not (tokens & (_TRANSITION_TOKENS | _SUBSYSTEM_TOKENS)):
            return
        target_locks = _symbol_locks(index, sym)
        checked = 0
        for token in sorted(tokens & (_TRANSITION_TOKENS | _SUBSYSTEM_TOKENS)):
            for companion in companion_by_token.get(token, [])[:10]:
                if companion.file_path == sym.file_path:
                    continue
                companion_locks = _symbol_locks(index, companion)
                if not companion_locks:
                    continue
                if target_locks & companion_locks:
                    continue
                if not self._same_protocol_area(sym, companion):
                    continue
                missing = ", ".join(sorted(companion_locks)[:3])
                result.protocol_notes.append(
                    f"{sym.file_path}::{sym.name} shares `{token}` transition/protocol state with "
                    f"{companion.file_path}::{companion.name}, but target-side lock coverage "
                    f"{sorted(target_locks)[:3] or ['(none)']} does not match companion lock(s) {missing}."
                )
                self._add_node(index, result, sym)
                self._add_node(index, result, companion)
                checked += 1
                if checked >= 4:
                    return

    def _best_protocol_companion(self, index, sym: SymbolDef, companions: list[SymbolDef]) -> SymbolDef | None:
        sym_tokens = _symbol_state_tokens(index, sym)
        candidates = []
        for companion in companions:
            overlap = len(sym_tokens & _symbol_state_tokens(index, companion))
            if not overlap:
                continue
            score = overlap
            if str(Path(companion.file_path).parent) == str(Path(sym.file_path).parent):
                score += 3
            if _module_stem(companion.name) == _module_stem(sym.name):
                score += 2
            if _symbol_locks(index, companion):
                score += 2
            candidates.append((-score, companion.file_path, companion.line_number, companion.name, companion))
        return sorted(candidates, key=lambda item: item[:-1])[0][-1] if candidates else None

    def _same_protocol_area(self, a: SymbolDef, b: SymbolDef) -> bool:
        dir_a = str(Path(a.file_path).parent).replace("\\", "/")
        dir_b = str(Path(b.file_path).parent).replace("\\", "/")
        if dir_a == dir_b or dir_a.startswith(dir_b) or dir_b.startswith(dir_a):
            return True
        stem_a = _module_stem(a.name)
        stem_b = _module_stem(b.name)
        return bool(stem_a and stem_b and (stem_a.startswith(stem_b) or stem_b.startswith(stem_a)))

    def _paired_lifecycle_symbols(self, index, name, target_prefixes, wanted_actions):
        stem = _module_stem(name)
        for sym in _lifecycle_symbol_candidates(index):
            sym_l = sym.name.lower()
            if not any(action in sym_l for action in wanted_actions):
                continue
            sym_stem = _module_stem(sym.name)
            if sym_stem == stem or sym_stem.startswith(stem) or stem.startswith(sym_stem) or sym_stem in target_prefixes:
                yield sym


_PARTIAL_REVIEW_SYS = """\
You are a conservative C/C++ security reviewer.
Review ONLY the target file for the requested pass.
Other files are evidence and context only.
Return findings only when the primary defective code is in the TARGET FILE.
Do not report bugs rooted in callers/callees unless the target file misuses their contract
or the target file owns the broken API behavior.
Use canonical ownership fields for every finding:
{{"primary_file": "src/example.c", "primary_function": "example_function",
"primary_line": 123,
"canonical_key": "src/example.c:example_function:vulnerability_family:root_cause_token"}}
Report each distinct root cause once. Be conservative.
vulnerability_type must be one of: """ + _VULN_TYPES + """.
Return ONLY valid JSON:
{{"findings": [{{"is_vulnerable": true, "vulnerability_type": "buffer_overflow",
"severity": "high", "confidence": "high", "function_name": "target_fn",
"related_function": "helper_fn", "line": 123, "description": "...",
"root_cause": "...", "evidence": "...", "primary_file": "src/target.c",
"primary_function": "target_fn", "primary_line": 123,
"canonical_key": "src/target.c:target_fn:memory_bounds:size_check"}}]}}
Return {{"findings": []}} if none found.
"""

_PARTIAL_REVIEW_USR = """\
Target file: {target_file}
Pass: {pass_name}

Review focus:
{focus}

Scope rule:
{scope_rule}

Candidate paths and relationships:
{paths_section}

Deterministic candidate notes:
{candidate_notes}

Global/callback constructs:
{globals_section}

== TARGET FILE CODE ==
{target_code}

== CONTEXT CODE ==
{context_code}
"""

_PASS_FOCI = {
    "target_intra": (
        "Bugs fully inside the target file: buffer overflow, null deref, format string, "
        "command injection, path traversal, integer overflow, double free, partial cleanup, "
        "TOCTOU, raw struct info leak. Do not report fixed literal printf formats."
    ),
    "inbound_contract": (
        "How external callers pass untrusted size/path/pointer/state into target functions. "
        "Report only if the target function fails to enforce its own contract or has broken ownership semantics."
    ),
    "outbound_misuse": (
        "Whether target code misuses helper APIs: wrong length field, ignored return, rich enum treated as bool, "
        "ownership transfer mistakes, NUL-termination contract mismatch."
    ),
    "shared_state": (
        "Shared-state semantic bugs in the target file: accounting drift, alias_count mismatch, refcount no-op, "
        "wrong flags/constants, width mismatch, stale length, information disclosure."
    ),
    "lifecycle": (
        "Lifecycle/ownership pairs: create/destroy, get/put, map/unmap, load/unload, init/term, "
        "callback teardown, stale pointers across realloc/compact, alias/source lifetime mismatch."
    ),
    "concurrency": (
        "Concrete concurrency bugs only: missing lock for shared fields, stale-after-unlock, lock-order among selected "
        "functions touching the same locks, teardown races with pending work/timers/callbacks."
    ),
    "state_publication": (
        "Ready/enabled/loaded/active/runtime flags set before validation or rollback-safe completion; error paths after "
        "publication that do not roll state back; disable/off paths that leave doorbell, ready, pending, or active state stale."
    ),
    "publish_rollback": (
        "Object publication before rollback-safe completion: rb_link_node/list_add/hash_add/register/insert before later "
        "capacity, allocation, validation, or registration failure, with missing or ineffective rollback."
    ),
    "allocation_arithmetic": (
        "Multiplication or addition in malloc/calloc/realloc/copy sizes where count comes from a parameter or field and no "
        "checked arithmetic or SIZE_MAX guard prevents undersized allocation."
    ),
    "format_and_info_leak": (
        "Variadic logger wrappers, non-literal format arguments into printf-family wrappers, and debug/log output of "
        "physical addresses, DMA addresses, pointers, tokens, keys, or secrets. Fixed literal formats with %s arguments are not bugs."
    ),
    "fops_lifecycle": (
        "file_operations/ops lifecycle: .release without .flush around poll/ioctl/read/write/shared-fd lifetime; release or "
        "teardown destroys context while poll/ioctl/callback/work/timer can still access it."
    ),
    "lock_and_stale": (
        "Deterministic lock-order candidates and stale local/cached pointer or state after unlock/relock. Report missing locks "
        "only when a concrete protected field, teardown race, or corruption path is shown."
    ),
    "cross_file_lock_cycle": (
        "Cross-file deadlock cycles and callback/notifier-induced lock inversions. Report only when the target file contributes "
        "a concrete lock-order edge or unsafe callback participation; use companion files only to prove the other edge(s)."
    ),
    "state_transition_protocol": (
        "Distributed protocol/state transition bugs: wait/ack without final active/protected verification, protected-mode/MMU/"
        "scheduler/firmware transitions without the companion serialization lock, and split enter/exit or enable/disable "
        "protocols where the target file owns the unsafe participation."
    ),
}


class TargetedFileReviewer:
    def __init__(
        self,
        llm_provider,
        model,
        usage_runtime,
        codebase_path: str,
        max_tokens: int = 8192,
        cache: PartialAnalysisCache | None = None,
        symbol_index: SymbolIndex | None = None,
    ):
        self._p = llm_provider
        self._m = model
        self._u = usage_runtime
        self._cb = os.path.abspath(codebase_path)
        self._t = max_tokens
        self._cache = cache or PartialAnalysisCache(codebase_path, symbol_index)
        self._cache.bind_index(symbol_index)

    def review(self, context: PartialReviewContext, partial_graph: ReachabilityGraph, *,
               detector_result: PartialDetectorResult | None = None,
               max_workers=4, progress_callback=None) -> list[VulnerabilityFinding]:
        detector_result = detector_result or PartialDetectorResult()
        passes = self._build_passes(context, partial_graph, detector_result)
        if not passes:
            return []
        if progress_callback:
            progress_callback({"event": "partial_review_start", "passes": len(passes)})
        findings: list[VulnerabilityFinding] = []
        with ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(passes)))) as ex:
            futs = {
                submit_with_current_context(ex, self._run_pass, context, partial_graph, item, detector_result): item[0]
                for item in passes
            }
            for fut in as_completed(futs):
                pass_name = futs[fut]
                try:
                    findings.extend(fut.result())
                except Exception as exc:
                    logger.warning("Partial review pass failed for %s: %s", pass_name, exc)
        if progress_callback:
            progress_callback({"event": "partial_review_raw_done", "raw_findings": len(findings)})
        return findings

    def _build_passes(self, context, graph, detector_result):
        detector_nodes = detector_result.nodes or []
        passes = [
            ("target_intra", context.target_nodes, []),
            ("inbound_contract", context.target_nodes, context.inbound_callers),
            ("outbound_misuse", context.target_nodes, context.outbound_callees),
            ("shared_state", context.target_nodes, context.shared_state_nodes),
            ("lifecycle", context.target_nodes, context.lifecycle_pair_nodes + context.callback_nodes),
            ("concurrency", context.target_nodes, context.shared_state_nodes + context.callback_nodes + context.lifecycle_pair_nodes),
        ]
        if detector_result.state_publication_notes or detector_result.disable_stale_notes:
            passes.append((
                "state_publication", context.target_nodes,
                context.shared_state_nodes + context.lifecycle_pair_nodes + context.callback_nodes + detector_nodes,
            ))
        if detector_result.publish_rollback_notes:
            passes.append(("publish_rollback", context.target_nodes, context.lifecycle_pair_nodes + detector_nodes))
        if detector_result.allocation_arithmetic_notes:
            passes.append(("allocation_arithmetic", context.target_nodes, context.outbound_callees + detector_nodes))
        if detector_result.format_notes or detector_result.info_leak_notes:
            passes.append(("format_and_info_leak", context.target_nodes, context.outbound_callees + detector_nodes))
        if detector_result.fops_notes:
            passes.append(("fops_lifecycle", context.target_nodes, context.callback_nodes + context.lifecycle_pair_nodes + detector_nodes))
        if detector_result.lock_order_notes or detector_result.stale_after_unlock_notes:
            passes.append(("lock_and_stale", context.target_nodes, context.shared_state_nodes + context.lifecycle_pair_nodes + detector_nodes))
        if detector_result.cross_file_lock_notes:
            passes.append((
                "cross_file_lock_cycle", context.target_nodes,
                context.companion_nodes + context.callback_nodes + context.lifecycle_pair_nodes
                + context.shared_state_nodes + detector_nodes,
            ))
        if detector_result.protocol_notes:
            passes.append((
                "state_transition_protocol", context.target_nodes,
                context.companion_nodes + context.lifecycle_pair_nodes + context.callback_nodes
                + context.shared_state_nodes + detector_nodes,
            ))
        return passes

    def _run_pass(self, context, graph, pass_item, detector_result):
        pass_name, target_nodes, context_nodes = pass_item
        target_code = self._build_code(target_nodes, per_fn_chars=4500, max_total_chars=42000)
        context_code = self._build_code(context_nodes, per_fn_chars=3000, max_total_chars=52000)
        if not target_code:
            return []
        prompt = ChatPromptTemplate.from_messages([
            ("system", _PARTIAL_REVIEW_SYS),
            ("user", _PARTIAL_REVIEW_USR),
        ])
        kw = self._u.hooks.chat_model_kwargs()
        chat = self._p.get_chat_model(model=self._m, max_tokens=self._t, temperature=0.1, **kw)
        raw = (prompt | chat | StrOutputParser()).invoke({
            "target_file": context.target_file,
            "pass_name": pass_name,
            "focus": _PASS_FOCI[pass_name],
            "scope_rule": self._scope_rule_for_pass(pass_name, context.target_file),
            "paths_section": self._paths_section(context.candidate_paths, graph),
            "candidate_notes": self._candidate_notes_for_pass(pass_name, detector_result),
            "globals_section": self._globals_section(context.globals),
            "target_code": target_code,
            "context_code": context_code,
        }).strip()
        return self._parse_findings(raw, context, graph, analysis_type=f"partial_{pass_name}")

    def _scope_rule_for_pass(self, pass_name: str, target_file: str) -> str:
        if pass_name in {"cross_file_lock_cycle", "state_transition_protocol"}:
            return (
                f"Findings must still use primary_file={target_file}. Companion files may prove the other half of the "
                "deadlock/protocol failure, but the target file must contain the concrete defective edge, unsafe transition, "
                "missing verification, or unsafe participation."
            )
        return "Findings must be rooted in the target file. Other files are evidence/context only."

    def _build_code(self, nodes, *, per_fn_chars, max_total_chars):
        parts, total = [], 0
        seen = set()
        for node in sorted(nodes, key=lambda n: (n.file_path, n.line_number, n.name)):
            if node.unique_name in seen:
                continue
            seen.add(node.unique_name)
            body = self._cache.node_body(node, max_chars=per_fn_chars)
            if not body:
                continue
            entry = f"--- {node.unique_name} (line {node.line_number} in {node.file_path}) ---\n{body}"
            if total + len(entry) > max_total_chars and parts:
                break
            parts.append(entry)
            total += len(entry)
        return "\n\n".join(parts)

    def _paths_section(self, paths, graph):
        lines = []
        for i, path in enumerate(paths[:80]):
            lines.append(f"Path {i}: {' -> '.join(path.path)}")
        return "\n".join(lines) if lines else "(none)"

    def _globals_section(self, globals_):
        lines = []
        for g in globals_[:40]:
            refs = ", ".join(g.referenced_functions)
            lines.append(
                f"GLOBAL {g.unique_name} line {g.line_number} kind={g.kind}\n"
                f"refs: {refs}\n{g.initializer[:1600]}"
            )
        return "\n\n".join(lines) if lines else "(none)"

    def _candidate_notes_for_pass(self, pass_name: str, detector_result: PartialDetectorResult) -> str:
        mapping = {
            "state_publication": (
                ("STATE_PUBLICATION", detector_result.state_publication_notes),
                ("DISABLE_STALE", detector_result.disable_stale_notes),
            ),
            "publish_rollback": (("PUBLISH_ROLLBACK", detector_result.publish_rollback_notes),),
            "allocation_arithmetic": (("ALLOCATION_ARITHMETIC", detector_result.allocation_arithmetic_notes),),
            "format_and_info_leak": (
                ("FORMAT_WRAPPER", detector_result.format_notes),
                ("INFO_LEAK", detector_result.info_leak_notes),
            ),
            "fops_lifecycle": (
                ("FOPS_LIFECYCLE", detector_result.fops_notes),
                ("CALLBACK_LIFETIME", detector_result.callback_lifetime_notes),
            ),
            "lock_and_stale": (
                ("LOCK_ORDER", detector_result.lock_order_notes),
                ("STALE_AFTER_UNLOCK", detector_result.stale_after_unlock_notes),
            ),
            "cross_file_lock_cycle": (
                ("CROSS_FILE_LOCK_CYCLE", detector_result.cross_file_lock_notes),
                ("LOCK_ORDER", detector_result.lock_order_notes[:20]),
            ),
            "state_transition_protocol": (
                ("STATE_TRANSITION_PROTOCOL", detector_result.protocol_notes),
                ("STATE_PUBLICATION", detector_result.state_publication_notes[:20]),
                ("DISABLE_STALE", detector_result.disable_stale_notes[:20]),
            ),
            "lifecycle": (
                ("CALLBACK_LIFETIME", detector_result.callback_lifetime_notes[:20]),
                ("FOPS_LIFECYCLE", detector_result.fops_notes[:20]),
            ),
            "concurrency": (
                ("LOCK_ORDER", detector_result.lock_order_notes[:20]),
                ("STALE_AFTER_UNLOCK", detector_result.stale_after_unlock_notes[:20]),
            ),
            "target_intra": (
                ("STATE_PUBLICATION", detector_result.state_publication_notes[:12]),
                ("ALLOCATION_ARITHMETIC", detector_result.allocation_arithmetic_notes[:12]),
                ("FORMAT_OR_INFO", (detector_result.format_notes + detector_result.info_leak_notes)[:12]),
            ),
            "shared_state": (
                ("DISABLE_STALE", detector_result.disable_stale_notes[:12]),
                ("CALLBACK_LIFETIME", detector_result.callback_lifetime_notes[:12]),
            ),
        }
        groups = mapping.get(pass_name, ())
        lines: list[str] = []
        for title, notes in groups:
            if not notes:
                continue
            lines.append(f"{title}:")
            lines.extend(f"- {note}" for note in notes[:40])
        if len(lines) > 90:
            lines = lines[:90] + ["- ..."]
        return "\n".join(lines) if lines else "(none)"

    def _parse_findings(self, raw, context, graph, analysis_type):
        parsed = parse_json_output(raw)
        if not isinstance(parsed, dict):
            return []
        entries = parsed.get("findings")
        if not isinstance(entries, list):
            return []
        by_name = {n.name: n for n in graph.nodes.values()}
        by_unique = dict(graph.nodes)
        target_default = context.target_nodes[0] if context.target_nodes else None
        results = []
        for entry in entries:
            if not isinstance(entry, dict) or entry.get("is_vulnerable") is False:
                continue
            fn = self._lookup_node(str(entry.get("function_name") or ""), by_name, by_unique) or target_default
            related = self._lookup_node(str(entry.get("related_function") or ""), by_name, by_unique)
            if not fn:
                continue
            line = _safe_int(entry.get("line"), fn.line_number)
            primary_file = str(entry.get("primary_file") or "").strip() or fn.file_path
            primary_function = str(entry.get("primary_function") or "").strip() or fn.unique_name
            primary_line = _safe_int(entry.get("primary_line"), line)
            canonical_key = str(entry.get("canonical_key") or "").strip()
            if not _same_file_ref(primary_file, context.target_file, self._cb):
                continue
            src = related or fn
            results.append(VulnerabilityFinding(
                id=os.urandom(8).hex(),
                vulnerability_type=_normalise_partial_vuln_type(entry.get("vulnerability_type") or "other"),
                severity=str(entry.get("severity") or "medium"),
                confidence=str(entry.get("confidence") or "medium"),
                source_function=src.unique_name,
                source_file=src.file_path,
                source_line=src.line_number,
                sink_function=fn.unique_name,
                sink_file=fn.file_path,
                sink_line=line,
                path=[src.unique_name, fn.unique_name] if related else [fn.unique_name],
                description=str(entry.get("description") or ""),
                root_cause=str(entry.get("root_cause") or ""),
                evidence=str(entry.get("evidence") or ""),
                analysis_type=analysis_type,
                primary_file=primary_file,
                primary_function=primary_function,
                primary_line=primary_line,
                canonical_key=canonical_key,
            ))
        return results

    def _lookup_node(self, name, by_name, by_unique):
        if not name:
            return None
        if name in by_unique:
            return by_unique[name]
        if name in by_name:
            return by_name[name]
        short = name.split("::")[-1]
        return by_name.get(short)


def _partial_finding_text(finding: VulnerabilityFinding) -> str:
    return " ".join(str(part or "") for part in (
        finding.description, finding.root_cause, finding.evidence, finding.canonical_key,
        finding.primary_function, finding.sink_function, finding.source_function,
    ))


def _partial_duplicate_family(vtype: str) -> str:
    normal = _normalise_partial_vuln_type(vtype)
    aliases = {
        "callback_lifecycle": "teardown_lifecycle",
        "deferred_uaf": "teardown_lifecycle",
        "teardown_race": "teardown_lifecycle",
        "file_ops_lifecycle_gap": "teardown_lifecycle",
        "cleanup_symmetry": "teardown_lifecycle",
        "stale_after_unlock": "lifetime",
        "stale_pointer": "lifetime",
        "use_after_free": "lifetime",
        "accounting_drift": "accounting",
        "refcount_imbalance": "accounting",
        "wrong_constant": "semantic_mismatch",
        "wrong_flag_semantic": "semantic_mismatch",
        "permission_mismatch": "semantic_mismatch",
        "state_order": "state_order",
        "ordering_gap": "state_order",
        "stale_state": "state_order",
    }
    return aliases.get(normal, normal)


def _partial_canonical_key(key: str) -> str:
    text = re.sub(r"[^a-z0-9]+", "_", str(key or "").lower())
    noisy = {
        "unchecked", "direct", "same", "path", "same_path", "same_path_input",
        "input", "user", "attacker", "unsanitized", "untrusted", "source", "sink",
    }
    tokens = [t for t in text.split("_") if t and t not in noisy]
    return "_".join(tokens)


def _partial_overlap(a: VulnerabilityFinding, b: VulnerabilityFinding) -> float:
    ta = _partial_note_tokens(_partial_finding_text(a))
    tb = _partial_note_tokens(_partial_finding_text(b))
    if not ta or not tb:
        return 0.0
    common = len(ta & tb)
    return common / max(1, min(len(ta), len(tb)))


def _partial_same_root(a: VulnerabilityFinding, b: VulnerabilityFinding) -> bool:
    af = a.primary_file or a.sink_file or a.source_file
    bf = b.primary_file or b.sink_file or b.source_file
    if af != bf:
        return False
    family_a = _partial_duplicate_family(a.vulnerability_type)
    family_b = _partial_duplicate_family(b.vulnerability_type)
    if family_a != family_b:
        return False
    fn_a = a.primary_function or a.sink_function or a.source_function
    fn_b = b.primary_function or b.sink_function or b.source_function
    line_a = _safe_int(a.primary_line or a.sink_line or a.source_line, 0)
    line_b = _safe_int(b.primary_line or b.sink_line or b.source_line, 0)
    if fn_a == fn_b and line_a and line_b and abs(line_a - line_b) <= 10:
        return True
    if a.sink_line and b.sink_line and a.sink_line == b.sink_line:
        return True
    ca = _partial_canonical_key(a.canonical_key)
    cb = _partial_canonical_key(b.canonical_key)
    if ca and cb and ca == cb:
        return True
    return fn_a == fn_b and _partial_overlap(a, b) >= 0.58


def _pick_partial_best(findings: list[VulnerabilityFinding]) -> VulnerabilityFinding:
    sev = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    conf = {"high": 0, "medium": 1, "low": 2}
    return min(findings, key=lambda f: (
        _PARTIAL_PASS_PRIORITY.get(f.analysis_type, 50),
        sev.get(str(f.severity or "").lower(), 5),
        conf.get(str(f.confidence or "").lower(), 3),
        len(f.path or []),
        -len(_partial_finding_text(f)),
    ))


def _collapse_partial_duplicates(findings: list[VulnerabilityFinding]) -> list[VulnerabilityFinding]:
    clusters: list[list[VulnerabilityFinding]] = []
    for finding in findings:
        merged = False
        for cluster in clusters:
            if _partial_same_root(finding, cluster[0]):
                cluster.append(finding)
                merged = True
                break
        if not merged:
            clusters.append([finding])
    return [_pick_partial_best(cluster) for cluster in clusters]


def _dedupe_partial_findings(findings: list[VulnerabilityFinding], *, max_per_sink: int) -> list[VulnerabilityFinding]:
    collapsed = _collapse_partial_duplicates(findings)
    deduped, _, _ = Deduplicator.deduplicate(collapsed, max_per_sink=max_per_sink)
    return _collapse_partial_duplicates(deduped)


def _is_external_entrypoint_finding(finding: VulnerabilityFinding) -> bool:
    text = _partial_finding_text(finding).lower()
    fn = str(finding.primary_function or finding.sink_function or finding.source_function or "").lower()
    return bool(re.search(
        r"\b(ioctl|dispatch|sysfs|debugfs|netlink|fops|file_operations|open|read|write|"
        r"poll|flush|release|callback|handler|irq|interrupt|user|copy_from_user|main)\b",
        f"{fn} {text}",
    ))


def _suppress_generic_null(finding: VulnerabilityFinding) -> bool:
    if _normalise_partial_vuln_type(finding.vulnerability_type) != "null_deref":
        return False
    text = _partial_finding_text(finding).lower()
    if re.search(r"\b(lookup|find|malloc|calloc|realloc|returns?\s+null|no matching|after loop|task_find|session_get|store_get|get_)\b", text):
        return False
    if _is_external_entrypoint_finding(finding):
        return False
    return bool(re.search(
        r"(missing\s+null\s+check|missing\s+null-check|caller-supplied pointer|"
        r"inbound pointer contract|missing validation of .* pointer|missing null check on "
        r"(?:dev|ctx|queue|obj|session|task|region))",
        text,
    ))


def _suppress_generic_missing_lock(finding: VulnerabilityFinding, detector_result: PartialDetectorResult) -> bool:
    if _normalise_partial_vuln_type(finding.vulnerability_type) != "missing_lock":
        return False
    text = _partial_finding_text(finding).lower()
    concrete = re.search(r"\b(free|destroy|teardown|release|callback|work|timer|fops|poll|ioctl|use-after-free|uaf|corrupt)\b", text)
    if concrete:
        return False
    notes = " ".join(
        detector_result.lock_order_notes
        + detector_result.stale_after_unlock_notes
        + detector_result.callback_lifetime_notes
        + detector_result.fops_notes
    )
    if _partial_note_tokens(text) & _partial_note_tokens(notes):
        return False
    return True


def _suppress_generic_partial(finding: VulnerabilityFinding) -> bool:
    text = _partial_finding_text(finding).lower()
    severity = str(finding.severity or "").lower()
    vtype = _normalise_partial_vuln_type(finding.vulnerability_type)
    if ("overwrites global file handle" in text or "repeated init" in text) and severity not in {"high", "critical"}:
        if not re.search(r"\b(double|use-after-free|uaf|security|attacker|external)\b", text):
            return True
    if vtype in {"missing_auth", "permission_mismatch"} and not _is_external_entrypoint_finding(finding):
        if re.search(r"\b(primitive|helper|low-level|lacks built-in authorization|caller authorization)\b", text):
            return True
    return False


def _post_filter_partial_findings(
    findings: list[VulnerabilityFinding],
    target_file: str,
    detector_result: PartialDetectorResult,
    codebase_path: str,
) -> tuple[list[VulnerabilityFinding], PartialPostFilterStats]:
    stats = PartialPostFilterStats()
    kept: list[VulnerabilityFinding] = []
    for finding in findings:
        finding.vulnerability_type = _normalise_partial_vuln_type(finding.vulnerability_type)
        primary = finding.primary_file or finding.sink_file or finding.source_file
        if not primary or not _same_file_ref(primary, target_file, codebase_path):
            stats.suppressed_non_target += 1
            continue
        if _suppress_generic_null(finding):
            stats.suppressed_null += 1
            continue
        if _suppress_generic_missing_lock(finding, detector_result):
            stats.suppressed_lock += 1
            continue
        if _suppress_generic_partial(finding):
            stats.suppressed_generic += 1
            continue
        kept.append(finding)
    return kept, stats


def _partial_cwe(vtype: str, finding: VulnerabilityFinding) -> str | None:
    normal = _normalise_partial_vuln_type(vtype)
    if normal == "info_leak":
        text = _partial_finding_text(finding).lower()
        return "CWE-532" if re.search(r"\b(log|printf|debug|trace|printk)\b", text) else "CWE-200"
    return _PARTIAL_CWE_OVERRIDES.get(normal) or _VULN_TO_CWE.get(normal)


class PartialReachabilityFileService:
    def __init__(self, config: EngineConfig, repository: EngineRepository, llm_provider, usage_runtime):
        self._config = config
        self._repository = repository
        self._llm_provider = llm_provider
        self._usage_runtime = usage_runtime
        self._symbol_index: SymbolIndex | None = None
        self._index_lock = threading.Lock()

    def review_file(
        self,
        file_path,
        *,
        extraction_model="gpt-4.1-mini",
        review_model=None,
        max_workers=8,
        context_budget=250,
        max_paths_per_sink=3,
        progress_callback=None,
    ):
        abs_target, rel_target = self._normalize_target_file(file_path)
        if os.path.splitext(rel_target)[1].lower() not in _C_CPP_EXTS:
            return None

        index = self._ensure_symbol_index(progress_callback=progress_callback)
        cache = PartialAnalysisCache(self._config.codebase_path, index)
        target_nodes, target_globals = self._extract_target(
            abs_target, rel_target, extraction_model, max_workers, progress_callback, cache)

        caps = PartialContextCaps(max_total_context_functions=max(25, int(context_budget or 250)))
        if progress_callback:
            progress_callback({"event": "partial_context_start", "file": rel_target})
        context_builder = PartialContextBuilder(self._config.codebase_path, caps, cache)
        context = context_builder.build_for_file(rel_target, target_nodes, index)
        if target_globals:
            context.globals = self._merge_globals(context.globals, target_globals)
        context_builder.expand_companions(context, index, progress_callback=progress_callback)

        detector_result = PartialCandidateDetector(self._config.codebase_path, cache).detect(
            index, rel_target, context.target_nodes, context)
        self._merge_detector_context(context, detector_result)
        if progress_callback:
            progress_callback({
                "event": "partial_detectors_done",
                "state_publication": len(detector_result.state_publication_notes),
                "publish_rollback": len(detector_result.publish_rollback_notes),
                "allocation_arithmetic": len(detector_result.allocation_arithmetic_notes),
                "format_wrappers": len(detector_result.format_notes),
                "info_leaks": len(detector_result.info_leak_notes),
                "fops": len(detector_result.fops_notes),
                "lock_order": len(detector_result.lock_order_notes),
                "stale_after_unlock": len(detector_result.stale_after_unlock_notes),
                "disable_stale": len(detector_result.disable_stale_notes),
                "callback_lifetime": len(detector_result.callback_lifetime_notes),
                "cross_file_lock_cycles": len(detector_result.cross_file_lock_notes),
                "protocol_candidates": len(detector_result.protocol_notes),
            })
            if detector_result.cross_file_lock_notes:
                progress_callback({
                    "event": "partial_lock_cycle_candidates",
                    "candidates": len(detector_result.cross_file_lock_notes),
                })
            if detector_result.protocol_notes:
                progress_callback({
                    "event": "partial_protocol_candidates",
                    "candidates": len(detector_result.protocol_notes),
                })
        if progress_callback:
            progress_callback({
                "event": "partial_context_done",
                "target_nodes": len(context.target_nodes),
                "inbound": len(context.inbound_callers),
                "outbound": len(context.outbound_callees),
                "shared": len(context.shared_state_nodes),
                "lifecycle": len(context.lifecycle_pair_nodes),
                "callbacks": len(context.callback_nodes),
                "companions": len(context.companion_nodes),
                "total_selected": len(self._all_context_nodes(context)),
            })

        graph_builder = PartialGraphBuilder()
        partial_graph = graph_builder.build(context, index, self._config.codebase_path)
        context.candidate_paths = graph_builder.candidate_paths(context, partial_graph)
        if progress_callback:
            progress_callback({
                "event": "partial_graph_done",
                "nodes": partial_graph.node_count(),
                "edges": partial_graph.edge_count(),
                "paths": len(context.candidate_paths),
            })

        model = review_model or self._config.llama_query_model
        reviewer = TargetedFileReviewer(
            self._llm_provider, model, self._usage_runtime, self._config.codebase_path,
            cache=cache, symbol_index=index)
        findings = reviewer.review(
            context, partial_graph, detector_result=detector_result,
            max_workers=max_workers, progress_callback=progress_callback)
        raw_findings = len(findings)
        findings = _post_filter_findings(findings, self._config.codebase_path)
        findings, filter_stats = _post_filter_partial_findings(
            findings, rel_target, detector_result, self._config.codebase_path)
        deduped = _dedupe_partial_findings(findings, max_per_sink=max_paths_per_sink)
        if progress_callback:
            progress_callback({
                "event": "partial_review_done",
                "raw_findings": raw_findings,
                "post_filtered_findings": len(findings),
                "deduped_findings": len(deduped),
                "suppressed_null": filter_stats.suppressed_null,
                "suppressed_lock": filter_stats.suppressed_lock,
                "suppressed_generic": filter_stats.suppressed_generic,
                "suppressed_non_target": filter_stats.suppressed_non_target,
            })
        return {
            "file": rel_target,
            "file_path": abs_target,
            "reviews": [self._finding_to_review(f) for f in deduped],
        }

    def _ensure_symbol_index(self, *, progress_callback=None):
        with self._index_lock:
            if self._symbol_index is not None:
                return self._symbol_index
            files = self._c_cpp_files()
            if progress_callback:
                progress_callback({"event": "partial_symbol_index_start", "files": len(files)})
            self._symbol_index = SymbolIndexBuilder().build(files, self._config.codebase_path)
            if progress_callback:
                progress_callback({
                    "event": "partial_symbol_index_done",
                    "files_indexed": self._symbol_index.files_indexed,
                    "definitions": sum(len(v) for v in self._symbol_index.definitions.values()),
                    "callsites": sum(len(v) for v in self._symbol_index.callsites.values()),
                    "fields": len(self._symbol_index.field_uses),
                    "locks": len(self._symbol_index.symbols_by_lock),
                    "state_tokens": len(self._symbol_index.symbols_by_state_token),
                    "globals": len(self._symbol_index.globals),
                })
            return self._symbol_index

    def _extract_target(self, abs_target, rel_target, extraction_model, max_workers, progress_callback, cache):
        if progress_callback:
            progress_callback({"event": "partial_target_extract_start", "file": rel_target})
        try:
            graph = GraphBuilder(
                self._llm_provider, extraction_model, self._usage_runtime
            ).build([abs_target], self._config.codebase_path, max_workers=1)
            nodes = [n for n in graph.nodes.values() if n.file_path.replace("\\", "/") == rel_target]
            globals_ = [g for g in graph.get_globals() if g.file_path.replace("\\", "/") == rel_target]
            for node in nodes:
                node.file_path = node.file_path.replace("\\", "/")
                node.unique_name = f"{node.file_path}::{node.name}"
            for g in globals_:
                g.file_path = g.file_path.replace("\\", "/")
                g.unique_name = f"{g.file_path}::{g.name}"
        except Exception as exc:
            logger.warning("Partial target extraction failed for %s: %s", rel_target, exc)
            nodes, globals_ = [], []
        if not nodes and self._symbol_index is not None:
            defs = _symbols_for_file(self._symbol_index, rel_target)
            nodes = [_symbol_to_node(self._symbol_index, self._config.codebase_path, sym, cache) for sym in defs]
            globals_ = [g for g in self._symbol_index.globals if g.file_path == rel_target]
        if progress_callback:
            progress_callback({
                "event": "partial_target_extract_done",
                "file": rel_target,
                "target_nodes": len(nodes),
                "globals": len(globals_),
            })
        return nodes, globals_

    def _normalize_target_file(self, file_path):
        abs_target = _abs_path(str(file_path), self._config.codebase_path)
        rel_target = _rel_path(abs_target, self._config.codebase_path)
        return abs_target, rel_target

    def _c_cpp_files(self):
        return [
            f for f in self._repository.get_code_files()
            if os.path.splitext(f)[1].lower() in _C_CPP_EXTS
        ]

    def _merge_globals(self, a, b):
        seen = {}
        for g in list(a or []) + list(b or []):
            seen[g.unique_name] = g
        return list(seen.values())

    def _merge_detector_context(self, context: PartialReviewContext, detector_result: PartialDetectorResult):
        if detector_result.globals:
            context.globals = self._merge_globals(context.globals, detector_result.globals)
        if detector_result.nodes:
            context.lifecycle_pair_nodes = self._dedupe_nodes(
                list(context.lifecycle_pair_nodes or []) + list(detector_result.nodes))
        paths = list(context.candidate_paths or [])
        for target in context.target_nodes:
            for node in detector_result.nodes:
                if node.unique_name == target.unique_name:
                    continue
                if node.file_path == context.target_file:
                    continue
                paths.append(ReachabilityPath(
                    target.unique_name, node.unique_name,
                    [target.unique_name, node.unique_name],
                    node.sink_type,
                ))
        context.candidate_paths = _dedupe_paths(paths)

    def _dedupe_nodes(self, nodes: list[FunctionNode]) -> list[FunctionNode]:
        seen, out = set(), []
        for node in nodes:
            if node.unique_name in seen:
                continue
            seen.add(node.unique_name)
            out.append(node)
        return out

    def _all_context_nodes(self, context):
        seen = {}
        for group in (
            context.target_nodes, context.inbound_callers, context.outbound_callees,
            context.shared_state_nodes, context.lifecycle_pair_nodes,
            context.callback_nodes, context.companion_nodes,
        ):
            for node in group:
                seen[node.unique_name] = node
        return list(seen.values())

    def _filter_target_findings(self, findings, target_file):
        result = []
        for finding in findings:
            primary = finding.primary_file or finding.sink_file or finding.source_file
            if primary and _same_file_ref(primary, target_file, self._config.codebase_path):
                result.append(finding)
        return result

    def _finding_to_review(self, finding):
        line_number = int(finding.primary_line or finding.sink_line or finding.source_line or 1)
        vtype = _normalise_partial_vuln_type(finding.vulnerability_type)
        issue = str(finding.description).strip()
        if not issue:
            primary_fn = finding.primary_function or finding.sink_function
            issue = f"{vtype.replace('_', ' ')} in {primary_fn}"
        reasoning_parts = []
        if str(finding.evidence or "").strip():
            reasoning_parts.append(str(finding.evidence).strip())
        if finding.path:
            reasoning_parts.append(f"Reachability path: {' -> '.join(finding.path)}")
        if str(finding.root_cause or "").strip():
            reasoning_parts.append(f"Root cause: {str(finding.root_cause).strip()}")
        if finding.analysis_type:
            reasoning_parts.append(f"Analysis type: {finding.analysis_type}")
        if finding.canonical_key:
            reasoning_parts.append(f"Canonical key: {finding.canonical_key}")
        target_file = finding.primary_file or finding.sink_file or finding.source_file
        code_snippet = ""
        if target_file:
            code_snippet = _read_line_context(self._config.codebase_path, target_file, line_number, context=2)
        return {
            "issue": issue,
            "line_number": line_number,
            "code_snippet": code_snippet,
            "cwe": _partial_cwe(vtype, finding),
            "severity": _severity_title(finding.severity, "Medium"),
            "confidence": _severity_title(finding.confidence, "Medium"),
            "reasoning": "\n".join(reasoning_parts),
            "mitigation": str(finding.root_cause or "").strip(),
        }
