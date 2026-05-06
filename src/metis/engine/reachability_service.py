from __future__ import annotations

import json
import logging
import os
import re
import threading
import uuid

from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate

from metis.usage import submit_with_current_context
from metis.utils import parse_json_output, read_file_content

from .repository import EngineRepository
from .runtime import EngineConfig

logger = logging.getLogger("metis")


def _chat_model_kwargs(usage_runtime, *, reasoning_effort=None):
    kwargs = usage_runtime.hooks.chat_model_kwargs()
    if reasoning_effort and str(reasoning_effort).lower() not in {"none", "off", "false", "default"}:
        kwargs["reasoning_effort"] = reasoning_effort
    return kwargs


# ── types ────────────────────────────────────────────────────────────────────

@dataclass
class FunctionNode:
    unique_name: str
    file_path: str
    name: str
    line_number: int
    is_source: bool
    is_sink: bool
    calls: list[str] = field(default_factory=list)
    resolved_calls: list[str] = field(default_factory=list)
    source_reason: str = ""
    sink_type: str = ""
    sink_reason: str = ""

    def to_dict(self) -> dict:
        return {
            "unique_name": self.unique_name, "file_path": self.file_path,
            "name": self.name, "line_number": self.line_number,
            "is_source": self.is_source, "is_sink": self.is_sink,
            "calls": self.calls, "resolved_calls": self.resolved_calls,
            "source_reason": self.source_reason, "sink_type": self.sink_type,
            "sink_reason": self.sink_reason,
        }


@dataclass
class GlobalConstruct:
    unique_name: str
    file_path: str
    name: str
    line_number: int
    kind: str
    initializer: str = ""
    referenced_functions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "unique_name": self.unique_name, "file_path": self.file_path,
            "name": self.name, "line_number": self.line_number,
            "kind": self.kind, "initializer": self.initializer,
            "referenced_functions": self.referenced_functions,
        }


@dataclass
class ReachabilityPath:
    source: str
    sink: str
    path: list[str] = field(default_factory=list)
    sink_type: str = ""


@dataclass
class VulnerabilityFinding:
    id: str
    vulnerability_type: str
    severity: str
    confidence: str
    source_function: str
    source_file: str
    source_line: int
    sink_function: str
    sink_file: str
    sink_line: int
    path: list[str] = field(default_factory=list)
    description: str = ""
    root_cause: str = ""
    evidence: str = ""
    analysis_type: str = "reachability"
    primary_file: str = ""
    primary_function: str = ""
    primary_line: int = 0
    canonical_key: str = ""

    def __post_init__(self):
        if not self.primary_file:
            self.primary_file = self.sink_file or self.source_file
        if not self.primary_function:
            self.primary_function = self.sink_function or self.source_function
        if not self.primary_line:
            self.primary_line = self.sink_line or self.source_line or 0

    def to_dict(self) -> dict:
        return {
            "id": self.id, "vulnerability_type": self.vulnerability_type,
            "severity": self.severity, "confidence": self.confidence,
            "source_function": self.source_function, "source_file": self.source_file,
            "source_line": self.source_line, "sink_function": self.sink_function,
            "sink_file": self.sink_file, "sink_line": self.sink_line,
            "path": self.path, "description": self.description,
            "root_cause": self.root_cause, "evidence": self.evidence,
            "analysis_type": self.analysis_type,
            "primary_file": self.primary_file, "primary_function": self.primary_function,
            "primary_line": self.primary_line, "canonical_key": self.canonical_key,
        }


class ReachabilityGraph:
    def __init__(self):
        self.nodes: dict[str, FunctionNode] = {}
        self.name_index: dict[str, list[str]] = {}
        self.globals: dict[str, GlobalConstruct] = {}

    def add_node(self, node):
        self.nodes[node.unique_name] = node
        self.name_index.setdefault(node.name, []).append(node.unique_name)

    def add_global(self, construct):
        self.globals[construct.unique_name] = construct

    def resolve_all_calls(self):
        for node in self.nodes.values():
            resolved = []
            for call_name in node.calls:
                targets = self.name_index.get(call_name, [])
                if len(targets) == 1:
                    resolved.append(targets[0])
                elif len(targets) > 1:
                    same = [t for t in targets if t.startswith(node.file_path + "::")]
                    resolved.extend(same if same else targets)
            node.resolved_calls = list(dict.fromkeys(resolved))

    def get_sources(self): return [n for n in self.nodes.values() if n.is_source]
    def get_sinks(self): return [n for n in self.nodes.values() if n.is_sink]
    def get_node(self, name): return self.nodes.get(name)
    def get_globals(self): return list(self.globals.values())
    def node_count(self): return len(self.nodes)
    def edge_count(self): return sum(len(n.resolved_calls) for n in self.nodes.values())

    def get_callers(self, target_unique_name):
        """Return nodes that have target in their resolved_calls."""
        return [n for n in self.nodes.values() if target_unique_name in n.resolved_calls]

    def get_file_nodes(self, file_path):
        """Return all nodes in a given file."""
        return [n for n in self.nodes.values() if n.file_path == file_path]

    def save_jsonl(self, path, *, include_globals=False):
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", encoding="utf-8") as fh:
            for n in self.nodes.values():
                row = n.to_dict()
                if include_globals:
                    row["record_type"] = "function"
                fh.write(json.dumps(row, ensure_ascii=False) + "\n")
            if include_globals:
                for g in self.globals.values():
                    row = g.to_dict()
                    row["record_type"] = "global"
                    fh.write(json.dumps(row, ensure_ascii=False) + "\n")

    @classmethod
    def load_jsonl(cls, path):
        """Load a previously saved graph from JSONL."""
        graph = cls()
        p = Path(path)
        if not p.exists():
            return graph
        with p.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                d = json.loads(line)
                if d.get("record_type") == "global":
                    graph.add_global(GlobalConstruct(
                        unique_name=d["unique_name"], file_path=d["file_path"],
                        name=d["name"], line_number=d["line_number"],
                        kind=d.get("kind", ""),
                        initializer=d.get("initializer", ""),
                        referenced_functions=d.get("referenced_functions", []),
                    ))
                    continue
                node = FunctionNode(
                    unique_name=d["unique_name"], file_path=d["file_path"],
                    name=d["name"], line_number=d["line_number"],
                    is_source=d["is_source"], is_sink=d["is_sink"],
                    calls=d.get("calls", []), resolved_calls=d.get("resolved_calls", []),
                    source_reason=d.get("source_reason", ""),
                    sink_type=d.get("sink_type", ""),
                    sink_reason=d.get("sink_reason", ""),
                )
                graph.add_node(node)
        # resolved_calls are already loaded; rebuild name_index only
        return graph


# ── shared helpers ───────────────────────────────────────────────────────────

def _number_lines(content):
    lines = content.splitlines()
    w = len(str(len(lines)))
    return "\n".join(f"{i+1:>{w}}: {line}" for i, line in enumerate(lines))

def _read_function_body(codebase_path, node, max_chars=3000):
    content = read_file_content(os.path.join(codebase_path, node.file_path))
    if not content: return ""
    fl = content.splitlines()
    start = max(0, node.line_number - 1)
    end = min(len(fl), start + 80)
    depth, opened = 0, False
    for i in range(start, min(len(fl), start + 300)):
        for ch in fl[i]:
            if ch == "{": depth += 1; opened = True
            elif ch == "}": depth -= 1
        if opened and depth <= 0: end = i + 1; break
    snippet = "\n".join(f"{start+1+j}: {fl[start+j]}" for j in range(end - start))
    return snippet[:max_chars] + "\n" if len(snippet) > max_chars else snippet

def _build_all_code(codebase_path, nodes, max_chars=3000):
    bodies = []
    for fn in nodes:
        body = _read_function_body(codebase_path, fn, max_chars)
        if body: bodies.append(f"Function {fn.unique_name} (line {fn.line_number} in {fn.file_path}):\n{body}")
    return "\n\n".join(bodies)

def _build_chunked_code(codebase_path, nodes, max_total_chars=60000, per_fn_chars=3000):
    """Build code text for nodes, chunking into groups that fit context limits."""
    chunks = []
    current_chunk = []
    current_size = 0
    for fn in nodes:
        body = _read_function_body(codebase_path, fn, per_fn_chars)
        if not body:
            continue
        entry = f"Function {fn.unique_name} (line {fn.line_number} in {fn.file_path}):\n{body}"
        entry_size = len(entry)
        if current_size + entry_size > max_total_chars and current_chunk:
            chunks.append("\n\n".join(current_chunk))
            current_chunk = []
            current_size = 0
        current_chunk.append(entry)
        current_size += entry_size
    if current_chunk:
        chunks.append("\n\n".join(current_chunk))
    return chunks

def _build_file_grouped_chunks(codebase_path, nodes, max_total_chars=60000, per_fn_chars=3000):
    """Build deterministic chunks, keeping functions from the same file together."""
    by_file = defaultdict(list)
    for fn in sorted(nodes, key=lambda n: (str(n.file_path), int(n.line_number or 0), str(n.name))):
        by_file[fn.file_path].append(fn)

    chunks = []
    current_chunk = []
    current_size = 0

    def flush_current():
        nonlocal current_chunk, current_size
        if current_chunk:
            chunks.append("\n\n".join(current_chunk))
            current_chunk = []
            current_size = 0

    for file_path in sorted(by_file):
        header = f"===== FILE: {file_path} ====="
        entries = []
        for fn in by_file[file_path]:
            body = _read_function_body(codebase_path, fn, per_fn_chars)
            if body:
                entries.append(f"Function {fn.unique_name} (line {fn.line_number} in {fn.file_path}):\n{body}")
        if not entries:
            continue

        file_text = header + "\n\n" + "\n\n".join(entries)
        if len(file_text) <= max_total_chars:
            if current_size + len(file_text) > max_total_chars and current_chunk:
                flush_current()
            current_chunk.append(file_text)
            current_size += len(file_text)
            continue

        flush_current()
        file_chunk = [header]
        file_size = len(header)
        for entry in entries:
            entry_size = len(entry) + 2
            if file_size + entry_size > max_total_chars and len(file_chunk) > 1:
                chunks.append("\n\n".join(file_chunk))
                file_chunk = [header]
                file_size = len(header)
            file_chunk.append(entry)
            file_size += entry_size
        if len(file_chunk) > 1:
            chunks.append("\n\n".join(file_chunk))

    flush_current()
    return chunks

def _build_file_grouped_node_chunks(codebase_path, nodes, max_total_chars=60000, per_fn_chars=3000):
    """Like _build_file_grouped_chunks, but keep the node list for each chunk."""
    by_file = defaultdict(list)
    for fn in sorted(nodes, key=lambda n: (str(n.file_path), int(n.line_number or 0), str(n.name))):
        by_file[fn.file_path].append(fn)

    chunks = []
    current_nodes = []
    current_parts = []
    current_size = 0

    def flush_current():
        nonlocal current_nodes, current_parts, current_size
        if current_parts:
            chunks.append((list(current_nodes), "\n\n".join(current_parts)))
            current_nodes = []
            current_parts = []
            current_size = 0

    for file_path in sorted(by_file):
        header = f"===== FILE: {file_path} ====="
        entries = []
        for fn in by_file[file_path]:
            body = _read_function_body(codebase_path, fn, per_fn_chars)
            if body:
                entries.append((fn, f"Function {fn.unique_name} (line {fn.line_number} in {fn.file_path}):\n{body}"))
        if not entries:
            continue

        file_nodes = [fn for fn, _ in entries]
        file_text = header + "\n\n" + "\n\n".join(text for _, text in entries)
        if len(file_text) <= max_total_chars:
            if current_size + len(file_text) > max_total_chars and current_parts:
                flush_current()
            current_nodes.extend(file_nodes)
            current_parts.append(file_text)
            current_size += len(file_text)
            continue

        flush_current()
        part_nodes = []
        part_texts = [header]
        part_size = len(header)
        for fn, text in entries:
            entry_size = len(text) + 2
            if part_size + entry_size > max_total_chars and part_nodes:
                chunks.append((part_nodes, "\n\n".join(part_texts)))
                part_nodes = []
                part_texts = [header]
                part_size = len(header)
            part_nodes.append(fn)
            part_texts.append(text)
            part_size += entry_size
        if part_nodes:
            chunks.append((part_nodes, "\n\n".join(part_texts)))

    flush_current()
    return chunks

def _build_globals_code(graph, max_chars=20000):
    globals_ = sorted(
        graph.get_globals(),
        key=lambda g: (str(g.file_path), int(g.line_number or 0), str(g.name)),
    )
    if not globals_:
        return ""
    parts, total = [], 0
    for g in globals_:
        refs = ", ".join(g.referenced_functions)
        entry = (
            f"GLOBAL {g.unique_name} line {g.line_number} kind={g.kind}\n"
            f"initializer:\n{g.initializer}\n"
            f"referenced_functions: {refs}"
        )
        if total + len(entry) > max_chars and parts:
            break
        if total + len(entry) > max_chars:
            entry = entry[:max_chars]
        parts.append(entry)
        total += len(entry)
    return "\n\n".join(parts)

def _lookup_fn(name, fn_by_name, fn_by_unique, all_fns):
    if not name: return None
    if name in fn_by_unique: return fn_by_unique[name]
    if name in fn_by_name: return fn_by_name[name]
    for fn in all_fns:
        if name in fn.name or name in fn.unique_name: return fn
    return None

def _severity_title(value, default="Medium"):
    text = str(value or "").strip().lower()
    if not text: return default
    return text[:1].upper() + text[1:]

def _chunked(items, size):
    if size <= 0: size = 1
    for i in range(0, len(items), size): yield items[i:i+size]

def _dedupe_paths(paths):
    seen, results = set(), []
    for p in paths:
        key = (p.source, p.sink, tuple(p.path))
        if key not in seen: seen.add(key); results.append(p)
    return results

def _read_line_context(codebase_path, rel_file, line_number, context=2, max_chars=1200):
    content = read_file_content(os.path.join(codebase_path, rel_file))
    if not content: return ""
    lines = content.splitlines()
    if not lines: return ""
    try: line_number = max(1, int(line_number))
    except: line_number = 1
    start = max(0, line_number - 1 - context)
    end = min(len(lines), line_number + context)
    snippet = "\n".join(f"{i+1}: {lines[i]}" for i in range(start, end))
    return snippet[:max_chars]

def _safe_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default

def _string_list(value):
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]

def _path_key(path):
    return os.path.normpath(str(path or "")).replace("\\", "/").lstrip("./")

def _same_file_ref(a, b, base_path=None):
    if not a or not b:
        return False
    ak, bk = _path_key(a), _path_key(b)
    if ak == bk:
        return True
    if base_path and os.path.isabs(str(a)):
        try:
            ak = _path_key(os.path.relpath(str(a), base_path))
        except ValueError:
            pass
    if base_path and os.path.isabs(str(b)):
        try:
            bk = _path_key(os.path.relpath(str(b), base_path))
        except ValueError:
            pass
    return ak == bk

def _canonical_fields(entry, *, default_file, default_function, default_line):
    primary_file = str(entry.get("primary_file") or "").strip() or default_file or ""
    primary_function = str(entry.get("primary_function") or "").strip() or default_function or ""
    primary_line = _safe_int(entry.get("primary_line"), default_line or 0)
    if primary_line <= 0:
        primary_line = default_line or 0
    canonical_key = str(entry.get("canonical_key") or "").strip()
    return primary_file, primary_function, primary_line, canonical_key

_VULN_TO_CWE = {
    "buffer_overflow": "CWE-120", "out_of_bounds": "CWE-787", "use_after_free": "CWE-416",
    "double_free": "CWE-415", "null_deref": "CWE-476", "command_injection": "CWE-78",
    "format_string": "CWE-134", "integer_overflow": "CWE-190", "path_traversal": "CWE-22",
    "race_condition": "CWE-362", "uninitialized_memory": "CWE-457", "type_confusion": "CWE-843",
    "boolean_coercion": "CWE-253", "wrong_constant": "CWE-697", "wrong_field": "CWE-688",
    "stale_length": "CWE-131", "double_close": "CWE-675", "callback_uaf": "CWE-416",
    "stale_pointer": "CWE-825", "refcount_imbalance": "CWE-911",
    # firmware / driver / hw specific
    "state_order": "CWE-696", "lock_order": "CWE-667", "missing_lock": "CWE-820",
    "stale_after_unlock": "CWE-667", "accounting_drift": "CWE-682",
    "toctou": "CWE-367", "missing_auth": "CWE-862", "permission_mismatch": "CWE-863",
    "info_leak": "CWE-532", "teardown_race": "CWE-362", "width_mismatch": "CWE-681",
    "partial_cleanup": "CWE-459", "rollback_gap": "CWE-460", "deferred_uaf": "CWE-416",
    "stale_state": "CWE-664", "cleanup_symmetry": "CWE-459",
    "missing_bounds_check": "CWE-120",
    "auth_comparison_logic_error": "CWE-863", "partial_cleanup_on_error": "CWE-459",
    "ownership_overwrite": "CWE-772", "premature_state_transition": "CWE-696",
    "stale_state_after_disable": "CWE-664",
    "ordering_gap": "CWE-696", "file_ops_lifecycle_gap": "CWE-362",
}

_VTYPE_FAMILY = {
    "buffer_overflow": "memory_bounds",
    "out_of_bounds": "memory_bounds",
    "use_after_free": "lifetime",
    "deferred_uaf": "lifetime",
    "callback_uaf": "lifetime",
    "stale_pointer": "lifetime",
    "double_free": "double_release",
    "double_close": "double_release",
    "path_traversal": "filesystem_path",
    "toctou": "filesystem_race",
    "teardown_race": "teardown_lifecycle",
    "file_ops_lifecycle_gap": "teardown_lifecycle",
    "cleanup_symmetry": "teardown_lifecycle",
    "partial_cleanup": "cleanup",
    "rollback_gap": "cleanup",
    "state_order": "state_order",
    "premature_state_transition": "state_order",
    "ordering_gap": "state_order",
    "stale_state": "state_order",
    "stale_state_after_disable": "state_order",
    "lock_order": "lock_order",
    "stale_after_unlock": "lock_order",
    "missing_auth": "authorization",
    "permission_mismatch": "authorization",
    "wrong_constant": "authorization",
    "boolean_coercion": "authorization",
    "auth_comparison_logic_error": "authorization",
    "accounting_drift": "accounting",
    "refcount_imbalance": "refcount",
    "info_leak": "information_disclosure",
    "missing_bounds_check": "memory_bounds",
    "partial_cleanup_on_error": "cleanup",
    "ownership_overwrite": "cleanup",
    "width_mismatch": "type_width",
}

# normalise vuln type variants the LLM might return
_VULN_TYPE_ALIASES = {
    "use-after-free": "use_after_free", "double-free": "double_free",
    "null-deref": "null_deref", "null_dereference": "null_deref",
    "null_pointer_dereference": "null_deref",
    "buffer-overflow": "buffer_overflow", "stack_buffer_overflow": "buffer_overflow",
    "heap_buffer_overflow": "buffer_overflow",
    "command-injection": "command_injection", "os_command_injection": "command_injection",
    "format-string": "format_string", "path-traversal": "path_traversal",
    "race-condition": "race_condition", "integer-overflow": "integer_overflow",
    "type-confusion": "type_confusion", "lock_inversion": "lock_order",
    "lock_order_inversion": "lock_order", "deadlock": "lock_order",
    "missing_cleanup": "partial_cleanup", "resource_leak": "partial_cleanup",
    "missing_authorization": "missing_auth", "missing_permission": "missing_auth",
    "wrong_enum_constant": "wrong_constant", "wrong_resource_constant": "wrong_constant",
    "wrong_resource": "wrong_constant", "wrong_permission_constant": "wrong_constant",
    "resource_mismatch": "permission_mismatch",
    "information_leak": "info_leak", "information_disclosure": "info_leak",
    "arbitrary_file_read": "path_traversal", "arbitrary_file_write": "path_traversal",
    "unvalidated_path": "path_traversal", "filesystem_traversal": "path_traversal",
    "directory_traversal": "path_traversal", "file_traversal": "path_traversal",
    "missing_flush": "teardown_race", "uncanceled_work": "teardown_race",
    "uncancelled_work": "teardown_race", "callback_lifecycle": "teardown_race",
    "missing_cancel": "teardown_race", "missing_cancellation": "teardown_race",
    "counter_drift": "accounting_drift", "missing_decrement": "accounting_drift",
    "missing_increment": "accounting_drift", "accounting_mismatch": "accounting_drift",
    "accounting_leak": "accounting_drift",
    "missing_barrier": "ordering_gap", "missing_flush_barrier": "ordering_gap",
    "power_ordering_gap": "ordering_gap", "flush_ordering_gap": "ordering_gap",
    "operation_ordering_gap": "ordering_gap",
    "file_ops_lifecycle_gap": "file_ops_lifecycle_gap",
    "missing_file_flush": "file_ops_lifecycle_gap",
    "release_without_flush": "file_ops_lifecycle_gap",
}

def _normalise_vuln_type(raw):
    t = str(raw or "other").strip().lower().replace("-", "_").replace(" ", "_")
    return _VULN_TYPE_ALIASES.get(t, t)


_PRINTF_FORMAT_ARG_INDEX = {
    "printf": 0,
    "fprintf": 1,
    "sprintf": 1,
    "snprintf": 2,
    "vfprintf": 1,
    "vsnprintf": 2,
}
_PRINTF_CALL_RE = re.compile(r"\b(printf|fprintf|sprintf|snprintf|vfprintf|vsnprintf)\s*\(", re.IGNORECASE)
_C_STRING_LITERAL_RE = re.compile(r'^\s*(?:(?:L|u8|u|U)?"(?:\\.|[^"\\])*"\s*)+$', re.DOTALL)


def _finding_text(f):
    return " ".join(str(part or "") for part in (
        getattr(f, "description", ""),
        getattr(f, "root_cause", ""),
        getattr(f, "evidence", ""),
        getattr(f, "canonical_key", ""),
    ))


def _finding_file(f):
    return getattr(f, "primary_file", "") or getattr(f, "sink_file", "") or getattr(f, "source_file", "") or ""


def _finding_function(f):
    return getattr(f, "primary_function", "") or getattr(f, "sink_function", "") or getattr(f, "source_function", "") or ""


def _finding_line(f):
    return _safe_int(
        getattr(f, "primary_line", 0) or getattr(f, "sink_line", 0) or getattr(f, "source_line", 0),
        0,
    )


def _strip_function_qualifier(name):
    return str(name or "").split("::")[-1]


def _extract_parenthesized_args(text, open_paren_index):
    depth = 0
    quote = None
    escape = False
    for i in range(open_paren_index, len(text)):
        ch = text[i]
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
        if ch == "(":
            depth += 1
            continue
        if ch == ")":
            depth -= 1
            if depth == 0:
                return text[open_paren_index + 1:i]
    return None


def _split_c_args(args_text):
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


def _is_c_string_literal_arg(value):
    return bool(_C_STRING_LITERAL_RE.match(str(value or "").strip()))


def _is_fixed_literal_format_call_false_positive(body_or_context, finding) -> bool:
    """
    Return true only when visible printf-family calls all use fixed string literal
    format arguments. If any visible call uses a variable format, keep the finding.
    """
    text = str(body_or_context or "")
    if not text.strip():
        return False

    literal_calls = 0
    variable_calls = 0
    for match in _PRINTF_CALL_RE.finditer(text):
        fn_name = match.group(1).lower()
        args_text = _extract_parenthesized_args(text, match.end() - 1)
        if args_text is None:
            return False
        args = _split_c_args(args_text)
        fmt_index = _PRINTF_FORMAT_ARG_INDEX.get(fn_name)
        if fmt_index is None or fmt_index >= len(args):
            return False
        if _is_c_string_literal_arg(args[fmt_index]):
            literal_calls += 1
        else:
            variable_calls += 1

    return literal_calls > 0 and variable_calls == 0


def _read_named_function_body(codebase_path, rel_file, fn_name, near_line=1, max_chars=6000):
    if not rel_file or not fn_name:
        return ""
    content = read_file_content(os.path.join(codebase_path, rel_file))
    if not content:
        return ""
    pattern = re.compile(
        r"(^|\n)[^\n;{}#]*\b" + re.escape(fn_name) + r"\s*\([^;{}]*\)\s*(?:\n\s*)?\{",
        re.MULTILINE,
    )
    matches = list(pattern.finditer(content))
    if not matches:
        return ""
    near_line = max(1, _safe_int(near_line, 1))

    def match_line(match):
        return content[:match.start()].count("\n") + 1

    chosen = None
    for match in matches:
        line = match_line(match)
        if line <= near_line:
            chosen = (line, match)
        elif chosen is None:
            chosen = (line, match)
            break
    if chosen is None:
        return ""
    node = FunctionNode(
        unique_name=f"{rel_file}::{fn_name}", file_path=rel_file,
        name=fn_name, line_number=chosen[0],
        is_source=False, is_sink=False,
    )
    return _read_function_body(codebase_path, node, max_chars=max_chars)


def _finding_code_context(codebase_path, finding, *, context=8, max_chars=6000):
    target_file = _finding_file(finding)
    if not target_file:
        return ""
    line = _finding_line(finding) or 1
    line_context = _read_line_context(codebase_path, target_file, line, context=context, max_chars=max_chars)
    fn_name = _strip_function_qualifier(_finding_function(finding))
    body = _read_named_function_body(codebase_path, target_file, fn_name, line, max_chars=max_chars)
    return body or line_context


def _is_borrowed_alias_cleanup_false_positive(finding):
    fn = _finding_function(finding).lower()
    if "destroy_alias" not in fn:
        return False
    text = _finding_text(finding).lower()
    compact = re.sub(r"\s+", "", text)
    mentions_alias_pages = "alias->pages" in compact or "alias pages" in text or "alias page" in text
    mentions_leak_cleanup = any(token in text for token in (
        "leak", "without freeing", "missing free", "not freed", "should free",
        "must free", "fails to free",
    ))
    keep_tokens = (
        "alias_count", "lifetime", "source", "use-after-free", "use_after_free",
        "refcount", "borrowed", "pin", "pinned",
    )
    return mentions_alias_pages and mentions_leak_cleanup and not any(token in text for token in keep_tokens)


def _is_leak_misclassified_as_double_free(finding):
    if _normalise_vuln_type(getattr(finding, "vulnerability_type", "")) != "double_free":
        return False
    text = _finding_text(finding).lower()
    leak_terms = ("leak", "partial cleanup", "missing cleanup", "not freed", "without freeing", "fails to free")
    double_free_terms = (
        "double free", "double-free", "freed twice", "free twice",
        "same pointer twice", "already freed", "second free",
    )
    return any(term in text for term in leak_terms) and not any(term in text for term in double_free_terms)


def _post_filter_findings(findings, codebase_path):
    if not findings:
        return []
    filtered = []
    for finding in findings:
        vtype = _normalise_vuln_type(getattr(finding, "vulnerability_type", ""))
        finding.vulnerability_type = vtype

        if _is_leak_misclassified_as_double_free(finding):
            finding.vulnerability_type = "partial_cleanup"
            vtype = "partial_cleanup"

        if _is_borrowed_alias_cleanup_false_positive(finding):
            continue

        if vtype == "format_string":
            context = _finding_code_context(codebase_path, finding)
            if _is_fixed_literal_format_call_false_positive(context, finding):
                continue

        filtered.append(finding)
    return filtered


# ── Graph builder ────────────────────────────────────────────────────────────

_EXTRACTION_SYSTEM_PROMPT = """\
You are a C and C++ static analysis tool. Analyze the following source file and \
extract ALL function definitions with their security relevant metadata.

For each function defined in this file (with body), provide:
1. "name": the function name
2. "line": line number where the function definition starts
3. "calls": list of ALL function and macro names called inside this function body
4. "is_source": true if this function directly receives or processes external/untrusted input
5. "source_reason": if is_source, briefly explain why
6. "is_sink": true if this function performs operations that could be dangerous with attacker-controlled input
7. "sink_type": if is_sink, one of: buffer_overflow, use_after_free, double_free, null_deref, \
command_injection, format_string, integer_overflow, path_traversal, race_condition, \
uninitialized_memory, type_confusion, out_of_bounds, other
8. "sink_reason": if is_sink, briefly explain the danger

Source indicators — mark is_source=true when a function:
- Reads from stdin, files, network sockets, pipes, IPC
- Processes command-line arguments (argc/argv) or environment variables
- Is a callback or handler for external events (ioctl, sysfs, debugfs, netlink)
- Is main() or an entry point that receives external parameters
- Handles hardware interrupts, DMA completions, firmware responses, or device register reads
- Is invoked from user-space via file_operations, ioctl dispatch, or similar interfaces

Sink indicators — mark is_sink=true when a function:
- Calls memcpy/strcpy/strcat/sprintf/gets/scanf with sizes derived from parameters
- Performs pointer arithmetic without bounds checking
- Has integer arithmetic that could overflow and influence buffer sizes or indices
- Calls system/popen/exec* with constructed strings
- Uses format strings built from variables
- Frees memory that may be used afterward, or frees the same pointer twice
- Dereferences pointers without null checks after allocation or lookup
- Accesses arrays with indices derived from untrusted input
- Has realloc/malloc with arithmetic on the size argument that could wrap
- Casts void* to a concrete type without type validation
- Writes to hardware registers, MMIO, or DMA buffers
- Manipulates refcounts, state flags, or power management transitions
- Performs cleanup/teardown that may race with pending work items or callbacks

A function CAN be both a source and a sink.
Do NOT include mere declarations/prototypes (no body).
DO include static, inline, and helper functions.

Also extract global constructs that bind external entry points or callbacks:
- struct file_operations / fops tables
- ops tables and callback tables
- timer/work/watchdog initializer structs
- global function-pointer structs

Return ONLY valid JSON:
{{"functions": [{{"name": "example", "line": 1, "calls": [], "is_source": false, \
"source_reason": "", "is_sink": false, "sink_type": "", "sink_reason": ""}}],
"globals": [{{"name": "gpu_fops", "line": 152, "kind": "file_operations",
"initializer": ".open = gpu_file_open, .release = gpu_file_release",
"referenced_functions": ["gpu_file_open", "gpu_file_release"]}}]}}

If the file has no function definitions or global constructs, return: {{"functions": [], "globals": []}}"""

_EXTRACTION_USER_TEMPLATE = "File: {file_path}\n\nCode:\n{file_content}"


class GraphBuilder:
    def __init__(self, llm_provider, model, usage_runtime, max_tokens=16384):
        self._p = llm_provider; self._m = model; self._u = usage_runtime; self._t = max_tokens

    def build(self, files, codebase_path, *, max_workers=4, progress_callback=None):
        graph = ReachabilityGraph()
        total = len(files); errors = []
        if progress_callback: progress_callback({"event": "extraction_start", "total": total})
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futs = {submit_with_current_context(ex, self._extract, f, codebase_path): f for f in files}
            done = 0
            for fut in as_completed(futs):
                fp = futs[fut]; done += 1
                try:
                    nodes, globals_ = fut.result()
                    for n in nodes: graph.add_node(n)
                    for g in globals_: graph.add_global(g)
                except Exception as e:
                    try:
                        rel = os.path.relpath(fp, codebase_path)
                    except Exception:
                        rel = os.path.basename(fp)
                    errors.append(f"{rel}: {type(e).__name__}: {e}")
                if progress_callback: progress_callback({"event": "extraction_progress", "completed": done, "total": total, "file": fp})
        graph.resolve_all_calls()
        if progress_callback:
            progress_callback({"event": "extraction_done", "nodes": graph.node_count(), "edges": graph.edge_count(),
                "sources": len(graph.get_sources()), "sinks": len(graph.get_sinks()),
                "globals": len(graph.get_globals()), "errors": errors})
        return graph

    def build_interactive(self, files, codebase_path, *, progress_callback=None):
        """Build a graph with one in-flight extraction so Ctrl-C stops promptly."""
        graph = ReachabilityGraph()
        total = len(files); errors = []
        if progress_callback: progress_callback({"event": "extraction_start", "total": total})
        for done, fp in enumerate(files, start=1):
            if progress_callback:
                progress_callback({"event": "extraction_file_start", "completed": done - 1, "total": total, "file": fp})
            try:
                nodes, globals_ = self._extract(fp, codebase_path)
                for n in nodes: graph.add_node(n)
                for g in globals_: graph.add_global(g)
            except KeyboardInterrupt:
                if progress_callback:
                    progress_callback({"event": "extraction_cancelled", "completed": done - 1, "total": total, "file": fp})
                raise
            except Exception as e:
                try:
                    rel = os.path.relpath(fp, codebase_path)
                except Exception:
                    rel = os.path.basename(fp)
                errors.append(f"{rel}: {type(e).__name__}: {e}")
            if progress_callback:
                progress_callback({"event": "extraction_progress", "completed": done, "total": total, "file": fp})
        graph.resolve_all_calls()
        if progress_callback:
            progress_callback({"event": "extraction_done", "nodes": graph.node_count(), "edges": graph.edge_count(),
                "sources": len(graph.get_sources()), "sinks": len(graph.get_sinks()),
                "globals": len(graph.get_globals()), "errors": errors})
        return graph

    def _extract(self, file_path, codebase_path):
        content = read_file_content(file_path)
        if not content or not content.strip(): return [], []
        base = os.path.abspath(codebase_path)
        rel = os.path.relpath(file_path, base)
        kw = _chat_model_kwargs(self._u, reasoning_effort=getattr(self, "_reasoning_effort", None))
        chat = self._p.get_chat_model(model=self._m, max_tokens=self._t, temperature=0.0, **kw)
        prompt = ChatPromptTemplate.from_messages([("system", _EXTRACTION_SYSTEM_PROMPT), ("user", _EXTRACTION_USER_TEMPLATE)])
        raw = (prompt | chat | StrOutputParser()).invoke({"file_path": rel, "file_content": _number_lines(content)}).strip()
        parsed = parse_json_output(raw)
        if not isinstance(parsed, dict): return [], []
        fns = parsed.get("functions")
        if not isinstance(fns, list): fns = []
        nodes, seen = [], set()
        for e in fns:
            if not isinstance(e, dict): continue
            name = str(e.get("name") or "").strip()
            if not name: continue
            u = f"{rel}::{name}"
            if u in seen: continue
            seen.add(u)
            calls = _string_list(e.get("calls") or [])
            line = 1
            try: line = max(1, int(e.get("line", 1)))
            except: pass
            nodes.append(FunctionNode(
                unique_name=u, file_path=rel, name=name, line_number=line,
                is_source=bool(e.get("is_source")), is_sink=bool(e.get("is_sink")),
                calls=calls, source_reason=str(e.get("source_reason") or ""),
                sink_type=str(e.get("sink_type") or ""), sink_reason=str(e.get("sink_reason") or "")))
        globals_, seen_globals = [], set()
        for e in parsed.get("globals") or []:
            if not isinstance(e, dict): continue
            name = str(e.get("name") or "").strip()
            if not name: continue
            unique_name = f"{rel}::{name}"
            if unique_name in seen_globals: continue
            seen_globals.add(unique_name)
            refs = _string_list(e.get("referenced_functions") or [])
            globals_.append(GlobalConstruct(
                unique_name=unique_name, file_path=rel, name=name,
                line_number=max(1, _safe_int(e.get("line"), 1)),
                kind=str(e.get("kind") or ""),
                initializer=str(e.get("initializer") or ""),
                referenced_functions=refs))
        return nodes, globals_


# ── path tracer ──────────────────────────────────────────────────────────────

class PathTracer:
    def __init__(self, graph, *, max_path_length=25, max_paths_per_source=200):
        self._g = graph; self._ml = max_path_length; self._mp = max_paths_per_source

    def find_all_paths(self):
        sources = self._g.get_sources()
        sinks = {n.unique_name for n in self._g.get_sinks()}
        if not sources or not sinks: return []
        paths = []
        for s in sources:
            if s.unique_name in sinks:
                paths.append(ReachabilityPath(source=s.unique_name, sink=s.unique_name, path=[s.unique_name], sink_type=s.sink_type))
            paths.extend(self._bfs(s.unique_name, sinks))
        return paths

    def _bfs(self, src, sinks):
        results, q = [], deque([[src]])
        while q and len(results) < self._mp:
            path = q.popleft(); node = self._g.get_node(path[-1])
            if not node: continue
            for c in node.resolved_calls:
                if c in path: continue
                np = path + [c]
                if c in sinks:
                    sn = self._g.get_node(c)
                    results.append(ReachabilityPath(source=src, sink=c, path=list(np), sink_type=sn.sink_type if sn else ""))
                    if len(results) >= self._mp: break
                    if len(np) < self._ml: q.append(np)
                elif len(np) < self._ml: q.append(np)
        return results


# ── reachability confirmer ───────────────────────────────────────────────────

_CANONICAL_FINDING_INSTRUCTIONS = """\

For every finding include canonical ownership fields:
{{"primary_file": "src/example.c", "primary_function": "example_function",
"primary_line": 123,
"canonical_key": "src/example.c:example_function:vulnerability_family:root_cause_token"}}
Choose primary_file/primary_function/primary_line as the location of the actual defective code,
not merely the source, caller, helper, or path endpoint.
If the same root cause appears through multiple paths, use the same canonical_key.
canonical_key should be stable and concise: file:function:vulnerability_family:root_cause_token.
Be conservative. Report each distinct root cause once.
Do not report a caller/path duplicate if the same primary defect is already represented.
Do not assign a bug to a helper/header unless the actual defective code is in that helper/header."""

_CONFIRM_SYS = """\
You are a security researcher specializing in C and C++ code analysis.
You are given reachable call paths from attacker input sources to flagged sinks, with relevant source code.
For EACH path determine if it is a real exploitable vulnerability:
1. Does attacker input actually propagate through every hop?
2. Are there sanitization or bounds checks?
3. Is the sink truly dangerous as called?
Return ONLY valid JSON:
{{"findings": [{{"path_index": 0, "is_vulnerable": true, "vulnerability_type": "buffer_overflow",
"severity": "high", "confidence": "high", "description": "...", "root_cause": "...", "evidence": "..."}}]}}
vulnerability_type: buffer_overflow, use_after_free, double_free, double_close, null_deref, command_injection, \
format_string, integer_overflow, path_traversal, race_condition, uninitialized_memory, type_confusion, \
out_of_bounds, refcount_imbalance, state_order, lock_order, stale_after_unlock, accounting_drift, \
missing_auth, permission_mismatch, info_leak, teardown_race, partial_cleanup, deferred_uaf, stale_state, \
toctou, other.
severity: critical, high, medium, low. confidence: high, medium, low. Be conservative.""" + _CANONICAL_FINDING_INSTRUCTIONS

_CONFIRM_USR = "{paths_section}\n\n{code_section}"

# --- Inbound: bugs rooted IN the target file ---

_FILE_CONFIRM_SYS = """\
You are a security researcher specializing in C and C++ code analysis.
You are reviewing ONE target file from a larger codebase.
You are given:
- reachable call paths from external or attacker-controlled sources
- the relevant code from the target file
- supporting code for upstream/downstream functions on the path
Only report a vulnerability when the primary bug mechanism is actually present in the TARGET FILE code shown.
If the real root cause is not in the target file, do not report it for this target file.
For EACH path determine if it is a real exploitable vulnerability in the target file:
1. Does attacker input actually propagate through the path into the target file logic?
2. Does the target file contain the missing validation, unsafe state transition, or dangerous sink usage?
3. Are there checks or lifecycle constraints that make the path non-exploitable?
4. Is the root cause in the target file rather than merely elsewhere on the path?
Return ONLY valid JSON:
{{"findings": [{{"path_index": 0, "is_vulnerable": true, "vulnerability_type": "buffer_overflow",
"severity": "high", "confidence": "high", "description": "...", "root_cause": "...", "evidence": "..."}}]}}
vulnerability_type: buffer_overflow, use_after_free, double_free, null_deref, command_injection, format_string, \
integer_overflow, path_traversal, race_condition, uninitialized_memory, type_confusion, out_of_bounds, \
state_order, lock_order, stale_after_unlock, accounting_drift, missing_auth, permission_mismatch, \
info_leak, teardown_race, partial_cleanup, deferred_uaf, stale_state, toctou, other.
severity: critical, high, medium, low. confidence: high, medium, low. Be conservative.""" + _CANONICAL_FINDING_INSTRUCTIONS

_FILE_CONFIRM_USR = """Target file: {target_file}
{paths_section}
== TARGET FILE CODE ==
{target_file_code}
== RELATED PATH CODE ==
{related_code_section}
"""

# --- Cross-file: bugs involving the target file's functions used by OTHER files ---

_CROSS_FILE_SYS = """\
You are a security researcher specializing in C and C++ code analysis.

You are reviewing how functions defined in the FOCUS FILE are used by OTHER files \
in the codebase. The goal is to find vulnerabilities that arise from cross-file \
interactions — where the focus file's functions are called, consumed, or depended \
upon by code in other files.

Report a vulnerability when:
- A function defined in the FOCUS FILE returns a value that callers in OTHER files \
  misinterpret (e.g. treating a permission level as boolean, ignoring error codes)
- A function in the FOCUS FILE produces output (string, buffer, pointer) that callers \
  in other files consume unsafely (e.g. copying into a smaller buffer without checking)
- A function in the FOCUS FILE frees/releases a resource, and callers in other files \
  also free/release the same resource, creating a double-free or double-close
- A function in the FOCUS FILE creates ambiguous ownership semantics that cause callers \
  to mismanage resources (e.g. parse function frees on some error paths but not others, \
  caller always frees)
- A function in the FOCUS FILE sanitizes or transforms data but does not update a \
  length/size field, causing callers to use stale metadata
- A function in the FOCUS FILE sets a state flag or readiness indicator that callers \
  depend on, but the flag is set before prerequisite operations complete

For each finding, identify both the focus-file function involved AND the caller \
function in the other file where the misuse occurs.

Return ONLY valid JSON:
{{"findings": [{{"path_index": 0, "is_vulnerable": true, "vulnerability_type": "boolean_coercion",
"severity": "high", "confidence": "high",
"description": "...", "root_cause": "...", "evidence": "..."}}]}}

vulnerability_type: boolean_coercion, double_free, double_close, buffer_overflow, \
use_after_free, wrong_constant, stale_length, type_confusion, state_order, \
refcount_imbalance, deferred_uaf, stale_state, partial_cleanup, other.
severity: critical, high, medium, low. confidence: high, medium, low.""" + _CANONICAL_FINDING_INSTRUCTIONS

_CROSS_FILE_USR = """Focus file: {target_file}

{paths_section}

== FOCUS FILE CODE (functions defined here) ==
{target_file_code}

== CALLER CODE (other files that use the focus file's functions) ==
{related_code_section}
"""


class VulnerabilityConfirmer:
    def __init__(
        self,
        llm_provider,
        model,
        usage_runtime,
        codebase_path,
        max_tokens=4096,
        reasoning_effort=None,
    ):
        self._p = llm_provider; self._m = model; self._u = usage_runtime
        self._cb = os.path.abspath(codebase_path); self._t = max_tokens
        self._reasoning_effort = reasoning_effort

    # --- Bulk confirmation (used by standalone reachability command) ---

    def confirm_parallel(self, paths, graph, *, max_workers=8, output_path=None, progress_callback=None):
        if not paths: return []
        groups = defaultdict(list)
        for p in paths: groups[p.sink].append(p)
        total = len(groups); all_f = []; lock = threading.Lock(); done = [0]
        if progress_callback: progress_callback({"event": "confirmation_start", "total": total})
        fh = None
        if output_path:
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            fh = open(output_path, "w", encoding="utf-8")
        try:
            with ThreadPoolExecutor(max_workers=max_workers) as ex:
                futs = {submit_with_current_context(ex, self._group, sn, gp, graph): sn for sn, gp in groups.items()}
                for fut in as_completed(futs):
                    sn = futs[fut]
                    try:
                        findings = fut.result()
                        with lock:
                            all_f.extend(findings)
                            if fh:
                                for f in findings: fh.write(json.dumps(f.to_dict(), ensure_ascii=False) + "\n")
                                fh.flush()
                    except Exception as e:
                        logger.warning("Confirm fail %s: %s", sn, e)
                        if progress_callback:
                            progress_callback({
                                "event": "confirmation_error",
                                "sink": sn,
                                "error": f"{type(e).__name__}: {e}",
                            })
                    with lock: done[0] += 1
                    if progress_callback: progress_callback({"event": "confirmation_progress", "completed": done[0], "total": total, "sink": sn})
        finally:
            if fh: fh.close()
        if progress_callback: progress_callback({"event": "confirmation_done", "confirmed": len(all_f)})
        return all_f

    def confirm_streaming(self, paths, graph, *, output_path=None, progress_callback=None):
        """Confirm paths one sink at a time and flush findings as soon as they arrive."""
        if not paths: return []
        groups = defaultdict(list)
        for p in paths: groups[p.sink].append(p)
        items = list(groups.items())
        total = len(items); all_f = []
        if progress_callback:
            progress_callback({"event": "confirmation_start", "total": total, "paths": len(paths)})
        fh = None
        if output_path:
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            fh = open(output_path, "w", encoding="utf-8")
        try:
            for done, (sn, gp) in enumerate(items, start=1):
                try:
                    findings = self._group(sn, gp, graph)
                except KeyboardInterrupt:
                    if progress_callback:
                        progress_callback({"event": "confirmation_cancelled", "completed": done - 1, "total": total, "sink": sn})
                    raise
                except Exception as e:
                    logger.warning("Confirm fail %s: %s", sn, e)
                    if progress_callback:
                        progress_callback({
                            "event": "confirmation_error",
                            "completed": done - 1,
                            "total": total,
                            "sink": sn,
                            "error": f"{type(e).__name__}: {e}",
                        })
                    findings = []
                if findings:
                    all_f.extend(findings)
                    if fh:
                        for f in findings:
                            fh.write(json.dumps(f.to_dict(), ensure_ascii=False) + "\n")
                        fh.flush()
                        try: os.fsync(fh.fileno())
                        except OSError: pass
                    if progress_callback:
                        progress_callback({
                            "event": "confirmation_findings",
                            "completed": done,
                            "total": total,
                            "sink": sn,
                            "findings": len(findings),
                            "confirmed": len(all_f),
                        })
                if progress_callback:
                    progress_callback({"event": "confirmation_progress", "completed": done, "total": total, "sink": sn})
        finally:
            if fh: fh.close()
        if progress_callback:
            progress_callback({"event": "confirmation_done", "confirmed": len(all_f)})
        return all_f

    def _group(self, sink_name, paths, graph):
        batch = paths[:8]; needed = {}
        for p in batch:
            for u in p.path:
                n = graph.get_node(u)
                if n: needed[u] = n
        ps = ["== CANDIDATE PATHS =="]
        for i, p in enumerate(batch):
            sn, sk = graph.get_node(p.source), graph.get_node(p.sink)
            ps.append(f"\nPath {i}:\n Chain: {' -> '.join(p.path)}")
            if sn: ps.append(f" Source: {sn.unique_name} (line {sn.line_number}) - {sn.source_reason}")
            if sk: ps.append(f" Sink: {sk.unique_name} (line {sk.line_number}) [{sk.sink_type}] - {sk.sink_reason}")
        cs = ["== SOURCE CODE =="]
        for u, n in needed.items():
            b = _read_function_body(self._cb, n)
            if b: cs.append(f"\n--- {u} (line {n.line_number}) ---\n{b}")
        kw = _chat_model_kwargs(self._u, reasoning_effort=getattr(self, "_reasoning_effort", None))
        chat = self._p.get_chat_model(model=self._m, max_tokens=self._t, temperature=0.1, **kw)
        prompt = ChatPromptTemplate.from_messages([("system", _CONFIRM_SYS), ("user", _CONFIRM_USR)])
        raw = (prompt | chat | StrOutputParser()).invoke({"paths_section": "\n".join(ps), "code_section": "\n".join(cs)}).strip()
        return self._parse_confirm(raw, batch, graph)

    def _parse_confirm(self, raw, batch, graph, *, target_file=None):
        parsed = parse_json_output(raw)
        if not isinstance(parsed, dict): return []
        fl = parsed.get("findings")
        if not isinstance(fl, list): return []
        results = []
        for e in fl:
            if not isinstance(e, dict) or not e.get("is_vulnerable"): continue
            idx = _safe_int(e.get("path_index"), -1)
            if idx < 0 or idx >= len(batch): continue
            rp = batch[idx]; sn = graph.get_node(rp.source); sk = graph.get_node(rp.sink)
            source_file = sn.file_path if sn else ""
            source_line = sn.line_number if sn else 0
            sink_file = sk.file_path if sk else ""
            sink_line = sk.line_number if sk else 0
            explicit_primary_file = str(e.get("primary_file") or "").strip()
            if target_file and explicit_primary_file and not _same_file_ref(explicit_primary_file, target_file, self._cb):
                continue
            primary_file, primary_function, primary_line, canonical_key = _canonical_fields(
                e, default_file=sink_file or source_file,
                default_function=rp.sink or rp.source,
                default_line=sink_line or source_line)
            results.append(VulnerabilityFinding(
                id=uuid.uuid4().hex[:16],
                vulnerability_type=_normalise_vuln_type(e.get("vulnerability_type") or rp.sink_type or "other"),
                severity=str(e.get("severity") or "medium"), confidence=str(e.get("confidence") or "medium"),
                source_function=rp.source, source_file=source_file, source_line=source_line,
                sink_function=rp.sink, sink_file=sink_file, sink_line=sink_line,
                path=list(rp.path), description=str(e.get("description") or ""),
                root_cause=str(e.get("root_cause") or ""), evidence=str(e.get("evidence") or ""),
                analysis_type="reachability", primary_file=primary_file,
                primary_function=primary_function, primary_line=primary_line,
                canonical_key=canonical_key))
        return results

    def confirm_for_file(self, target_file, paths, graph, *, max_workers=4, progress_callback=None):
        paths = _dedupe_paths(paths)
        if not paths: return []
        batches = list(_chunked(paths, 8))
        all_findings = []
        with ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(batches)))) as ex:
            futs = {submit_with_current_context(ex, self._confirm_file_batch, target_file, batch, graph): idx for idx, batch in enumerate(batches)}
            for fut in as_completed(futs):
                try: all_findings.extend(fut.result())
                except Exception as e: logger.warning("Error confirming inbound paths for %s: %s", target_file, e)
        return all_findings

    def _confirm_file_batch(self, target_file, batch, graph):
        target_nodes, related_nodes = {}, {}
        for p in batch:
            for u in p.path:
                n = graph.get_node(u)
                if not n: continue
                if n.file_path == target_file: target_nodes[u] = n
                else: related_nodes[u] = n
        ps = ["== CANDIDATE PATHS =="]
        for i, p in enumerate(batch):
            sn, sk = graph.get_node(p.source), graph.get_node(p.sink)
            ps.append(f"\nPath {i}:\n Chain: {' -> '.join(p.path)}")
            if sn: ps.append(f" Source: {sn.unique_name} (line {sn.line_number}) - {sn.source_reason}")
            if sk: ps.append(f" Sink: {sk.unique_name} (line {sk.line_number}) [{sk.sink_type}] - {sk.sink_reason}")
        tc = ["-- Functions from target file --"]
        for u, n in target_nodes.items():
            body = _read_function_body(self._cb, n, 5000)
            if body: tc.append(f"\n--- {u} (line {n.line_number}) ---\n{body}")
        rc = ["-- Supporting code from other files --"]
        for u, n in related_nodes.items():
            body = _read_function_body(self._cb, n, 2500)
            if body: rc.append(f"\n--- {u} (line {n.line_number}) ---\n{body}")
        kw = _chat_model_kwargs(self._u, reasoning_effort=getattr(self, "_reasoning_effort", None))
        chat = self._p.get_chat_model(model=self._m, max_tokens=self._t, temperature=0.1, **kw)
        prompt = ChatPromptTemplate.from_messages([("system", _FILE_CONFIRM_SYS), ("user", _FILE_CONFIRM_USR)])
        raw = (prompt | chat | StrOutputParser()).invoke({
            "target_file": target_file, "paths_section": "\n".join(ps),
            "target_file_code": "\n".join(tc), "related_code_section": "\n".join(rc)}).strip()
        return self._parse_confirm(raw, batch, graph, target_file=target_file)

    def confirm_cross_file(self, target_file, paths, graph, *, max_workers=4, progress_callback=None):
        """Find bugs where OTHER files misuse functions defined in target_file."""
        paths = _dedupe_paths(paths)
        if not paths: return []
        batches = list(_chunked(paths, 8))
        all_findings = []
        with ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(batches)))) as ex:
            futs = {submit_with_current_context(ex, self._confirm_cross_file_batch, target_file, batch, graph): idx
                    for idx, batch in enumerate(batches)}
            for fut in as_completed(futs):
                try: all_findings.extend(fut.result())
                except Exception as e: logger.warning("Error confirming cross-file paths for %s: %s", target_file, e)
        return all_findings

    def _confirm_cross_file_batch(self, target_file, batch, graph):
        target_nodes, caller_nodes = {}, {}
        for p in batch:
            for u in p.path:
                n = graph.get_node(u)
                if not n: continue
                if n.file_path == target_file:
                    target_nodes[u] = n
                else:
                    caller_nodes[u] = n

        if not target_nodes or not caller_nodes:
            return []

        ps = ["== PATHS INVOLVING FOCUS FILE FUNCTIONS =="]
        for i, p in enumerate(batch):
            sn, sk = graph.get_node(p.source), graph.get_node(p.sink)
            ps.append(f"\nPath {i}:\n Chain: {' -> '.join(p.path)}")
            if sn: ps.append(f" Source: {sn.unique_name} (line {sn.line_number}) - {sn.source_reason}")
            if sk: ps.append(f" Sink: {sk.unique_name} (line {sk.line_number}) [{sk.sink_type}] - {sk.sink_reason}")
            focus_fns = [u for u in p.path if graph.get_node(u) and graph.get_node(u).file_path == target_file]
            if focus_fns:
                ps.append(f" Focus-file functions on this path: {', '.join(focus_fns)}")

        tc = ["-- FOCUS FILE: functions defined here --"]
        for u, n in target_nodes.items():
            body = _read_function_body(self._cb, n, 5000)
            if body: tc.append(f"\n--- {u} (line {n.line_number}) ---\n{body}")

        rc = ["-- CALLERS: code in other files that uses focus-file functions --"]
        for u, n in caller_nodes.items():
            body = _read_function_body(self._cb, n, 3000)
            if body: rc.append(f"\n--- {u} (line {n.line_number} in {n.file_path}) ---\n{body}")

        kw = _chat_model_kwargs(self._u, reasoning_effort=getattr(self, "_reasoning_effort", None))
        chat = self._p.get_chat_model(model=self._m, max_tokens=self._t, temperature=0.1, **kw)
        prompt = ChatPromptTemplate.from_messages([("system", _CROSS_FILE_SYS), ("user", _CROSS_FILE_USR)])
        raw = (prompt | chat | StrOutputParser()).invoke({
            "target_file": target_file, "paths_section": "\n".join(ps),
            "target_file_code": "\n".join(tc), "related_code_section": "\n".join(rc)}).strip()

        parsed = parse_json_output(raw)
        if not isinstance(parsed, dict): return []
        fl = parsed.get("findings")
        if not isinstance(fl, list): return []
        results = []
        for e in fl:
            if not isinstance(e, dict) or not e.get("is_vulnerable"): continue
            idx = _safe_int(e.get("path_index"), -1)
            if idx < 0 or idx >= len(batch): continue
            rp = batch[idx]; sn = graph.get_node(rp.source); sk = graph.get_node(rp.sink)
            focus_fn = None
            for u in rp.path:
                n = graph.get_node(u)
                if n and n.file_path == target_file:
                    focus_fn = n; break
            sink_file = target_file
            sink_fn = focus_fn.unique_name if focus_fn else rp.sink
            sink_line = focus_fn.line_number if focus_fn else (sk.line_number if sk else 0)
            source_file = sn.file_path if sn else ""
            source_line = sn.line_number if sn else 0
            primary_file, primary_function, primary_line, canonical_key = _canonical_fields(
                e, default_file=sink_file or source_file,
                default_function=sink_fn or rp.source,
                default_line=sink_line or source_line)
            results.append(VulnerabilityFinding(
                id=uuid.uuid4().hex[:16],
                vulnerability_type=_normalise_vuln_type(e.get("vulnerability_type") or "other"),
                severity=str(e.get("severity") or "medium"),
                confidence=str(e.get("confidence") or "medium"),
                source_function=rp.source, source_file=source_file,
                source_line=source_line,
                sink_function=sink_fn, sink_file=sink_file, sink_line=sink_line,
                path=list(rp.path), description=str(e.get("description") or ""),
                root_cause=str(e.get("root_cause") or ""),
                evidence=str(e.get("evidence") or ""),
                analysis_type="cross_file", primary_file=primary_file,
                primary_function=primary_function, primary_line=primary_line,
                canonical_key=canonical_key))
        return results


# ── supplementary analyzer ───────────────────────────────────────────────────

_RESOURCE_KW = frozenset({
    "free", "malloc", "calloc", "realloc", "close", "destroy", "release",
    "delete", "munmap", "unref", "grow", "compact", "resize",
    "kfree", "vfree", "devm_kfree", "put", "get", "ref", "unref",
})
_AUTH_KW = frozenset({
    "auth", "login", "check", "verify", "compare", "validate", "token",
    "password", "permit", "deny", "match", "level", "permission",
    "capable", "access_ok",
})
_HW_STATE_KW = frozenset({
    "ready", "init", "enable", "disable", "reset", "power", "suspend",
    "resume", "probe", "remove", "shutdown", "flush", "drain",
    "start", "stop", "halt", "abort", "fence", "sync",
    "doorbell", "register", "mmio", "firmware", "fw",
    "irq", "interrupt", "handler", "callback", "work", "timer",
    "schedule", "cancel", "queue", "dequeue",
    "lock", "unlock", "mutex", "spinlock", "spin_lock", "spin_unlock",
})
_LIFECYCLE_KW = frozenset({
    "create", "alloc", "open", "setup", "teardown", "cleanup",
    "fini", "exit", "deinit", "unregister", "detach",
    "load", "unload", "bind", "unbind",
})

_CLASSIC_C_SINK_RE = re.compile(
    r"\b(?:sprintf|vsprintf|strcpy|strcat|gets|scanf|sscanf|memcpy|memmove|strncpy|"
    r"snprintf|system|popen|exec(?:l|le|lp|lpe|v|ve|vp|vpe)?|fopen|open|stat|"
    r"lstat|access|printf|fprintf|vprintf|vfprintf|malloc|calloc|realloc|free|"
    r"strlen|strnlen|close|auth_get_level|store_unref|store_compact|task_serialize|"
    r"util_log|session_sweep|session_close|notify_fire)\s*\(",
    re.IGNORECASE,
)
_ERROR_UNWIND_RE = re.compile(
    r"\b(?:malloc|calloc|realloc|goto|rb_link_node|rb_erase|list_add|list_del|"
    r"hash_add|insert|register)\b|return\s+(?:NULL|-1)|ctx->regions|"
    r"\b(?:region_count|queue_count|ctx_count)\b|(?:^|_)(?:insert|register|create)(?:_|$)",
    re.IGNORECASE,
)
_COUNTER_RE = re.compile(
    r"\b(?:count|refcount|refs|gpu_mappings|alias_count|region_count|queue_count|"
    r"ctx_count|nr_pages|total|get|put|create|destroy|map|unmap|alias|shrink|grow)\b|"
    r"(?:^|_)(?:get|put|ref|unref|create|destroy|map|unmap|alias|shrink|grow)(?:_|$)|"
    r"\+\+|--|\+=|-=",
    re.IGNORECASE,
)
_ORDERING_GAP_RE = re.compile(
    r"\b(?:flush|sync|drain|fence|reset|power|pm|suspend|resume|disable|enable|"
    r"shutdown|term|mmu|dma)\b|"
    r"(?:^|_)(?:flush|sync|drain|fence|reset|power|pm|suspend|resume|disable|"
    r"enable|shutdown|term|mmu|dma)(?:_|$)",
    re.IGNORECASE,
)
_PATH_ACCESS_RE = re.compile(
    r"\b(?:fopen|open|stat|lstat|access|realpath|canonicalize|snprintf)\s*\(|"
    r"\b(?:path|full_path|file|filename|fw_name|name)\b",
    re.IGNORECASE,
)
_GLOBAL_LIFECYCLE_NAME_RE = re.compile(
    r"(?:init|term|shutdown|release|destroy|poll|flush|submit|callback|worker|"
    r"timer|watchdog|open|ioctl|unregister|cancel)",
    re.IGNORECASE,
)
_LOCK_EVENT_RE = re.compile(
    r"\b(?P<fn>pthread_mutex_lock|pthread_mutex_unlock|mutex_lock|mutex_unlock|"
    r"spin_lock(?:_irqsave|_irq)?|spin_unlock(?:_irqrestore|_irq)?)\s*"
    r"\(\s*(?P<arg>[^,\)]+)",
    re.IGNORECASE,
)
_RELATED_FILE_FUNCTION_KEYWORDS = frozenset({
    "init", "term", "shutdown", "destroy", "release", "cancel", "flush",
    "create", "get", "put", "ref", "unref", "map", "unmap", "grow",
    "shrink", "alias", "load", "unload", "verify", "open", "poll",
    "ioctl", "enable", "disable", "reset", "schedule", "callback",
    "worker", "work", "timer", "watchdog",
})

def _node_match_text(codebase_path, node, max_chars=12000):
    body = _read_function_body(codebase_path, node, max_chars)
    return f"{node.name}\n{' '.join(node.calls)}\n{body}"

def _select_nodes_by_regex(graph, codebase_path, pattern, *, max_body_chars=12000):
    nodes = []
    for node in sorted(graph.nodes.values(), key=lambda n: (n.file_path, n.line_number, n.name)):
        if pattern.search(_node_match_text(codebase_path, node, max_body_chars)):
            nodes.append(node)
    return nodes

def _function_name_tokens(name):
    return [t for t in re.split(r"[^a-z0-9]+", str(name or "").lower()) if t]

def _related_function_score(seed_nodes, node, relation_keywords):
    name_l = str(node.name or "").lower()
    if not any(k in name_l for k in relation_keywords):
        return 0

    node_tokens = set(_function_name_tokens(node.name))
    node_stem = node_tokens - set(relation_keywords)
    score = 0
    nearest = None
    for seed in seed_nodes:
        seed_tokens = set(_function_name_tokens(seed.name))
        seed_stem = seed_tokens - set(relation_keywords)
        shared_stem = node_stem & seed_stem
        if shared_stem:
            score = max(score, 10 + len(shared_stem) * 3)
        elif seed_tokens and node_tokens and sorted(seed_tokens)[0] in node_tokens:
            score = max(score, 4)
        distance = abs(int(node.line_number or 0) - int(seed.line_number or 0))
        nearest = distance if nearest is None else min(nearest, distance)
    if score and nearest is not None and nearest <= 160:
        score += max(1, 8 - nearest // 20)
    return score

def _expand_candidates_with_related_file_functions(graph, candidates, relation_keywords, max_extra_per_file=8):
    """Add a capped set of same-file lifecycle/accounting siblings for local context."""
    if not candidates:
        return []
    relation_keywords = frozenset(str(k).lower() for k in relation_keywords if str(k).strip())
    if not relation_keywords:
        return list(candidates)

    selected = {node.unique_name: node for node in candidates}
    by_file = defaultdict(list)
    for node in candidates:
        by_file[node.file_path].append(node)

    for file_path, seed_nodes in by_file.items():
        scored = []
        for node in graph.get_file_nodes(file_path):
            if node.unique_name in selected:
                continue
            score = _related_function_score(seed_nodes, node, relation_keywords)
            if score <= 0:
                continue
            nearest = min(abs(int(node.line_number or 0) - int(seed.line_number or 0)) for seed in seed_nodes)
            scored.append((-score, nearest, int(node.line_number or 0), node.name, node))
        for _, _, _, _, node in sorted(scored)[:max_extra_per_file]:
            selected[node.unique_name] = node

    return sorted(selected.values(), key=lambda n: (n.file_path, int(n.line_number or 0), n.name))

# ── pass 1: intra-function ──

_INTRA_SYS = """\
You are a C/C++ vulnerability expert. Examine each function below for bugs WITHIN the function itself.
Look for:
1. DOUBLE-FREE / DOUBLE-CLOSE: Can any path free/close the same resource twice? goto to cleanup that frees something already freed on an error path.
2. AUTH / COMPARISON LOGIC ERRORS: Is the CORRECT field used for length/comparison? Can empty input bypass a check? Is a return value (role/level/enum) incorrectly used as a boolean?
3. INTEGER OVERFLOW IN SIZE CALCULATIONS: Can (count * sizeof(T)) wrap size_t? Struct sizes are often 100-2000 bytes!
4. ARRAY INDEX OUT OF BOUNDS: arr[flags & 0x0F] with arr[4] — mask allows 0-15.
5. RESOURCE LEAKS on error paths: malloc without free on early return; open without close.
   Report resource leaks as partial_cleanup, not double_free.
6. FORMAT STRING: User/external data passed as format argument to printf/vfprintf/sprintf.
   Do NOT report fixed literal formats such as fprintf(out, "%s\\n", msg).
7. COMMAND INJECTION: system()/popen()/exec*() with string built from user input.
8. PATH TRAVERSAL: fopen/stat/access with path from user input without canonicalization.
9. TOCTOU: stat/access check followed by fopen/unlink on the same path.
10. NULL DEREFERENCE: Pointer used before its null-check, or dereferenced without checking after fallible lookup.
11. MISSING BOUNDS CHECK: memcpy/sprintf/strncpy with size from parameter without validation.
12. STATE ORDERING: Setting ready/enabled flag BEFORE prerequisite validation/initialization completes.
13. STALE METADATA: Modifying buffer content without updating associated length/size field.
Return ONLY valid JSON:
{{"findings": [{{"vulnerability_type": "double_free", "severity": "high", "confidence": "high", \
"function_name": "handle_set", "line": 55, "description": "...", "root_cause": "...", "evidence": "..."}}]}}
Return {{"findings": []}} if none found. Be thorough but report each distinct bug only ONCE.""" + _CANONICAL_FINDING_INSTRUCTIONS

_INTRA_USR = "File: {file_path}\n\n{functions_code}"

# ── pass 2: lifecycle / UAF ──

_LIFE_SYS = """\
You are analyzing a C/C++ codebase for USE-AFTER-FREE, DANGLING POINTER, and LIFETIME bugs spanning MULTIPLE functions.
Below are functions from the codebase. Analyze their INTERACTIONS:
1. USE-AFTER-FREE: Function A frees a resource, Function B later dereferences it.
2. DANGLING POINTERS: Pointers in global/shared structures not NULLed when target freed.
3. LIFETIME MISMATCH: Object A stores pointer to B, but B can be destroyed while A exists.
4. DEFERRED CALLBACK UAF: A timer/work/watchdog is registered with an object as context. \
   The object is freed or torn down without canceling/flushing the pending callback. \
   When the callback fires, it dereferences freed memory.
5. STALE POINTER AFTER REALLOC: Code caches a pointer, then calls a function that may \
   realloc/grow/compact the backing store. The cached pointer is now stale.
Return ONLY valid JSON:
{{"findings": [{{"vulnerability_type": "use_after_free", "severity": "high", "confidence": "high", \
"free_function": "session_close", "use_function": "store_lookup", \
"description": "...", "root_cause": "...", "evidence": "..."}}]}}
Return {{"findings": []}} if none found.""" + _CANONICAL_FINDING_INSTRUCTIONS

_LIFE_USR = "{all_functions_code}"

# ── pass 3: ownership / cleanup ──

_OWN_SYS = """\
You are analyzing a C/C++ codebase for RESOURCE OWNERSHIP, CLEANUP COORDINATION, and TEARDOWN bugs.
Examine ALL functions below for:
1. DOUBLE-FREE / DOUBLE-CLOSE ACROSS FUNCTIONS: Function A frees on error, caller also frees unconditionally. \
   A callee frees a resource and returns error, but the caller frees the same resource on error.
2. REFCOUNT IMBALANCE: get/ref and put/unref are not called in matched pairs. \
   Also check: are get/put functions actually no-ops (empty body or just return)?
3. CLEANUP SYMMETRY: init/setup allocates or registers N resources, but teardown/cleanup \
   only releases N-1 (missing cancel_work, del_timer, unregister, iounmap, etc.).
4. PARTIAL CLEANUP ON ERROR: An init function allocates A, B, C in sequence. If C fails, \
   it cleans up C but forgets to clean up A or B.
5. ROLLBACK GAP: A function adds an entry to a data structure (rbtree, list, hash) then \
   fails a later step but does not remove the entry — leaving a dangling/corrupt entry.
6. CALLBACK / REGISTRATION LIFECYCLE: Register callback with object as context (work_queue, \
   timer, irq), free object without unregistering/canceling.
Return ONLY valid JSON:
{{"findings": [{{"vulnerability_type": "double_free", "severity": "high", "confidence": "high", \
"function_a": "proto_parse", "function_b": "dispatch", \
"description": "...", "root_cause": "...", "evidence": "..."}}]}}
Return {{"findings": []}} if none found.""" + _CANONICAL_FINDING_INSTRUCTIONS

_OWN_USR = "{all_functions_code}"

# ── pass 4: semantic / type / data-flow ──

_SEM_SYS = """\
You are analyzing a C/C++ codebase for SEMANTIC, TYPE, and DATA-FLOW correctness bugs.
Examine ALL functions below for:
1. BOOLEAN COERCION OF RICH RETURNS: Function returns level/enum/count, caller checks with if (!func()). \
   This collapses a multi-valued result into a binary test.
2. WRONG ENUM / CONSTANT: Permission check uses wrong resource type constant. \
   Example: checking GPU_WR permission when CPU_WR is needed.
3. TYPE CONFUSION / VOID* MISCAST: void* from generic store cast without checking type tag.
4. WRONG STRUCT FIELD: raw_len used where data_len needed, or nr_pages vs size confusion.
5. FIELD STALENESS AFTER MUTATION: Data sanitized/transformed but old length/count stored — callers use stale value.
6. WIDTH MISMATCH: A 32-bit variable used to check a 64-bit value, causing truncation. \
   Or: uint32_t comparison against a size_t/uint64_t parameter.
7. ARRAY INDEX vs SIZE MISMATCH: arr[flags & 0x0F] where array has fewer than 16 entries.
8. INTEGER OVERFLOW IN ALLOCATION: new_cap * sizeof(large_struct) wraps size_t.
9. UNINITIALIZED DATA EXPOSURE: malloc + partial init + memcpy entire struct to network/user.
10. WRONG FLAG SEMANTIC: Using DONT_NEED where NO_USER_FREE is intended, or similar flag confusion.
11. ACCOUNTING DRIFT: A counter (gpu_mappings, alias_count, nr_pages) is incremented on add \
    but not decremented on remove, or vice versa. Or: counter tracks one quantity but is \
    compared against a different quantity.
12. INFO LEAK: Logging/printing physical addresses, keys, tokens, or other sensitive data.
13. MISSING AUTH / PERMISSION CHECK: A privileged operation (reset, firmware load, debug access) \
    lacks any capability or permission check.
Return ONLY valid JSON:
{{"findings": [{{"vulnerability_type": "boolean_coercion", "severity": "high", "confidence": "high", \
"function_name": "dispatch", "related_function": "auth_get_level", \
"description": "...", "root_cause": "...", "evidence": "..."}}]}}
Return {{"findings": []}} if none found. Be EXTREMELY thorough.""" + _CANONICAL_FINDING_INSTRUCTIONS

_SEM_USR = "{all_functions_code}"

# ── pass 5: state ordering and concurrency ──

_STATE_SYS = """\
You are analyzing a C/C++ codebase for STATE ORDERING, CONCURRENCY, and SYNCHRONIZATION bugs.
Examine ALL functions below for:
1. PREMATURE STATE TRANSITION: A "ready", "enabled", or "initialized" flag/field is set \
   BEFORE the object is actually ready. Other code that checks the flag may observe \
   partially initialized state.
2. ORDERING GAP: An operation (flush, sync, drain, fence) must complete before another \
   (power off, teardown, reset), but the code does not enforce the ordering (missing \
   wait/flush/barrier before the dependent operation).
3. STALE-AFTER-UNLOCK: Code reads a value while holding a lock, releases the lock, \
   then uses the value. Another thread may have changed the underlying data.
4. LOCK ORDER INVERSION: Two or more locks are acquired in inconsistent orders across \
   different functions, creating deadlock potential. E.g. function A takes lock1→lock2 \
   but function B takes lock2→lock1.
5. TEARDOWN RACE: A teardown/cleanup function destroys a mutex, frees a workqueue, \
   or releases a resource while pending work/timers/callbacks may still reference it. \
   Must cancel/flush work before destroying the synchronization primitive.
6. MISSING LOCK: A shared data structure is accessed without holding the protecting lock \
   in some code paths, while other paths properly lock.
7. STALE STATE AFTER DISABLE: A hardware resource (doorbell, ring buffer, DMA channel) \
   is disabled but associated software state (cached pointers, pending flags) is not \
   cleared/reset, causing stale state if re-enabled or inspected.
Return ONLY valid JSON:
{{"findings": [{{"vulnerability_type": "state_order", "severity": "high", "confidence": "high", \
"function_name": "device_init", "related_function": "device_ready_check", \
"description": "...", "root_cause": "...", "evidence": "..."}}]}}
Return {{"findings": []}} if none found. Be thorough.""" + _CANONICAL_FINDING_INSTRUCTIONS

_STATE_USR = "{all_functions_code}"

_TARGET_STATE_SYS = """\
You are analyzing C/C++ GPU, firmware, and driver-style code for ready/state flag ordering bugs.
Target only this bug class:
- State flags or fields named like gpu_ready, loaded, active, initialized, enabled,
  runtime_active, gpu_powered, ready, or online are set before validation, allocation,
  registration, firmware load, hardware init, or capability checks complete.
- An error path after the state transition does not roll the state back.
- Other functions later trust that state flag to access hardware, firmware, DMA, queues,
  MMIO, or privileged operations.
Return ONLY valid JSON:
{{"findings": [{{"vulnerability_type": "state_order", "severity": "high",
"confidence": "high", "function_name": "gpu_init", "related_function": "gpu_submit",
"description": "...", "root_cause": "...", "evidence": "..."}}]}}
Return {{"findings": []}} if none found. Be conservative.""" + _CANONICAL_FINDING_INSTRUCTIONS

_TARGET_CALLBACK_SYS = """\
You are analyzing C/C++ GPU, firmware, and driver-style code for callback teardown symmetry bugs.
Target only this bug class:
- timer/work/watchdog/callback fn/data/ctx is initialized with an object pointer.
- A pending, armed, active, scheduled, or enabled state is set later.
- Teardown, release, remove, shutdown, error cleanup, or destroy/free code does not
  cancel, deactivate, flush, unregister, or clear the callback before freeing the
  object or destroying its mutex/workqueue.
- file_operations or ops tables show lifecycle asymmetry, such as .release without
  a needed .flush/cancel path.
Return ONLY valid JSON:
{{"findings": [{{"vulnerability_type": "teardown_race", "severity": "high",
"confidence": "high", "function_name": "gpu_remove", "related_function": "gpu_watchdog_fn",
"description": "...", "root_cause": "...", "evidence": "..."}}]}}
Return {{"findings": []}} if none found. Be conservative.""" + _CANONICAL_FINDING_INSTRUCTIONS

_TARGET_REFCOUNT_SYS = """\
You are analyzing C/C++ code for no-op reference counting helpers.
Target only this bug class:
- Functions named like *_get, *_put, *_ref, *_unref, acquire, release, retain, or drop
  have empty/no-op bodies, only return a pointer, only cast, or only log.
- They do not update a refcount/atomic/kref/state value and do not free on final put.
- Callers rely on those helpers for lifetime safety.
Return ONLY valid JSON:
{{"findings": [{{"vulnerability_type": "refcount_imbalance", "severity": "high",
"confidence": "high", "function_name": "gpu_ctx_get", "related_function": "gpu_ctx_put",
"description": "...", "root_cause": "...", "evidence": "..."}}]}}
Return {{"findings": []}} if none found. Be conservative.""" + _CANONICAL_FINDING_INSTRUCTIONS

_TARGET_PERMISSION_SYS = """\
You are analyzing C/C++ GPU, firmware, and driver-style code for permission-domain mismatches.
Target only these bug classes:
- A privileged CPU operation checks GPU_WR or a GPU-only permission when CPU_WR is needed.
- A channel, message, firmware, reset, debug, sysfs, ioctl, or destructive operation
  checks a wrong resource constant such as RES_MSG before channel deletion.
- A function returns a numeric permission level or role and callers treat it as a boolean,
  allowing low-privilege nonzero values to pass high-privilege checks.
- A caller checks the wrong resource/domain constant for the operation being performed,
  such as checking task permission before creating/deleting a project.
- A privileged operation uses a generic boolean permission check where a domain-specific
  capability/permission check is required.
- reset, firmware load, debug, MMIO, DMA, or register access lacks capability or
  permission checks entirely.
Return ONLY valid JSON:
{{"findings": [{{"vulnerability_type": "permission_mismatch", "severity": "high",
"confidence": "high", "function_name": "gpu_ioctl_reset", "related_function": "gpu_check_perm",
"description": "...", "root_cause": "...", "evidence": "..."}}]}}
Return {{"findings": []}} if none found. Be conservative.""" + _CANONICAL_FINDING_INSTRUCTIONS

_TARGET_TOCTOU_SYS = """\
You are analyzing C/C++ code for filesystem time-of-check/time-of-use bugs.
Target only this bug class:
- stat, lstat, access, faccessat, or similar path checks are followed by fopen, open,
  unlink, rename, chmod, chown, truncate, or another mutating/opening operation on
  the same or clearly related path variable.
- There is no safe open-by-handle, O_NOFOLLOW/openat discipline, directory fd pinning,
  or post-open validation that closes the race.
Return ONLY valid JSON:
{{"findings": [{{"vulnerability_type": "toctou", "severity": "medium",
"confidence": "high", "function_name": "load_firmware_path", "related_function": "",
"description": "...", "root_cause": "...", "evidence": "..."}}]}}
Return {{"findings": []}} if none found. Be conservative.""" + _CANONICAL_FINDING_INSTRUCTIONS

_CLASSIC_C_SINK_SYS = """\
You are analyzing selected C/C++ functions that contain classic dangerous APIs.
Only report concrete bugs in the shown functions:
1. Unbounded sprintf/vsprintf/strcpy/strcat into fixed-size or caller-provided buffers.
2. memcpy/memmove/strncpy where the copy size may exceed destination capacity.
3. Integer overflow in allocation or copy size calculations.
4. Format string bugs ONLY when attacker-controlled data is the actual format parameter.
   Do NOT report fprintf(out, "%s\\n", msg), printf("%s", msg), or other fixed-literal
   formats as format-string vulnerabilities.
5. Command injection through system/popen/exec* with attacker-controlled command strings.
6. Path traversal/arbitrary file access when caller-controlled paths reach fopen/open/stat/access
   without canonicalization and base-directory restriction.
7. TOCTOU when stat/access/lstat is followed by open/fopen/unlink/etc. on the same path.
8. NULL dereference after failed allocation/lookup and out-of-bounds indexing.
Return ONLY valid JSON:
{{"findings": [{{"vulnerability_type": "buffer_overflow", "severity": "high",
"confidence": "high", "function_name": "gpu_debug_dump_context", "line": 123,
"description": "...", "root_cause": "...", "evidence": "..."}}]}}
Return {{"findings": []}} if none found. Be conservative and report each root cause once.""" + _CANONICAL_FINDING_INSTRUCTIONS

_ERROR_UNWIND_SYS = """\
You are analyzing selected C/C++ functions for error-unwind, cleanup, and rollback bugs.
Focus only on:
- Partial cleanup: a loop allocates multiple objects and a later failure leaks earlier objects.
- Ownership overwrite: object fields such as region->pages are overwritten without releasing old storage.
- Rollback gap: rb_link_node/list_add/hash_add/insert/register publishes an object, then later
  validation or registration fails without rb_erase/list_del/hash removal/unregister.
- No-op rollback helper: cleanup calls a helper like rb_erase/list_del/unregister, but the
  helper body shown is empty or ineffective.
- Object publication before full initialization succeeds.
- Do not report borrowed pointer fields being set to NULL as leaks unless this function
  actually owns the pointed-to memory.
Return ONLY valid JSON:
{{"findings": [{{"vulnerability_type": "rollback_gap", "severity": "high",
"confidence": "high", "function_name": "gpu_region_create", "related_function": "rb_erase",
"description": "...", "root_cause": "...", "evidence": "..."}}]}}
Return {{"findings": []}} if none found. Be conservative and do not report style-only cleanup issues.""" + _CANONICAL_FINDING_INSTRUCTIONS

_COUNTER_SYMMETRY_SYS = """\
You are analyzing selected C/C++ functions for counter, refcount, and accounting symmetry bugs.
Compare add/remove, create/destroy, map/unmap, alias_create/alias_destroy, get/put,
grow/shrink, and allocation/free pairs.
Report only concrete mismatches:
- gpu_mappings++ on map but no decrement on unmap.
- alias_count checked but never incremented on alias creation, or not decremented on destroy.
- region/page/queue/context counts incremented but not decremented.
- Delta computed after overwriting the old value.
- No-op get/put/ref/unref helpers that callers rely on for lifetime or accounting.
Return ONLY valid JSON:
{{"findings": [{{"vulnerability_type": "accounting_drift", "severity": "medium",
"confidence": "high", "function_name": "gpu_region_create_alias",
"related_function": "gpu_region_destroy_alias",
"description": "...", "root_cause": "...", "evidence": "..."}}]}}
Return {{"findings": []}} if none found. Be conservative.""" + _CANONICAL_FINDING_INSTRUCTIONS

_GLOBAL_LIFECYCLE_SYS = """\
You are analyzing global C/C++ callback and file-operations tables plus referenced functions.
Focus on:
- struct file_operations / fops tables, ops tables, timer/work/watchdog callback tables.
- .open, .release, .flush, .poll, .ioctl lifecycle expectations.
- init/term/register/unregister/cancel/flush symmetry.
- .release and .poll/.ioctl without .flush when fork/dup/shared-fd lifecycle can keep
  callbacks or references alive beyond release.
- callback fn/data initialized with object context, but teardown does not cancel/flush
  before free/destroy/mutex_destroy.
Return ONLY valid JSON:
{{"findings": [{{"vulnerability_type": "teardown_race", "severity": "high",
"confidence": "high", "function_name": "gpu_file_release", "related_function": "gpu_file_poll",
"description": "...", "root_cause": "...", "evidence": "..."}}]}}
Return {{"findings": []}} if none found. Be conservative and report only actionable lifecycle gaps.""" + _CANONICAL_FINDING_INSTRUCTIONS

_LOCK_ORDER_SYS = """\
You are analyzing deterministic lock acquisition sequences extracted from C/C++ functions.
Confirm only real lock-order inversions:
- Function A acquires lock A then lock B while Function B can acquire lock B then lock A.
- The locks protect shared state and the functions can run concurrently.
- Ignore sequences where one lock is released before the other is acquired or where the
  ordering is impossible due to clear call/lifecycle constraints.
Return ONLY valid JSON:
{{"findings": [{{"vulnerability_type": "lock_order", "severity": "medium",
"confidence": "high", "function_name": "gpu_sched_submit", "related_function": "gpu_ctx_destroy",
"description": "...", "root_cause": "...", "evidence": "..."}}]}}
Return {{"findings": []}} if none found. Be conservative.""" + _CANONICAL_FINDING_INSTRUCTIONS

_TARGET_ORDERING_GAP_SYS = """\
You are analyzing C/C++ driver-like code for operation ordering gaps.
Focus only on:
- flush/sync/drain/fence/reset/power transition ordering bugs.
- Power state changed while mutating MMU/DMA/register/shared state.
- Power off/on published during MMU mutation.
- Missing wait/flush/barrier before dependent operation.
- Missing PM/MMU lock coordination around power transitions.
Return ONLY valid JSON:
{{"findings": [{{"vulnerability_type": "ordering_gap", "severity": "high",
"confidence": "high", "function_name": "gpu_mmu_insert_pages",
"related_function": "gpu_power_off",
"description": "...", "root_cause": "...", "evidence": "..."}}]}}
Return {{"findings": []}} if none found. Be conservative.""" + _CANONICAL_FINDING_INSTRUCTIONS

_TARGET_PATH_ACCESS_SYS = """\
You are analyzing selected C/C++ functions for path traversal and filesystem TOCTOU.
Target only:
- Caller/user-controlled path used directly in fopen/open/stat/access.
- No canonicalization and no restriction to a base directory.
- /lib/firmware/%s with unchecked fw_name allowing ../ traversal.
- Direct full_path opened with no validation.
- stat/access/lstat followed by fopen/open on the same path.
Prefer vulnerability_type path_traversal or toctou. Do not classify as missing_auth
unless the real root cause is authorization rather than filesystem path validation.
Return ONLY valid JSON:
{{"findings": [{{"vulnerability_type": "path_traversal", "severity": "high",
"confidence": "high", "function_name": "gpu_fw_load_custom", "related_function": "",
"description": "...", "root_cause": "...", "evidence": "..."}}]}}
Return {{"findings": []}} if none found. Be conservative.""" + _CANONICAL_FINDING_INSTRUCTIONS


class SupplementaryAnalyzer:
    def __init__(self, llm_provider, audit_model, strong_model, usage_runtime, codebase_path,
                 audit_max_tokens=8192, strong_max_tokens=16384, reasoning_effort=None):
        self._p = llm_provider; self._am = audit_model; self._sm = strong_model
        self._u = usage_runtime; self._cb = os.path.abspath(codebase_path)
        self._at = audit_max_tokens; self._st = strong_max_tokens
        self._reasoning_effort = reasoning_effort

    def analyze(self, graph, *, max_workers=8, progress_callback=None):
        pass_specs = [
            ("intra_audit", self._pass_intra),
            ("lifecycle_audit", self._pass_lifecycle),
            ("ownership_audit", self._pass_ownership),
            ("semantic_audit", self._pass_semantic),
            ("state_audit", self._pass_state_concurrency),
            ("targeted_state_order", self._pass_targeted_state_order),
            ("targeted_callback_lifecycle", self._pass_targeted_callback_lifecycle),
            ("targeted_refcount", self._pass_targeted_refcount),
            ("targeted_permission", self._pass_targeted_permission),
            ("targeted_toctou", self._pass_targeted_toctou),
            ("classic_c_sink", self._pass_classic_c_sinks),
            ("error_unwind", self._pass_error_unwind),
            ("counter_symmetry", self._pass_counter_symmetry),
            ("global_lifecycle", self._pass_global_lifecycle),
            ("lock_order_extraction", self._pass_lock_order),
            ("targeted_ordering_gap", self._pass_targeted_ordering_gap),
            ("targeted_path_access", self._pass_targeted_path_access),
        ]
        findings = []
        if not pass_specs:
            return findings
        worker_budget = max(1, int(max_workers or 1))
        pass_parallelism = max(1, min(len(pass_specs), worker_budget, 8))
        pass_workers = max(1, worker_budget // pass_parallelism)

        def _run_pass(pass_name, pass_fn):
            try:
                return pass_fn(graph, pass_workers, progress_callback)
            except KeyboardInterrupt:
                raise
            except Exception as exc:
                logger.warning("%s pass fail: %s", pass_name, exc)
                if progress_callback:
                    progress_callback({
                        "event": f"{pass_name}_error",
                        "error": f"{type(exc).__name__}: {exc}",
                    })
                return []

        if pass_parallelism == 1:
            for pass_name, pass_fn in pass_specs:
                findings.extend(_run_pass(pass_name, pass_fn))
        else:
            with ThreadPoolExecutor(max_workers=pass_parallelism) as executor:
                futures = {
                    submit_with_current_context(executor, _run_pass, pass_name, pass_fn): pass_name
                    for pass_name, pass_fn in pass_specs
                }
                for future in as_completed(futures):
                    findings.extend(future.result())
        if progress_callback:
            by_type = defaultdict(int)
            for f in findings: by_type[f.analysis_type] += 1
            progress_callback({"event": "supplementary_done", **dict(by_type), "total": len(findings)})
        return findings

    # ── intra-function pass ──

    def _pass_intra(self, graph, max_workers, cb):
        targets = self._select_intra_targets(graph)
        if not targets: return []
        groups = defaultdict(list)
        for t in targets: groups[t.file_path].append(t)
        if cb: cb({"event": "intra_audit_start", "files": len(groups), "functions": len(targets)})
        results = []
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futs = {submit_with_current_context(ex, self._audit_file, fp, fns): fp for fp, fns in groups.items()}
            done = 0
            for fut in as_completed(futs):
                fp = futs[fut]; done += 1
                try: results.extend(fut.result())
                except Exception as e: logger.warning("Intra audit fail %s: %s", fp, e)
                if cb: cb({"event": "intra_audit_progress", "completed": done, "total": len(groups), "file": fp})
        return results

    def _select_intra_targets(self, graph):
        all_kw = _RESOURCE_KW | _AUTH_KW | _HW_STATE_KW | _LIFECYCLE_KW
        seen, targets = set(), []
        for n in graph.nodes.values():
            nl = n.name.lower(); cl = [c.lower() for c in n.calls]; ac = nl + " " + " ".join(cl)
            if (n.is_sink or n.is_source
                    or any(k in ac for k in all_kw)
                    or "goto" in ac):
                if n.unique_name not in seen: seen.add(n.unique_name); targets.append(n)
        # if we missed any functions (small codebase), include everything
        if len(targets) < len(graph.nodes) * 0.3:
            for n in graph.nodes.values():
                if n.unique_name not in seen:
                    seen.add(n.unique_name); targets.append(n)
        return targets

    def _audit_file(self, file_path, functions):
        bodies = []
        for fn in functions:
            b = _read_function_body(self._cb, fn, 4096)
            if b: bodies.append(f"--- {fn.unique_name} (line {fn.line_number}) ---\n{b}")
        if not bodies: return []
        kw = _chat_model_kwargs(self._u, reasoning_effort=getattr(self, "_reasoning_effort", None))
        chat = self._p.get_chat_model(model=self._am, max_tokens=self._at, temperature=0.1, **kw)
        prompt = ChatPromptTemplate.from_messages([("system", _INTRA_SYS), ("user", _INTRA_USR)])
        raw = (prompt | chat | StrOutputParser()).invoke({"file_path": file_path, "functions_code": "\n\n".join(bodies)}).strip()
        return self._parse_intra(raw, functions)

    def _parse_intra(self, raw, functions, analysis_type="intra_function"):
        parsed = parse_json_output(raw)
        if not isinstance(parsed, dict): return []
        fl = parsed.get("findings")
        if not isinstance(fl, list): return []
        lk = {fn.name: fn for fn in functions}; bu = {f.unique_name: f for f in functions}
        results = []
        for e in fl:
            if not isinstance(e, dict): continue
            fn = _lookup_fn(str(e.get("function_name") or ""), lk, bu, functions)
            if not fn: fn = functions[0]
            line = fn.line_number
            try: line = max(1, int(e.get("line", line)))
            except: pass
            primary_file, primary_function, primary_line, canonical_key = _canonical_fields(
                e, default_file=fn.file_path, default_function=fn.unique_name, default_line=line)
            results.append(VulnerabilityFinding(
                id=uuid.uuid4().hex[:16],
                vulnerability_type=_normalise_vuln_type(e.get("vulnerability_type") or "other"),
                severity=str(e.get("severity") or "medium"), confidence=str(e.get("confidence") or "medium"),
                source_function=fn.unique_name, source_file=fn.file_path, source_line=line,
                sink_function=fn.unique_name, sink_file=fn.file_path, sink_line=line,
                path=[fn.unique_name], description=str(e.get("description") or ""),
                root_cause=str(e.get("root_cause") or ""), evidence=str(e.get("evidence") or ""),
                analysis_type=analysis_type, primary_file=primary_file,
                primary_function=primary_function, primary_line=primary_line,
                canonical_key=canonical_key))
        return results

    # ── cross-function passes (lifecycle, ownership, semantic, state) ──
    # All use chunking to avoid blowing context windows.

    def _run_chunked_cross_pass(self, graph, sys_prompt, usr_template, usr_key,
                                 analysis_type, key_a, key_b, model, max_tokens,
                                 max_workers, cb, event_prefix, include_globals=False):
        fns = list(graph.nodes.values())
        if not fns: return []
        if cb: cb({"event": f"{event_prefix}_start", "functions": len(fns)})
        chunks = _build_file_grouped_chunks(self._cb, fns, max_total_chars=60000, per_fn_chars=3000)
        if not chunks: return []
        globals_code = _build_globals_code(graph) if include_globals else ""
        if globals_code:
            chunks = [f"== GLOBAL CONSTRUCTS ==\n{globals_code}\n\n{chunk}" for chunk in chunks]
        results = []

        def _run_chunk(code_chunk):
            kw = _chat_model_kwargs(self._u, reasoning_effort=getattr(self, "_reasoning_effort", None))
            chat = self._p.get_chat_model(model=model, max_tokens=max_tokens, temperature=0.1, **kw)
            prompt = ChatPromptTemplate.from_messages([("system", sys_prompt), ("user", usr_template)])
            raw = (prompt | chat | StrOutputParser()).invoke({usr_key: code_chunk}).strip()
            return raw

        if len(chunks) == 1:
            raw = _run_chunk(chunks[0])
            results = self._parse_cross(raw, fns, analysis_type, key_a, key_b)
        else:
            with ThreadPoolExecutor(max_workers=min(max_workers, len(chunks))) as ex:
                futs = {submit_with_current_context(ex, _run_chunk, chunk): i for i, chunk in enumerate(chunks)}
                for fut in as_completed(futs):
                    try:
                        raw = fut.result()
                        results.extend(self._parse_cross(raw, fns, analysis_type, key_a, key_b))
                    except Exception as e:
                        logger.warning("%s chunk fail: %s", event_prefix, e)

        if cb: cb({"event": f"{event_prefix}_done", "findings": len(results)})
        return results

    def _run_chunked_semantic_pass(self, graph, max_workers, cb):
        fns = list(graph.nodes.values())
        if not fns: return []
        if cb: cb({"event": "semantic_audit_start", "functions": len(fns)})
        chunks = _build_file_grouped_chunks(self._cb, fns, max_total_chars=60000, per_fn_chars=3000)
        if not chunks: return []
        globals_code = _build_globals_code(graph)
        if globals_code:
            chunks = [f"== GLOBAL CONSTRUCTS ==\n{globals_code}\n\n{chunk}" for chunk in chunks]
        results = []

        def _run_chunk(code_chunk):
            kw = _chat_model_kwargs(self._u, reasoning_effort=getattr(self, "_reasoning_effort", None))
            chat = self._p.get_chat_model(model=self._sm, max_tokens=self._st, temperature=0.1, **kw)
            prompt = ChatPromptTemplate.from_messages([("system", _SEM_SYS), ("user", _SEM_USR)])
            return (prompt | chat | StrOutputParser()).invoke({"all_functions_code": code_chunk}).strip()

        if len(chunks) == 1:
            raw = _run_chunk(chunks[0])
            results = self._parse_semantic(raw, fns)
        else:
            with ThreadPoolExecutor(max_workers=min(max_workers, len(chunks))) as ex:
                futs = {submit_with_current_context(ex, _run_chunk, chunk): i for i, chunk in enumerate(chunks)}
                for fut in as_completed(futs):
                    try:
                        raw = fut.result()
                        results.extend(self._parse_semantic(raw, fns))
                    except Exception as e:
                        logger.warning("Semantic chunk fail: %s", e)

        if cb: cb({"event": "semantic_audit_done", "findings": len(results)})
        return results

    def _pass_lifecycle(self, graph, max_workers, cb):
        return self._run_chunked_cross_pass(
            graph, _LIFE_SYS, _LIFE_USR, "all_functions_code",
            "lifecycle", "free_function", "use_function",
            self._sm, self._st, max_workers, cb, "lifecycle_audit")

    def _pass_ownership(self, graph, max_workers, cb):
        return self._run_chunked_cross_pass(
            graph, _OWN_SYS, _OWN_USR, "all_functions_code",
            "ownership", "function_a", "function_b",
            self._sm, self._st, max_workers, cb, "ownership_audit",
            include_globals=True)

    def _pass_semantic(self, graph, max_workers, cb):
        return self._run_chunked_semantic_pass(graph, max_workers, cb)

    def _pass_state_concurrency(self, graph, max_workers, cb):
        """New pass: state ordering, lock discipline, teardown races."""
        fns = list(graph.nodes.values())
        if not fns: return []
        if cb: cb({"event": "state_audit_start", "functions": len(fns)})
        chunks = _build_file_grouped_chunks(self._cb, fns, max_total_chars=60000, per_fn_chars=3000)
        if not chunks: return []
        globals_code = _build_globals_code(graph)
        if globals_code:
            chunks = [f"== GLOBAL CONSTRUCTS ==\n{globals_code}\n\n{chunk}" for chunk in chunks]
        results = []

        def _run_chunk(code_chunk):
            kw = _chat_model_kwargs(self._u, reasoning_effort=getattr(self, "_reasoning_effort", None))
            chat = self._p.get_chat_model(model=self._sm, max_tokens=self._st, temperature=0.1, **kw)
            prompt = ChatPromptTemplate.from_messages([("system", _STATE_SYS), ("user", _STATE_USR)])
            return (prompt | chat | StrOutputParser()).invoke({"all_functions_code": code_chunk}).strip()

        if len(chunks) == 1:
            raw = _run_chunk(chunks[0])
            results = self._parse_semantic(raw, fns, analysis_type="state_concurrency")
        else:
            with ThreadPoolExecutor(max_workers=min(max_workers, len(chunks))) as ex:
                futs = {submit_with_current_context(ex, _run_chunk, chunk): i for i, chunk in enumerate(chunks)}
                for fut in as_completed(futs):
                    try:
                        raw = fut.result()
                        results.extend(self._parse_semantic(raw, fns, analysis_type="state_concurrency"))
                    except Exception as e:
                        logger.warning("State/concurrency chunk fail: %s", e)

        if cb: cb({"event": "state_audit_done", "findings": len(results)})
        return results

    def _run_targeted_pass(self, graph, sys_prompt, analysis_type, max_workers, cb, event_prefix,
                           relation_keywords=None):
        fns = list(graph.nodes.values())
        if relation_keywords:
            fns = _expand_candidates_with_related_file_functions(graph, fns, relation_keywords)
        if not fns: return []
        if cb: cb({"event": f"{event_prefix}_start", "functions": len(fns)})
        chunks = _build_file_grouped_chunks(self._cb, fns, max_total_chars=60000, per_fn_chars=3000)
        if not chunks: return []
        globals_code = _build_globals_code(graph)
        if globals_code:
            chunks = [f"== GLOBAL CONSTRUCTS ==\n{globals_code}\n\n{chunk}" for chunk in chunks]
        results = []

        def _run_chunk(code_chunk):
            kw = _chat_model_kwargs(self._u, reasoning_effort=getattr(self, "_reasoning_effort", None))
            chat = self._p.get_chat_model(model=self._sm, max_tokens=self._st, temperature=0.1, **kw)
            prompt = ChatPromptTemplate.from_messages([("system", sys_prompt), ("user", _SEM_USR)])
            return (prompt | chat | StrOutputParser()).invoke({"all_functions_code": code_chunk}).strip()

        if len(chunks) == 1:
            results = self._parse_semantic(_run_chunk(chunks[0]), fns, analysis_type=analysis_type)
        else:
            with ThreadPoolExecutor(max_workers=min(max_workers, len(chunks))) as ex:
                futs = {submit_with_current_context(ex, _run_chunk, chunk): i for i, chunk in enumerate(chunks)}
                for fut in as_completed(futs):
                    try:
                        results.extend(self._parse_semantic(fut.result(), fns, analysis_type=analysis_type))
                    except Exception as e:
                        logger.warning("%s chunk fail: %s", event_prefix, e)
        if cb: cb({"event": f"{event_prefix}_done", "findings": len(results)})
        return results

    def _run_candidate_intra_pass(self, graph, pattern, sys_prompt, analysis_type, max_workers, cb, event_prefix):
        candidates = _select_nodes_by_regex(graph, self._cb, pattern)
        if not candidates: return []
        if cb: cb({"event": f"{event_prefix}_start", "functions": len(candidates)})
        chunks = _build_file_grouped_node_chunks(self._cb, candidates, max_total_chars=50000, per_fn_chars=5000)
        if not chunks: return []
        results = []

        def _run_chunk(chunk_nodes, code_chunk):
            kw = _chat_model_kwargs(self._u, reasoning_effort=getattr(self, "_reasoning_effort", None))
            chat = self._p.get_chat_model(model=self._sm, max_tokens=self._st, temperature=0.1, **kw)
            prompt = ChatPromptTemplate.from_messages([("system", sys_prompt), ("user", _INTRA_USR)])
            raw = (prompt | chat | StrOutputParser()).invoke({
                "file_path": "candidate functions",
                "functions_code": code_chunk,
            }).strip()
            return self._parse_intra(raw, chunk_nodes, analysis_type=analysis_type)

        with ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(chunks)))) as ex:
            futs = {submit_with_current_context(ex, _run_chunk, nodes, text): i for i, (nodes, text) in enumerate(chunks)}
            for fut in as_completed(futs):
                try: results.extend(fut.result())
                except Exception as e: logger.warning("%s chunk fail: %s", event_prefix, e)
        if cb: cb({"event": f"{event_prefix}_done", "findings": len(results)})
        return results

    def _run_candidate_semantic_pass(self, graph, pattern, sys_prompt, analysis_type, max_workers, cb, event_prefix,
                                     relation_keywords=None):
        candidates = _select_nodes_by_regex(graph, self._cb, pattern)
        if not candidates: return []
        if relation_keywords:
            candidates = _expand_candidates_with_related_file_functions(graph, candidates, relation_keywords)
        if cb: cb({"event": f"{event_prefix}_start", "functions": len(candidates)})
        chunks = _build_file_grouped_node_chunks(self._cb, candidates, max_total_chars=60000, per_fn_chars=4000)
        if not chunks: return []
        results = []

        def _run_chunk(chunk_nodes, code_chunk):
            kw = _chat_model_kwargs(self._u, reasoning_effort=getattr(self, "_reasoning_effort", None))
            chat = self._p.get_chat_model(model=self._sm, max_tokens=self._st, temperature=0.1, **kw)
            prompt = ChatPromptTemplate.from_messages([("system", sys_prompt), ("user", _SEM_USR)])
            raw = (prompt | chat | StrOutputParser()).invoke({"all_functions_code": code_chunk}).strip()
            return self._parse_semantic(raw, chunk_nodes, analysis_type=analysis_type)

        with ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(chunks)))) as ex:
            futs = {submit_with_current_context(ex, _run_chunk, nodes, text): i for i, (nodes, text) in enumerate(chunks)}
            for fut in as_completed(futs):
                try: results.extend(fut.result())
                except Exception as e: logger.warning("%s chunk fail: %s", event_prefix, e)
        if cb: cb({"event": f"{event_prefix}_done", "findings": len(results)})
        return results

    def _pass_classic_c_sinks(self, graph, max_workers, cb):
        return self._run_candidate_intra_pass(
            graph, _CLASSIC_C_SINK_RE, _CLASSIC_C_SINK_SYS,
            "classic_c_sink", max_workers, cb, "classic_c_sink")

    def _pass_error_unwind(self, graph, max_workers, cb):
        return self._run_candidate_semantic_pass(
            graph, _ERROR_UNWIND_RE, _ERROR_UNWIND_SYS,
            "error_unwind", max_workers, cb, "error_unwind",
            relation_keywords=_RELATED_FILE_FUNCTION_KEYWORDS)

    def _pass_counter_symmetry(self, graph, max_workers, cb):
        return self._run_candidate_semantic_pass(
            graph, _COUNTER_RE, _COUNTER_SYMMETRY_SYS,
            "counter_symmetry", max_workers, cb, "counter_symmetry",
            relation_keywords=_RELATED_FILE_FUNCTION_KEYWORDS)

    def _pass_targeted_ordering_gap(self, graph, max_workers, cb):
        return self._run_candidate_semantic_pass(
            graph, _ORDERING_GAP_RE, _TARGET_ORDERING_GAP_SYS,
            "targeted_ordering_gap", max_workers, cb, "targeted_ordering_gap",
            relation_keywords=_RELATED_FILE_FUNCTION_KEYWORDS)

    def _pass_targeted_path_access(self, graph, max_workers, cb):
        return self._run_candidate_semantic_pass(
            graph, _PATH_ACCESS_RE, _TARGET_PATH_ACCESS_SYS,
            "targeted_path_access", max_workers, cb, "targeted_path_access")

    def _pass_global_lifecycle(self, graph, max_workers, cb):
        globals_ = graph.get_globals()
        if not globals_: return []
        nodes_by_unique = {}
        for g in globals_:
            prefix = re.split(r"[_\W]+", g.name.lower())[0] if g.name else ""
            for ref in g.referenced_functions:
                for unique_name in graph.name_index.get(ref, []):
                    node = graph.get_node(unique_name)
                    if node: nodes_by_unique[node.unique_name] = node
            for node in graph.get_file_nodes(g.file_path):
                name_l = node.name.lower()
                if _GLOBAL_LIFECYCLE_NAME_RE.search(name_l) or (prefix and name_l.startswith(prefix)):
                    nodes_by_unique[node.unique_name] = node
        nodes = _expand_candidates_with_related_file_functions(
            graph, list(nodes_by_unique.values()), _RELATED_FILE_FUNCTION_KEYWORDS)
        nodes = sorted(nodes, key=lambda n: (n.file_path, n.line_number, n.name))
        if not nodes: return []
        if cb: cb({"event": "global_lifecycle_start", "globals": len(globals_), "functions": len(nodes)})
        chunks = _build_file_grouped_node_chunks(self._cb, nodes, max_total_chars=50000, per_fn_chars=4000)
        globals_code = _build_globals_code(graph, max_chars=30000)
        results = []

        def _run_chunk(chunk_nodes, code_chunk):
            code = f"== GLOBAL CONSTRUCTS ==\n{globals_code}\n\n{code_chunk}"
            kw = _chat_model_kwargs(self._u, reasoning_effort=getattr(self, "_reasoning_effort", None))
            chat = self._p.get_chat_model(model=self._sm, max_tokens=self._st, temperature=0.1, **kw)
            prompt = ChatPromptTemplate.from_messages([("system", _GLOBAL_LIFECYCLE_SYS), ("user", _SEM_USR)])
            raw = (prompt | chat | StrOutputParser()).invoke({"all_functions_code": code}).strip()
            return self._parse_semantic(raw, chunk_nodes, analysis_type="global_lifecycle")

        with ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(chunks)))) as ex:
            futs = {submit_with_current_context(ex, _run_chunk, chunk_nodes, text): i
                    for i, (chunk_nodes, text) in enumerate(chunks)}
            for fut in as_completed(futs):
                try: results.extend(fut.result())
                except Exception as e: logger.warning("Global lifecycle chunk fail: %s", e)
        if cb: cb({"event": "global_lifecycle_done", "findings": len(results)})
        return results

    def _normalise_lock_expr(self, expr):
        expr = re.sub(r"/\*.*?\*/", "", str(expr or ""))
        expr = re.sub(r"\s+", "", expr).strip("&()")
        expr = re.sub(r"^\([^)]*\)", "", expr)
        expr = expr.replace("->", ".").strip("&()")
        if not expr:
            return ""
        if "hwaccess_lock" in expr:
            return "hwaccess_lock"
        if "scheduler_lock" in expr:
            return "scheduler_lock"
        if ".ctx.lock" in expr or expr.endswith("ctx.lock"):
            return "ctx.lock"
        if ".queue.lock" in expr or expr.endswith("queue.lock"):
            return "queue.lock"
        if ".pm.lock" in expr or expr.endswith("pm.lock"):
            return "pm.lock"
        if ".mmu.lock" in expr or expr.endswith("mmu.lock"):
            return "mmu.lock"
        if expr.endswith(".lock"):
            return ".".join(expr.split(".")[-2:])
        return expr

    def _extract_lock_conflicts(self, graph):
        edges = defaultdict(list)
        for node in sorted(graph.nodes.values(), key=lambda n: (n.file_path, n.line_number, n.name)):
            body = _read_function_body(self._cb, node, 8000)
            if not body: continue
            held = []
            for match in _LOCK_EVENT_RE.finditer(body):
                lock = self._normalise_lock_expr(match.group("arg"))
                if not lock: continue
                line = node.line_number + body[:match.start()].count("\n")
                fn_name = match.group("fn").lower()
                if "unlock" in fn_name:
                    if lock in held:
                        held.remove(lock)
                    continue
                for prior in held:
                    if prior != lock:
                        edges[(prior, lock)].append((node, line))
                if lock not in held:
                    held.append(lock)

        conflicts, seen = [], set()
        for (a, b), first_edges in edges.items():
            reverse_edges = edges.get((b, a))
            if not reverse_edges:
                continue
            for node_a, line_a in first_edges:
                for node_b, line_b in reverse_edges:
                    if node_a.unique_name == node_b.unique_name:
                        continue
                    key = tuple(sorted((node_a.unique_name, node_b.unique_name)) + sorted((a, b)))
                    if key in seen:
                        continue
                    seen.add(key)
                    conflicts.append((a, b, node_a, line_a, node_b, line_b))
                    if len(conflicts) >= 40:
                        return conflicts
        return conflicts

    def _pass_lock_order(self, graph, max_workers, cb):
        conflicts = self._extract_lock_conflicts(graph)
        if not conflicts: return []
        if cb: cb({"event": "lock_order_extraction_start", "conflicts": len(conflicts)})
        results = []
        for batch in _chunked(conflicts, 8):
            nodes = []
            seen = set()
            lines = ["== LOCK ORDER CANDIDATES =="]
            for i, (a, b, node_a, line_a, node_b, line_b) in enumerate(batch):
                lines.append(
                    f"Conflict {i}: {a} -> {b} in {node_a.unique_name} line {line_a}; "
                    f"{b} -> {a} in {node_b.unique_name} line {line_b}"
                )
                for node in (node_a, node_b):
                    if node.unique_name not in seen:
                        seen.add(node.unique_name)
                        nodes.append(node)
            body_chunks = _build_file_grouped_chunks(self._cb, nodes, max_total_chars=50000, per_fn_chars=5000)
            code = "\n".join(lines) + "\n\n== RELEVANT FUNCTION BODIES ==\n" + "\n\n".join(body_chunks)
            kw = _chat_model_kwargs(self._u, reasoning_effort=getattr(self, "_reasoning_effort", None))
            chat = self._p.get_chat_model(model=self._sm, max_tokens=self._st, temperature=0.1, **kw)
            prompt = ChatPromptTemplate.from_messages([("system", _LOCK_ORDER_SYS), ("user", _SEM_USR)])
            raw = (prompt | chat | StrOutputParser()).invoke({"all_functions_code": code}).strip()
            results.extend(self._parse_semantic(raw, nodes, analysis_type="lock_order_extraction"))
        if cb: cb({"event": "lock_order_extraction_done", "findings": len(results)})
        return results

    def _pass_targeted_state_order(self, graph, max_workers, cb):
        return self._run_targeted_pass(
            graph, _TARGET_STATE_SYS, "targeted_state_order", max_workers, cb,
            "targeted_state_order")

    def _pass_targeted_callback_lifecycle(self, graph, max_workers, cb):
        return self._run_targeted_pass(
            graph, _TARGET_CALLBACK_SYS, "targeted_callback_lifecycle", max_workers, cb,
            "targeted_callback_lifecycle", relation_keywords=_RELATED_FILE_FUNCTION_KEYWORDS)

    def _pass_targeted_refcount(self, graph, max_workers, cb):
        return self._run_targeted_pass(
            graph, _TARGET_REFCOUNT_SYS, "targeted_refcount", max_workers, cb,
            "targeted_refcount")

    def _pass_targeted_permission(self, graph, max_workers, cb):
        return self._run_targeted_pass(
            graph, _TARGET_PERMISSION_SYS, "targeted_permission", max_workers, cb,
            "targeted_permission")

    def _pass_targeted_toctou(self, graph, max_workers, cb):
        return self._run_targeted_pass(
            graph, _TARGET_TOCTOU_SYS, "targeted_toctou", max_workers, cb,
            "targeted_toctou")

    def _parse_cross(self, raw, all_fns, analysis_type, key_a, key_b):
        parsed = parse_json_output(raw)
        if not isinstance(parsed, dict): return []
        fl = parsed.get("findings")
        if not isinstance(fl, list): return []
        bn = {fn.name: fn for fn in all_fns}; bu = {fn.unique_name: fn for fn in all_fns}
        results = []
        for e in fl:
            if not isinstance(e, dict): continue
            fa = _lookup_fn(str(e.get(key_a) or ""), bn, bu, all_fns)
            fb = _lookup_fn(str(e.get(key_b) or ""), bn, bu, all_fns)
            if not fa or not fb: continue
            primary_file, primary_function, primary_line, canonical_key = _canonical_fields(
                e, default_file=fb.file_path, default_function=fb.unique_name, default_line=fb.line_number)
            results.append(VulnerabilityFinding(
                id=uuid.uuid4().hex[:16],
                vulnerability_type=_normalise_vuln_type(e.get("vulnerability_type") or "use_after_free"),
                severity=str(e.get("severity") or "high"), confidence=str(e.get("confidence") or "medium"),
                source_function=fa.unique_name, source_file=fa.file_path, source_line=fa.line_number,
                sink_function=fb.unique_name, sink_file=fb.file_path, sink_line=fb.line_number,
                path=[fa.unique_name, fb.unique_name], description=str(e.get("description") or ""),
                root_cause=str(e.get("root_cause") or ""), evidence=str(e.get("evidence") or ""),
                analysis_type=analysis_type, primary_file=primary_file,
                primary_function=primary_function, primary_line=primary_line,
                canonical_key=canonical_key))
        return results

    def _parse_semantic(self, raw, all_fns, analysis_type="semantic"):
        parsed = parse_json_output(raw)
        if not isinstance(parsed, dict): return []
        fl = parsed.get("findings")
        if not isinstance(fl, list): return []
        bn = {fn.name: fn for fn in all_fns}; bu = {fn.unique_name: fn for fn in all_fns}
        results = []
        for e in fl:
            if not isinstance(e, dict): continue
            fn = _lookup_fn(str(e.get("function_name") or ""), bn, bu, all_fns)
            rf = _lookup_fn(str(e.get("related_function") or ""), bn, bu, all_fns)
            if not fn: continue
            src_fn = rf or fn
            primary_file, primary_function, primary_line, canonical_key = _canonical_fields(
                e, default_file=fn.file_path, default_function=fn.unique_name, default_line=fn.line_number)
            results.append(VulnerabilityFinding(
                id=uuid.uuid4().hex[:16],
                vulnerability_type=_normalise_vuln_type(e.get("vulnerability_type") or "other"),
                severity=str(e.get("severity") or "medium"), confidence=str(e.get("confidence") or "medium"),
                source_function=src_fn.unique_name, source_file=src_fn.file_path, source_line=src_fn.line_number,
                sink_function=fn.unique_name, sink_file=fn.file_path, sink_line=fn.line_number,
                path=[src_fn.unique_name, fn.unique_name] if rf else [fn.unique_name],
                description=str(e.get("description") or ""), root_cause=str(e.get("root_cause") or ""),
                evidence=str(e.get("evidence") or ""), analysis_type=analysis_type,
                primary_file=primary_file, primary_function=primary_function,
                primary_line=primary_line, canonical_key=canonical_key))
        return results


# ── deduplicator ─────────────────────────────────────────────────────────────

def _finding_signature(f):
    """
    Produce a canonical key that identifies the root cause, not the path.
    Canonical keys are intentionally not privileged here because independent
    passes often invent different keys for the same defect.
    """
    family = _dedupe_family(f)
    file = _finding_file(f)
    fn = _finding_function(f)
    line = _finding_line(f)
    line_bucket = line // 10

    return (file, fn, family, line_bucket)


_DEDUP_NOISY_CANONICAL_TOKENS = frozenset({
    "unchecked", "direct", "same_path", "same", "input",
    "user", "attacker", "unsanitized", "unsanitised",
})
_DEDUP_STOPWORDS = frozenset({
    "a", "an", "and", "are", "as", "at", "be", "but", "by", "can",
    "code", "does", "for", "from", "has", "have", "in", "into", "is",
    "it", "its", "may", "not", "of", "on", "or", "report",
    "same", "that", "the", "this", "to", "when", "where", "with",
    "without", "would",
})
_DEDUP_TOKEN_ALIASES = {
    "uncancelled": "uncanceled",
    "uncancelling": "uncanceled",
    "cancelled": "cancel",
    "canceled": "cancel",
    "cancelling": "cancel",
    "deactivation": "deactivate",
    "deactivated": "deactivate",
    "deactivates": "deactivate",
    "pathname": "path",
    "paths": "path",
    "fopen": "open",
    "opened": "open",
    "opening": "open",
    "leaks": "leak",
    "leaking": "leak",
    "pages": "page",
    "mappings": "mapping",
    "callbacks": "callback",
    "timers": "timer",
    "workers": "worker",
    "files": "file",
    "operations": "operation",
    "permissions": "permission",
    "freed": "free",
    "freeing": "free",
    "unsanitised": "unsanitized",
}
_CALLBACK_TEARDOWN_TYPES = frozenset({
    "teardown_race", "callback_uaf", "deferred_uaf",
    "cleanup_symmetry", "file_ops_lifecycle_gap",
})
_AUTH_DEDUP_TYPES = frozenset({
    "missing_auth",
    "permission_mismatch",
    "wrong_constant",
    "auth_comparison_logic_error",
    "boolean_coercion",
})
_CALLBACK_OBJECT_TOKENS = frozenset({
    "callback", "cb", "work", "worker", "workqueue", "timer", "watchdog",
    "flush", "cancel", "release", "reset", "poll", "ioctl", "file", "fops",
})
_PRIVILEGED_OP_TOKENS = frozenset({
    "reset", "firmware", "fw", "debug", "mmio", "dma", "register",
    "channel", "delete", "destroy", "load", "write", "cpu", "gpu",
    "project", "proj", "task", "create", "update", "resource", "res",
    "permission", "domain", "level", "role", "boolean",
})


def _dedupe_family(f):
    vtype = _normalise_vuln_type(getattr(f, "vulnerability_type", ""))
    return _VTYPE_FAMILY.get(vtype, vtype)


def _normalise_dedupe_token(token):
    token = _DEDUP_TOKEN_ALIASES.get(token, token)
    if token in _DEDUP_TOKEN_ALIASES:
        return _DEDUP_TOKEN_ALIASES[token]
    if len(token) > 5:
        for suffix in ("ingly", "edly", "ation", "ing", "ed"):
            if token.endswith(suffix) and len(token) - len(suffix) >= 4:
                return token[:-len(suffix)]
    return token


def _normalise_dedupe_tokens(text, *, drop_noisy=False):
    tokens = []
    for raw in re.split(r"[^a-z0-9]+", str(text or "").lower()):
        if not raw or raw in _DEDUP_STOPWORDS:
            continue
        if drop_noisy and raw in _DEDUP_NOISY_CANONICAL_TOKENS:
            continue
        token = _normalise_dedupe_token(raw)
        if not token or token in _DEDUP_STOPWORDS:
            continue
        if drop_noisy and token in _DEDUP_NOISY_CANONICAL_TOKENS:
            continue
        if len(token) < 2:
            continue
        tokens.append(token)
    return tokens


def _normalise_canonical_key(key):
    tokens = _normalise_dedupe_tokens(key, drop_noisy=True)
    return "_".join(tokens)


def _root_tokens(f):
    text = " ".join(str(part or "") for part in (
        getattr(f, "root_cause", ""),
        getattr(f, "evidence", ""),
        getattr(f, "description", ""),
    ))
    return set(_normalise_dedupe_tokens(text))


def _root_cause_token_signature(f):
    tokens = sorted(_root_tokens(f))
    if not tokens:
        return None
    return (_finding_file(f), _finding_function(f), _dedupe_family(f), tuple(tokens[:14]))


def _token_overlap_score(tokens_a, tokens_b):
    if not tokens_a or not tokens_b:
        return 0.0
    overlap = len(tokens_a & tokens_b)
    shorter = min(len(tokens_a), len(tokens_b))
    return overlap / shorter if shorter else 0.0


def _description_overlap(a: str, b: str, threshold=0.6) -> bool:
    """Normalized word-overlap check for duplicate root-cause prose."""
    wa = set(_normalise_dedupe_tokens(a))
    wb = set(_normalise_dedupe_tokens(b))
    if not wa or not wb:
        return False
    return _token_overlap_score(wa, wb) >= threshold


def _finding_info(f):
    vtype = _normalise_vuln_type(getattr(f, "vulnerability_type", ""))
    return {
        "finding": f,
        "vtype": vtype,
        "family": _VTYPE_FAMILY.get(vtype, vtype),
        "file": _finding_file(f),
        "fn": _finding_function(f),
        "line": _finding_line(f),
        "sink_file": getattr(f, "sink_file", "") or "",
        "sink_line": _safe_int(getattr(f, "sink_line", 0), 0),
        "canon": _normalise_canonical_key(getattr(f, "canonical_key", "")),
        "tokens": _root_tokens(f),
        "text": _finding_text(f),
    }


def _compatible_dedupe_family(a, b):
    types = {a["vtype"], b["vtype"]}
    if types <= _AUTH_DEDUP_TYPES:
        if a["fn"] != b["fn"]:
            return False
        shared = (a["tokens"] & b["tokens"]) & _PRIVILEGED_OP_TOKENS
        return bool(shared) or (a["line"] and b["line"] and abs(a["line"] - b["line"]) <= 5)
    if a["family"] == b["family"]:
        return True
    if types <= _CALLBACK_TEARDOWN_TYPES:
        shared = (a["tokens"] & b["tokens"]) & _CALLBACK_OBJECT_TOKENS
        return bool(shared)
    return False


def _same_root_cause(a, b):
    if not _compatible_dedupe_family(a, b):
        return False

    if a["canon"] and a["canon"] == b["canon"]:
        return True

    if a["sink_line"] and a["sink_line"] == b["sink_line"] and a["sink_file"] == b["sink_file"]:
        return True

    same_primary = a["file"] == b["file"] and a["fn"] == b["fn"]
    if not same_primary:
        return False

    if a["line"] and b["line"] and abs(a["line"] - b["line"]) <= 10:
        return True

    if _description_overlap(a["text"], b["text"], threshold=0.58):
        return True

    if _token_overlap_score(a["tokens"], b["tokens"]) >= 0.62 and len(a["tokens"] & b["tokens"]) >= 4:
        return True

    types = {a["vtype"], b["vtype"]}
    if types <= _CALLBACK_TEARDOWN_TYPES:
        shared = (a["tokens"] & b["tokens"]) & _CALLBACK_OBJECT_TOKENS
        if shared and (not a["line"] or not b["line"] or abs(a["line"] - b["line"]) <= 25):
            return True

    return False


def _collapse_by_root_cause(findings):
    if len(findings) <= 1:
        return list(findings)

    infos = [_finding_info(f) for f in findings]
    parent = list(range(len(infos)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(i, j):
        ri, rj = find(i), find(j)
        if ri != rj:
            parent[rj] = ri

    pair_candidates = set()

    def add_pairs(indices):
        indices = list(indices)
        for i in range(len(indices)):
            for j in range(i + 1, len(indices)):
                pair_candidates.add((indices[i], indices[j]))

    by_location = defaultdict(list)
    by_canon = defaultdict(list)
    by_sink = defaultdict(list)
    by_root_sig = defaultdict(list)
    for idx, info in enumerate(infos):
        by_location[(info["file"], info["fn"])].append(idx)
        if info["canon"]:
            by_canon[info["canon"]].append(idx)
        if info["sink_line"]:
            by_sink[(info["sink_file"], info["sink_line"], info["family"])].append(idx)
        root_sig = _root_cause_token_signature(info["finding"])
        if root_sig:
            by_root_sig[root_sig].append(idx)

    for group in by_location.values():
        add_pairs(group)
    for group in by_canon.values():
        add_pairs(group)
    for group in by_sink.values():
        add_pairs(group)
    for group in by_root_sig.values():
        add_pairs(group)

    for i, j in pair_candidates:
        if _same_root_cause(infos[i], infos[j]):
            union(i, j)

    groups = defaultdict(list)
    for idx, info in enumerate(infos):
        groups[find(idx)].append(info["finding"])

    return [_pick_best(group) for group in groups.values()]


class Deduplicator:
    @staticmethod
    def deduplicate(findings, *, max_per_sink=3):
        """
        Two-stage deduplication:
        1. Group by logical root-cause signature.
           Within each group keep only the best (highest severity, shortest path).
        2. Across remaining findings, cap per (primary_function, vuln family) at max_per_sink.
        """
        if not findings: return [], 0, 0

        # Stage 1: collapse duplicate reports of the same root cause.
        stage1 = _collapse_by_root_cause(list(findings))

        # Stage 1b: catch any remaining prose-level duplicates within a location/family bucket.
        stage1b = _collapse_by_description(stage1)

        # Stage 2: cap per (sink_function, vuln_type)
        sink_groups = defaultdict(list)
        for f in stage1b:
            vtype = _normalise_vuln_type(f.vulnerability_type)
            family = _VTYPE_FAMILY.get(vtype, vtype)
            sink_groups[(f.primary_function or f.sink_function, family)].append(f)
        selected = []
        for g in sink_groups.values():
            selected.extend(_select_diverse(g, max_per_sink))

        return selected, len(findings), len(findings) - len(selected)


def _pick_best(findings):
    """Pick the single best representative from a group of duplicates."""
    sev = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    conf = {"high": 0, "medium": 1, "low": 2}
    return min(findings, key=lambda f: (
        sev.get(f.severity, 5),
        conf.get(f.confidence, 3),
        len(f.path),
        -len(f.description),  # prefer longer descriptions
    ))


def _collapse_by_description(findings):
    """Within same primary location and family, merge highly overlapping descriptions."""
    groups = defaultdict(list)
    for f in findings:
        vtype = _normalise_vuln_type(f.vulnerability_type)
        key = (
            f.primary_file or f.sink_file or f.source_file,
            f.primary_function or f.sink_function or f.source_function,
            _VTYPE_FAMILY.get(vtype, vtype),
            _safe_int(f.primary_line or f.sink_line or f.source_line, 0) // 10,
        )
        groups[key].append(f)

    result = []
    for key, group in groups.items():
        if len(group) <= 1:
            result.extend(group)
            continue
        # greedy clustering by description overlap
        clusters = []
        for f in group:
            merged = False
            for cluster in clusters:
                if _description_overlap(_finding_text(f), _finding_text(cluster[0]), threshold=0.55):
                    cluster.append(f)
                    merged = True
                    break
            if not merged:
                clusters.append([f])
        for cluster in clusters:
            result.append(_pick_best(cluster))
    return result


def _select_diverse(findings, limit):
    if len(findings) <= limit: return list(findings)
    sev = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    fs = sorted(findings, key=lambda f: (sev.get(f.severity, 5), len(f.path)))
    sel, cov = [], set()
    for f in fs:
        if len(sel) >= limit: break
        if not sel or len(set(f.path) - cov) > 0: sel.append(f); cov.update(f.path)
    if len(sel) < limit:
        ids = {id(f) for f in sel}
        for f in fs:
            if id(f) not in ids: sel.append(f)
            if len(sel) >= limit: break
    return sel


# ── service ──────────────────────────────────────────────────────────────────

_C_CPP_EXTS = frozenset({".c", ".h", ".cc", ".cpp", ".hpp", ".hh", ".hxx", ".cxx"})
DEFAULT_OUTPUT_DIR = "metis_reachability_results"


class ReachabilityService:
    def __init__(self, config, repository, llm_provider, usage_runtime):
        self._config = config; self._repository = repository
        self._llm_provider = llm_provider; self._usage_runtime = usage_runtime
        self._graph_cache: dict[tuple, tuple[ReachabilityGraph, list[ReachabilityPath]]] = {}
        self._supp_cache: dict[tuple, list[VulnerabilityFinding]] = {}
        self._file_review_cache: dict[tuple, dict] = {}
        self._cache_lock = threading.Lock()

    def get_c_cpp_files(self):
        return [f for f in self._repository.get_code_files() if os.path.splitext(f)[1].lower() in _C_CPP_EXTS]

    def build_graph(self, files, *, extraction_model="gpt-4.1-mini", max_workers=8, progress_callback=None):
        return GraphBuilder(self._llm_provider, extraction_model, self._usage_runtime).build(
            files, self._config.codebase_path, max_workers=max_workers, progress_callback=progress_callback)

    def build_graph_interactive(self, files, *, extraction_model="gpt-4.1-mini", progress_callback=None):
        return GraphBuilder(self._llm_provider, extraction_model, self._usage_runtime).build_interactive(
            files, self._config.codebase_path, progress_callback=progress_callback)

    def trace_paths(self, graph, *, max_path_length=25):
        return PathTracer(graph, max_path_length=max_path_length).find_all_paths()

    def run_supplementary_analysis(self, graph, *, audit_model="gpt-4.1-mini", strong_model=None, max_workers=8, progress_callback=None, reasoning_effort=None):
        sm = strong_model or self._config.llama_query_model
        return SupplementaryAnalyzer(self._llm_provider, audit_model, sm, self._usage_runtime, self._config.codebase_path,
                                     reasoning_effort=reasoning_effort,
        ).analyze(graph, max_workers=max_workers, progress_callback=progress_callback)

    def confirm_paths(self, paths, graph, *, confirmation_model=None, max_workers=8, output_path=None, progress_callback=None, reasoning_effort=None):
        cm = confirmation_model or self._config.llama_query_model
        return VulnerabilityConfirmer(self._llm_provider, cm, self._usage_runtime, self._config.codebase_path,
                                      reasoning_effort=reasoning_effort).confirm_parallel(
            paths, graph, max_workers=max_workers, output_path=output_path, progress_callback=progress_callback)

    def confirm_paths_streaming(self, paths, graph, *, confirmation_model=None, output_path=None, progress_callback=None, reasoning_effort=None):
        cm = confirmation_model or self._config.llama_query_model
        return VulnerabilityConfirmer(self._llm_provider, cm, self._usage_runtime, self._config.codebase_path,
                                      reasoning_effort=reasoning_effort).confirm_streaming(
            paths, graph, output_path=output_path, progress_callback=progress_callback)

    def confirm_paths_for_file(self, target_file, paths, graph, *, confirmation_model=None, max_workers=8, progress_callback=None, reasoning_effort=None):
        cm = confirmation_model or self._config.llama_query_model
        return VulnerabilityConfirmer(self._llm_provider, cm, self._usage_runtime, self._config.codebase_path,
                                      reasoning_effort=reasoning_effort).confirm_for_file(
            target_file, paths, graph, max_workers=max_workers, progress_callback=progress_callback)

    def confirm_cross_file_for_target(self, target_file, paths, graph, *, confirmation_model=None, max_workers=8, progress_callback=None, reasoning_effort=None):
        cm = confirmation_model or self._config.llama_query_model
        return VulnerabilityConfirmer(self._llm_provider, cm, self._usage_runtime, self._config.codebase_path,
                                      reasoning_effort=reasoning_effort).confirm_cross_file(
            target_file, paths, graph, max_workers=max_workers, progress_callback=progress_callback)

    def graph_coverage_report(self, graph):
        base_path = os.path.abspath(self._config.codebase_path)
        nodes_by_file = defaultdict(list)
        for node in graph.nodes.values():
            nodes_by_file[node.file_path].append(node)

        files = set(nodes_by_file)
        for file_path in self.get_c_cpp_files():
            abs_file = file_path if os.path.isabs(file_path) else os.path.join(base_path, file_path)
            files.add(os.path.relpath(os.path.abspath(abs_file), base_path))

        report = []
        for rel_file in sorted(files):
            nodes = sorted(nodes_by_file.get(rel_file, []), key=lambda n: (int(n.line_number or 0), n.name))
            report.append({
                "file": rel_file,
                "functions_extracted": len(nodes),
                "sources": sum(1 for n in nodes if n.is_source),
                "sinks": sum(1 for n in nodes if n.is_sink),
                "function_names": [n.name for n in nodes],
            })
        return report

    def write_graph_coverage_report(self, graph, output_path):
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", encoding="utf-8") as fh:
            json.dump(self.graph_coverage_report(graph), fh, ensure_ascii=False, indent=2)

    def _graph_cache_key(self, *, extraction_model, max_workers, max_paths, max_path_length):
        return (str(extraction_model or ""), int(max_workers), int(max_paths), int(max_path_length))

    def _supp_cache_key(self, *, extraction_model, confirmation_model, max_workers, max_paths, max_path_length, reasoning_effort=None):
        return (str(extraction_model or ""), str(confirmation_model or self._config.llama_query_model or ""),
                int(max_workers), int(max_paths), int(max_path_length), str(reasoning_effort or ""))

    def _file_review_cache_key(self, *, target_file, extraction_model, confirmation_model, max_workers, max_paths, max_paths_per_sink, max_path_length, reasoning_effort=None):
        return (str(target_file), str(extraction_model or ""), str(confirmation_model or self._config.llama_query_model or ""),
                int(max_workers), int(max_paths), int(max_paths_per_sink), int(max_path_length), str(reasoning_effort or ""))


    def _ensure_graph_and_paths(self, *, extraction_model="gpt-4.1-mini", max_workers=8, max_paths=0, max_path_length=25, progress_callback=None):
        key = self._graph_cache_key(extraction_model=extraction_model, max_workers=max_workers, max_paths=max_paths, max_path_length=max_path_length)
        with self._cache_lock:
            cached = self._graph_cache.get(key)
        if cached is not None: return cached
        files = self.get_c_cpp_files()
        if not files:
            result = (ReachabilityGraph(), [])
        else:
            graph = self.build_graph(files, extraction_model=extraction_model, max_workers=max_workers, progress_callback=progress_callback)
            if graph.node_count() == 0:
                result = (graph, [])
            else:
                paths = self.trace_paths(graph, max_path_length=max_path_length)
                if max_paths > 0: paths = paths[:max_paths]
                paths = _dedupe_paths(paths)
                result = (graph, paths)
        with self._cache_lock: self._graph_cache[key] = result
        return result


    def _ensure_supplementary(self, graph, *, extraction_model="gpt-4.1-mini", confirmation_model=None,
                              max_workers=8, max_paths=0, max_path_length=25, progress_callback=None,
                              reasoning_effort=None):
        key = self._supp_cache_key(extraction_model=extraction_model, confirmation_model=confirmation_model,
                                   max_workers=max_workers, max_paths=max_paths, max_path_length=max_path_length,
                                   reasoning_effort=reasoning_effort)
        with self._cache_lock:
            cached = self._supp_cache.get(key)
        if cached is not None: return cached
        semantic_model = confirmation_model or self._config.llama_query_model
        findings = self.run_supplementary_analysis(
            graph, audit_model=semantic_model, strong_model=semantic_model,
            max_workers=max_workers, progress_callback=progress_callback,
            reasoning_effort=reasoning_effort)
        with self._cache_lock: self._supp_cache[key] = findings
        return findings


    def _normalize_target_file(self, file_path):
        base_path = os.path.abspath(self._config.codebase_path)
        abs_target = file_path if os.path.isabs(file_path) else os.path.join(base_path, file_path)
        abs_target = os.path.abspath(abs_target)
        return abs_target, os.path.relpath(abs_target, base_path)

    def _paths_touching_file(self, graph, paths, target_file):
        """All paths where any node on the path is in the target file."""
        results = []
        for p in paths:
            for node_name in p.path:
                node = graph.get_node(node_name)
                if node and node.file_path == target_file:
                    results.append(p); break
        return _dedupe_paths(results)

    def _split_paths_for_file(self, graph, paths, target_file):
        """Split paths into inbound (sink in target) and cross-file (target is intermediate, sink elsewhere)."""
        inbound, cross_file = [], []
        for p in paths:
            sink = graph.get_node(p.sink)
            has_target_node = False
            for node_name in p.path:
                node = graph.get_node(node_name)
                if node and node.file_path == target_file:
                    has_target_node = True; break
            if not has_target_node:
                continue
            if sink and sink.file_path == target_file:
                inbound.append(p)
            else:
                cross_file.append(p)
        return _dedupe_paths(inbound), _dedupe_paths(cross_file)

    def _supp_findings_for_file(self, supp_findings, target_file):
        return [f for f in supp_findings
                if f.primary_file == target_file or f.sink_file == target_file or f.source_file == target_file]


    def review_codebase(self, *, extraction_model="gpt-4.1-mini", confirmation_model=None,
                        max_workers=8, max_paths=0, max_paths_per_sink=3, max_path_length=25,
                        progress_callback=None, reasoning_effort=None):
        graph, paths = self._ensure_graph_and_paths(
            extraction_model=extraction_model, max_workers=max_workers,
            max_paths=max_paths, max_path_length=max_path_length, progress_callback=progress_callback)
        if graph.node_count() == 0: return []

        supp_findings = self._ensure_supplementary(
            graph, extraction_model=extraction_model, confirmation_model=confirmation_model,
            max_workers=max_workers, max_paths=max_paths, max_path_length=max_path_length,
            progress_callback=progress_callback, reasoning_effort=reasoning_effort)

        files_with_paths = set()
        for p in paths:
            for node_name in p.path:
                node = graph.get_node(node_name)
                if node: files_with_paths.add(node.file_path)
        files_with_supp = (
            {f.primary_file for f in supp_findings if f.primary_file}
            | {f.sink_file for f in supp_findings if f.sink_file}
            | {f.source_file for f in supp_findings if f.source_file}
        )
        all_target_files = sorted(files_with_paths | files_with_supp)

        if progress_callback: progress_callback({"event": "file_review_start", "files": len(all_target_files)})
        results = []; completed = 0
        for target_file in all_target_files:
            review = self.review_single_file_from_codebase(
                target_file, extraction_model=extraction_model, confirmation_model=confirmation_model,
                max_workers=max_workers, max_paths=max_paths, max_paths_per_sink=max_paths_per_sink,
                max_path_length=max_path_length, progress_callback=progress_callback,
                reasoning_effort=reasoning_effort)
            completed += 1
            if review and review.get("reviews"): results.append(review)
            if progress_callback: progress_callback({"event": "file_review_progress", "completed": completed, "total": len(all_target_files), "file": target_file})
        if progress_callback: progress_callback({"event": "file_review_done", "files": len(results)})
        return results

    def review_single_file_from_codebase(self, file_path, *, extraction_model="gpt-4.1-mini", confirmation_model=None,
                                          max_workers=8, max_paths=0, max_paths_per_sink=3, max_path_length=25,
                                          progress_callback=None, reasoning_effort=None):
        abs_target, relative_target = self._normalize_target_file(file_path)
        cache_key = self._file_review_cache_key(
            target_file=relative_target, extraction_model=extraction_model, confirmation_model=confirmation_model,
            max_workers=max_workers, max_paths=max_paths, max_paths_per_sink=max_paths_per_sink,
            max_path_length=max_path_length, reasoning_effort=reasoning_effort)
        with self._cache_lock:
            cached = self._file_review_cache.get(cache_key)
        if cached is not None: return dict(cached)

        graph, paths = self._ensure_graph_and_paths(
            extraction_model=extraction_model, max_workers=max_workers,
            max_paths=max_paths, max_path_length=max_path_length, progress_callback=progress_callback)
        if graph.node_count() == 0:
            review = {"file": relative_target, "file_path": abs_target, "reviews": []}
            with self._cache_lock: self._file_review_cache[cache_key] = review
            return dict(review)

        supp_findings = self._ensure_supplementary(
            graph, extraction_model=extraction_model, confirmation_model=confirmation_model,
            max_workers=max_workers, max_paths=max_paths, max_path_length=max_path_length,
            progress_callback=progress_callback, reasoning_effort=reasoning_effort)
        file_supp = self._supp_findings_for_file(supp_findings, relative_target)

        inbound_paths, cross_file_paths = self._split_paths_for_file(graph, paths, relative_target)

        file_reach = []
        if inbound_paths:
            file_reach = self.confirm_paths_for_file(
                relative_target, inbound_paths, graph,
                confirmation_model=confirmation_model, max_workers=max_workers,
                progress_callback=progress_callback, reasoning_effort=reasoning_effort)

        cross_findings = []
        if cross_file_paths:
            cross_findings = self.confirm_cross_file_for_target(
                relative_target, cross_file_paths, graph,
                confirmation_model=confirmation_model, max_workers=max_workers,
                progress_callback=progress_callback, reasoning_effort=reasoning_effort)

        all_findings = file_reach + cross_findings + file_supp
        if not all_findings:
            review = {"file": relative_target, "file_path": abs_target, "reviews": []}
            with self._cache_lock: self._file_review_cache[cache_key] = review
            return dict(review)

        filtered_findings = _post_filter_findings(all_findings, self._config.codebase_path)
        if not filtered_findings:
            review = {"file": relative_target, "file_path": abs_target, "reviews": []}
            with self._cache_lock: self._file_review_cache[cache_key] = review
            return dict(review)

        deduped, _, _ = Deduplicator.deduplicate(filtered_findings, max_per_sink=max_paths_per_sink)
        grouped = self._group_findings_as_reviews(deduped)
        review = None
        for item in grouped:
            if item.get("file") == relative_target: review = item; break
        if review is None:
            review = {"file": relative_target, "file_path": abs_target, "reviews": []}
        with self._cache_lock: self._file_review_cache[cache_key] = review
        return dict(review)


    def _group_findings_as_reviews(self, findings):
        grouped = defaultdict(list)
        base_path = os.path.abspath(self._config.codebase_path)
        for finding in findings:
            rel_file = finding.primary_file or finding.sink_file or finding.source_file
            if not rel_file: continue
            abs_file = rel_file if os.path.isabs(rel_file) else os.path.join(base_path, rel_file)
            grouped[(rel_file, os.path.abspath(abs_file))].append(self._finding_to_review(finding))
        return [{"file": rf, "file_path": af, "reviews": revs} for (rf, af), revs in grouped.items()]

    def _finding_to_review(self, finding):
        line_number = int(finding.primary_line or finding.sink_line or finding.source_line or 1)
        vtype = _normalise_vuln_type(finding.vulnerability_type)
        primary_fn = finding.primary_function or finding.sink_function
        issue = str(finding.description).strip() if str(finding.description or "").strip() else f"{vtype.replace('_', ' ')} in {primary_fn}"
        reasoning_parts = []
        if str(finding.evidence or "").strip(): reasoning_parts.append(str(finding.evidence).strip())
        if finding.path: reasoning_parts.append(f"Reachability path: {' -> '.join(finding.path)}")
        if str(finding.root_cause or "").strip(): reasoning_parts.append(f"Root cause: {str(finding.root_cause).strip()}")
        if finding.analysis_type:
            reasoning_parts.append(f"Analysis type: {finding.analysis_type}")
        if finding.canonical_key:
            reasoning_parts.append(f"Canonical key: {finding.canonical_key}")
        code_snippet = ""
        target_file = finding.primary_file or finding.sink_file or finding.source_file
        if target_file: code_snippet = _read_line_context(self._config.codebase_path, target_file, line_number, context=2)
        return {
            "issue": issue, "line_number": line_number, "code_snippet": code_snippet,
            "cwe": _VULN_TO_CWE.get(vtype),
            "severity": _severity_title(finding.severity, "Medium"),
            "confidence": _severity_title(finding.confidence, "Medium"),
            "reasoning": "\n".join(reasoning_parts),
            "mitigation": str(finding.root_cause or "").strip(),
        }

    def deduplicate_and_write(self, findings, output_path, *, max_paths_per_sink=3):
        filtered_findings = _post_filter_findings(findings, self._config.codebase_path)
        deduped, _, _ = Deduplicator.deduplicate(filtered_findings, max_per_sink=max_paths_per_sink)
        total = len(findings)
        removed = total - len(deduped)
        _write_jsonl(output_path, deduped)
        return deduped, total, removed


def _write_jsonl(path, findings):
    out = Path(path); out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        for f in findings: fh.write(json.dumps(f.to_dict(), ensure_ascii=False) + "\n")
