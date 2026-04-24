from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import threading
import uuid

from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from langchain_core.messages import SystemMessage, HumanMessage, AIMessage
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate

from metis.usage import submit_with_current_context
from metis.utils import parse_json_output, read_file_content

from .repository import EngineRepository
from .runtime import EngineConfig

logger = logging.getLogger("metis")


# types


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
    mechanism: str = ""
    mechanism_family: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id, "vulnerability_type": self.vulnerability_type,
            "severity": self.severity, "confidence": self.confidence,
            "source_function": self.source_function, "source_file": self.source_file,
            "source_line": self.source_line, "sink_function": self.sink_function,
            "sink_file": self.sink_file, "sink_line": self.sink_line,
            "path": self.path, "description": self.description,
            "root_cause": self.root_cause, "evidence": self.evidence,
            "analysis_type": self.analysis_type, "mechanism": self.mechanism,
            "mechanism_family": self.mechanism_family,
        }


class ReachabilityGraph:
    def __init__(self):
        self.nodes: dict[str, FunctionNode] = {}
        self.name_index: dict[str, list[str]] = {}

    def add_node(self, node):
        self.nodes[node.unique_name] = node
        self.name_index.setdefault(node.name, []).append(node.unique_name)

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
    def node_count(self): return len(self.nodes)
    def edge_count(self): return sum(len(n.resolved_calls) for n in self.nodes.values())

    def save_jsonl(self, path):
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", encoding="utf-8") as fh:
            for n in self.nodes.values():
                fh.write(json.dumps(n.to_dict(), ensure_ascii=False) + "\n")


# shared

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

def _lookup_fn(name, fn_by_name, fn_by_unique, all_fns):
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

def _collect_function_starts(lines):
    starts = []
    control_re = re.compile(r"\b(?:if|for|while|switch|catch)\s*\(")
    name_re = re.compile(r"([A-Za-z_~][\w:~]*)\s*\([^;{}]*\)\s*(?:const\s*)?(?:\{|$)")
    for i in range(len(lines)):
        if "(" not in lines[i]:
            continue
        window = " ".join(line.strip() for line in lines[i:min(len(lines), i + 4)])
        if not window or control_re.search(window):
            continue
        if window.lstrip().startswith(("return", "typedef")):
            continue
        sig_prefix = window.split("{", 1)[0]
        if ";" in sig_prefix:
            continue
        match = name_re.search(window)
        if not match:
            continue
        name = match.group(1)
        starts.append((i + 1, name))
    return starts

def _collect_function_bodies(file_content, max_lines=400):
    lines = file_content.splitlines()
    starts = _collect_function_starts(lines)
    results = []
    for start, name in starts:
        start_idx = max(0, start - 1)
        end_idx = min(len(lines), start_idx + 80)
        depth = 0
        opened = False
        for i in range(start_idx, min(len(lines), start_idx + max_lines)):
            for ch in lines[i]:
                if ch == "{":
                    depth += 1
                    opened = True
                elif ch == "}":
                    depth -= 1
            if opened and depth <= 0:
                end_idx = i + 1
                break
        results.append((name, start, lines[start_idx:end_idx]))
    return results

def _function_name_for_line(function_starts, line_number):
    current = "unknown"
    for start, name in function_starts:
        if start <= line_number:
            current = name
        else:
            break
    return current

def _line_context_from_content(file_content, line_number, context=4, max_chars=1600):
    lines = file_content.splitlines()
    if not lines:
        return ""
    try: line_number = max(1, int(line_number))
    except: line_number = 1
    start = max(0, line_number - 1 - context)
    end = min(len(lines), line_number + context)
    snippet = "\n".join(f"{i+1}: {lines[i]}" for i in range(start, end))
    return snippet[:max_chars]

def _merge_hint_lists(*hint_lists):
    merged = []
    seen = set()
    for hints in hint_lists:
        for hint in hints or []:
            text = str(hint).strip()
            if not text or text in seen:
                continue
            seen.add(text)
            merged.append(text)
    return merged

_DRIVER_PATH_HINTS = (
    "/gpu/", "/mali/", "/midgard/", "/bifrost/", "/valhall/", "/drm/", "/devicedrv/",
    "/ump/", "/umplock/", "/csf/", "/scheduler/", "/mmu/", "/hwcnt/", "/gralloc/",
    "/dma_buf_", "/runtime_pm", "/protected_mode", "/kcpu", "/softjobs", "/memory/",
)

_DRIVER_CONTENT_HINTS = (
    "kbase_", "mali_", "gpu_", "mmu", "doorbell", "queue_group", "workqueue", "timer",
    "hrtimer", "pm_runtime", "protected", "dma_buf", "get_user_pages", "put_page",
    "kbase_phy_alloc_mapping_get", "rb_link_node", "rb_erase", "list_add", "list_del",
    "fence", "scheduler", "soft_reset", "flush_noretain", "gpu_mappings", "alias",
)

_COMPILER_PATH_HINTS = (
    "/compiler/", "/cmpbe/", "/llvm/", "/ast2lir/", "/vectorize/", "/texture/",
    "/gles/", "/bifrost/", "/valhall/",
)

_COMPILER_CONTENT_HINTS = (
    "matrix", "vector", "constructor", "column", "row", "expr.u.value", "ast", "lir",
    "shader", "type_width", "lane", "swizzle", "parse", "token", "builder",
)

_MECHANISM_TO_VULN_TYPE = {
    "state_transition": "state_transition_bug",
    "ordering_gap": "ordering_race",
    "partial_cleanup": "partial_failure_cleanup",
    "cleanup_symmetry": "cleanup_asymmetry",
    "rollback_gap": "rollback_invariant_bug",
    "stale_after_unlock": "lifetime_invariant_break",
    "permission_domain_mismatch": "permission_mismatch",
    "deferred_callback_after_teardown": "deferred_work_uaf",
    "accounting_drift": "accounting_mismatch",
    "lock_order": "lock_order_inversion",
    "info_leak_logging": "information_disclosure",
    "width_mismatch_second_access": "out_of_bounds",
    "file_ops_lifecycle_gap": "lifetime_invariant_break",
    "compiler_shape_mismatch": "out_of_bounds",
    "generic_memory": "other",
}

_MECHANISM_FAMILY = {
    "state_transition": "state_order",
    "ordering_gap": "state_order",
    "stale_after_unlock": "state_order",
    "lock_order": "concurrency",
    "partial_cleanup": "cleanup_lifecycle",
    "cleanup_symmetry": "cleanup_lifecycle",
    "rollback_gap": "cleanup_lifecycle",
    "deferred_callback_after_teardown": "cleanup_lifecycle",
    "file_ops_lifecycle_gap": "cleanup_lifecycle",
    "permission_domain_mismatch": "semantic_validation",
    "width_mismatch_second_access": "semantic_validation",
    "accounting_drift": "accounting_lifetime",
    "info_leak_logging": "info_leak",
    "compiler_shape_mismatch": "compiler_semantic",
    "generic_memory": "classic_memory",
}

_ROOT_CAUSE_FAMILY_ORDER_DRIVER = {
    "state_order": 0,
    "cleanup_lifecycle": 1,
    "semantic_validation": 2,
    "accounting_lifetime": 3,
    "concurrency": 4,
    "info_leak": 5,
    "compiler_semantic": 6,
    "classic_memory": 7,
    "generic": 9,
}

_ROOT_CAUSE_FAMILY_ORDER_NONDRIVER = {
    "classic_memory": 0,
    "semantic_validation": 1,
    "cleanup_lifecycle": 2,
    "state_order": 3,
    "compiler_semantic": 4,
    "info_leak": 5,
    "concurrency": 6,
    "accounting_lifetime": 7,
    "generic": 9,
}

_MECHANISM_ORDER = {
    "state_transition": 0,
    "ordering_gap": 1,
    "partial_cleanup": 2,
    "cleanup_symmetry": 3,
    "rollback_gap": 4,
    "stale_after_unlock": 5,
    "permission_domain_mismatch": 6,
    "deferred_callback_after_teardown": 7,
    "accounting_drift": 8,
    "lock_order": 9,
    "width_mismatch_second_access": 10,
    "file_ops_lifecycle_gap": 11,
    "info_leak_logging": 12,
    "compiler_shape_mismatch": 13,
    "generic_memory": 50,
}

_GPU_TYPE_ORDER = {
    "command_injection": 0,
    "path_traversal": 1,
    "buffer_overflow": 2,
    "format_string": 3,
    "sscanf_overflow": 4,
    "information_disclosure": 5,
    "deferred_work_uaf": 6,
    "use_after_free": 7,
    "state_transition_bug": 8,
    "stale_state": 9,
    "teardown_race": 10,
    "ordering_race": 11,
    "cleanup_asymmetry": 12,
    "partial_failure_cleanup": 13,
    "permission_mismatch": 14,
    "flag_semantic_bug": 15,
    "accounting_mismatch": 16,
    "lifetime_invariant_break": 17,
    "rollback_invariant_bug": 18,
    "lock_order_inversion": 19,
    "double_free": 20,
    "double_close": 21,
    "boolean_coercion": 22,
    "wrong_constant": 23,
    "stale_length": 24,
    "type_confusion": 25,
    "out_of_bounds": 26,
    "integer_overflow": 27,
    "null_deref": 28,
    "race_condition": 29,
    "ignored_return": 30,
    "fd_leak": 31,
    "toctou": 32,
    "other": 40,
}

_VULN_TO_CWE = {
    "buffer_overflow": "CWE-120", "out_of_bounds": "CWE-787", "use_after_free": "CWE-416",
    "double_free": "CWE-415", "null_deref": "CWE-476", "command_injection": "CWE-78",
    "format_string": "CWE-134", "integer_overflow": "CWE-190", "path_traversal": "CWE-22",
    "race_condition": "CWE-362", "uninitialized_memory": "CWE-457", "type_confusion": "CWE-843",
    "boolean_coercion": "CWE-253", "wrong_constant": "CWE-697", "wrong_field": "CWE-688",
    "stale_length": "CWE-131", "double_close": "CWE-675", "callback_uaf": "CWE-416",
    "stale_pointer": "CWE-825", "refcount_imbalance": "CWE-911",
    "missing_auth": "CWE-862", "ignored_return": "CWE-252", "sscanf_overflow": "CWE-120",
    "toctou": "CWE-367", "static_buffer_reuse": "CWE-562", "pool_free_mismatch": "CWE-762",
    "fd_leak": "CWE-775", "thread_unsafe": "CWE-362", "assignment_in_condition": "CWE-481",
    "sign_confusion": "CWE-195", "permission_escalation": "CWE-269",
    "state_transition_bug": "CWE-664", "stale_state": "CWE-664", "ordering_race": "CWE-362",
    "teardown_race": "CWE-362", "deferred_work_uaf": "CWE-416", "cleanup_asymmetry": "CWE-404",
    "partial_failure_cleanup": "CWE-404", "lock_order_inversion": "CWE-833",
    "permission_mismatch": "CWE-285", "flag_semantic_bug": "CWE-697",
    "accounting_mismatch": "CWE-664", "lifetime_invariant_break": "CWE-664",
    "rollback_invariant_bug": "CWE-664", "information_disclosure": "CWE-200",
}

_MECHANISM_TO_CWE = {
    "state_transition": "CWE-664",
    "ordering_gap": "CWE-362",
    "partial_cleanup": "CWE-404",
    "cleanup_symmetry": "CWE-404",
    "rollback_gap": "CWE-664",
    "stale_after_unlock": "CWE-416",
    "permission_domain_mismatch": "CWE-285",
    "deferred_callback_after_teardown": "CWE-416",
    "accounting_drift": "CWE-664",
    "lock_order": "CWE-833",
    "info_leak_logging": "CWE-200",
    "width_mismatch_second_access": "CWE-787",
    "file_ops_lifecycle_gap": "CWE-664",
    "compiler_shape_mismatch": "CWE-787",
}

def _looks_driver_file(file_path, file_content=""):
    path_text = str(file_path or "").lower().replace("\\", "/")
    if any(token in path_text for token in _DRIVER_PATH_HINTS):
        return True
    content_text = str(file_content or "").lower()
    score = sum(1 for token in _DRIVER_CONTENT_HINTS if token in content_text)
    return score >= 2

def _looks_compilerish_file(file_path, file_content=""):
    path_text = str(file_path or "").lower().replace("\\", "/")
    if any(token in path_text for token in _COMPILER_PATH_HINTS):
        return True
    content_text = str(file_content or "").lower()
    score = sum(1 for token in _COMPILER_CONTENT_HINTS if token in content_text)
    return score >= 2

def _normalize_mechanism(value, fallback_type="other"):
    text = str(value or "").strip().lower()
    aliases = {
        "state_transition_bug": "state_transition",
        "ordering_race": "ordering_gap",
        "partial_failure_cleanup": "partial_cleanup",
        "cleanup_asymmetry": "cleanup_symmetry",
        "rollback_invariant_bug": "rollback_gap",
        "permission_mismatch": "permission_domain_mismatch",
        "deferred_work_uaf": "deferred_callback_after_teardown",
        "accounting_mismatch": "accounting_drift",
        "lock_order_inversion": "lock_order",
        "information_disclosure": "info_leak_logging",
        "stale_state": "state_transition",
        "lifetime_invariant_break": "stale_after_unlock",
        "out_of_bounds": "width_mismatch_second_access" if str(fallback_type or "").strip() == "out_of_bounds" else "generic_memory",
    }
    if text in aliases:
        return aliases[text]
    if text in _MECHANISM_TO_VULN_TYPE:
        return text
    if str(fallback_type or "").strip() in {"state_transition_bug", "ordering_race", "partial_failure_cleanup", "cleanup_asymmetry",
                                            "rollback_invariant_bug", "permission_mismatch", "deferred_work_uaf",
                                            "accounting_mismatch", "lock_order_inversion", "information_disclosure"}:
        return aliases.get(str(fallback_type or "").strip(), "generic_memory")
    return "generic_memory"

def _resolve_vulnerability_type(mechanism, declared_type):
    declared = str(declared_type or "").strip()
    mech = _normalize_mechanism(mechanism, declared)
    mapped = _MECHANISM_TO_VULN_TYPE.get(mech, "other")
    if not declared:
        return mapped
    if declared in {"other", "integer_overflow", "null_deref", "fd_leak", "race_condition"} and mapped not in {"other", declared}:
        return mapped
    if mech == "info_leak_logging" and declared != "information_disclosure":
        return "information_disclosure"
    return declared

def _mechanism_family(mechanism, fallback_type="other"):
    mech = _normalize_mechanism(mechanism, fallback_type)
    if mech in _MECHANISM_FAMILY:
        return _MECHANISM_FAMILY[mech]
    if str(fallback_type or "").strip() in {"buffer_overflow", "out_of_bounds", "use_after_free", "double_free", "null_deref",
                                            "command_injection", "format_string", "integer_overflow", "path_traversal",
                                            "information_disclosure"}:
        return "classic_memory" if str(fallback_type or "").strip() != "information_disclosure" else "info_leak"
    return "generic"

def _family_order(candidate):
    fam = str(candidate.get("mechanism_family") or _mechanism_family(candidate.get("mechanism"), candidate.get("type"))).strip()
    if candidate.get("driver_context"):
        return _ROOT_CAUSE_FAMILY_ORDER_DRIVER.get(fam, 50)
    return _ROOT_CAUSE_FAMILY_ORDER_NONDRIVER.get(fam, 50)

def _cwe_for(vulnerability_type, mechanism=""):
    mech = _normalize_mechanism(mechanism, vulnerability_type)
    if mech in _MECHANISM_TO_CWE:
        return _MECHANISM_TO_CWE[mech]
    return _VULN_TO_CWE.get(str(vulnerability_type or "").strip())

def _mechanism_priority(mechanism, fallback_type="other"):
    mech = _normalize_mechanism(mechanism, fallback_type)
    return _MECHANISM_ORDER.get(mech, 99)

def _candidate_priority_key(candidate):
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return (
        0 if candidate.get("primary") else 1,
        0 if candidate.get("locality") == "local_direct" else 1,
        sev_order.get(str(candidate.get("severity") or "medium").lower(), 5),
        _family_order(candidate),
        _mechanism_priority(candidate.get("mechanism"), candidate.get("type")),
        _GPU_TYPE_ORDER.get(str(candidate.get("type") or "other").strip(), 50),
        int(candidate.get("line") or 0),
    )

def _default_hints_for_candidate(candidate):
    fn = str(candidate.get("function_name") or "unknown").strip()
    ctype = str(candidate.get("type") or "other").strip()
    mechanism = _normalize_mechanism(candidate.get("mechanism"), ctype)
    base = [f"{fn}("] if fn and fn != "unknown" else []
    extra = {
        "command_injection": ["system(", "popen("],
        "buffer_overflow": ["sprintf(", "strcpy(", "strcat("],
        "sscanf_overflow": ["sscanf(", "%s"],
        "path_traversal": ["fopen(", "open(", "ifstream"],
        "integer_overflow": ["malloc(", "calloc(", "realloc("],
        "use_after_free": ["kfree(", "free(", "put_page("],
        "deferred_work_uaf": ["queue_work(", "schedule_work(", "cancel_work_sync(", "del_timer_sync("],
        "state_transition_bug": ["state", "enabled", "terminated", "override", "doorbell"],
        "stale_state": ["state", "active_protm_grp", "override", "doorbell"],
        "ordering_race": ["pm_runtime_get_sync(", "enable_gpu_power_control(", "flush_noretain", "reset"],
        "teardown_race": ["destroy_workqueue(", "cancel_work_sync(", "del_timer_sync(", "hrtimer_cancel("],
        "cleanup_asymmetry": ["get_user_pages", "put_page(", "mapping_get", "mapping_put", "list_add(", "list_del("],
        "partial_failure_cleanup": ["goto", "err_", "fail:", "put_page(", "dma_buf_put("],
        "lock_order_inversion": ["mutex_lock(", "spin_lock(", "lock", "unlock"],
        "permission_mismatch": ["GPU_WR", "CPU_WR", "READ", "WRITE", "permission", "flags"],
        "flag_semantic_bug": ["flags", "permission", "constant", "mask"],
        "accounting_mismatch": ["gpu_mappings", "refcount", "alias", "evictable", "dont_need"],
        "lifetime_invariant_break": ["alias", "refcount", "gpu_mappings", "shrink", "free"],
        "rollback_invariant_bug": ["rb_link_node(", "rb_erase(", "list_add(", "list_del(", "goto"],
        "information_disclosure": ["printk", "dev_err", "pr_err", "%pa", "%px"],
    }.get(ctype, [])
    mechanism_extra = {
        "state_transition": ["state", "enabled", "terminated", "doorbell", "override"],
        "ordering_gap": ["pm_runtime_get_sync(", "enable_gpu_power_control(", "flush_noretain", "disable", "reset"],
        "partial_cleanup": ["goto", "err_", "fail:", "put_page(", "mapping_put", "cancel_work_sync("],
        "cleanup_symmetry": ["setup", "release", "destroy", "cancel_work_sync(", "del_timer_sync("],
        "rollback_gap": ["rb_link_node(", "rb_erase(", "list_add(", "list_del(", "goto"],
        "stale_after_unlock": ["unlock", "lock", "relock", "stale", "region", "gpu_alloc"],
        "permission_domain_mismatch": ["GPU_WR", "CPU_WR", "flags", "permission", "BASE_MEM_"],
        "deferred_callback_after_teardown": ["queue_work(", "schedule_work(", "cancel_work_sync(", "del_timer_sync("],
        "accounting_drift": ["gpu_mappings", "alias", "refcount", "shrink", "free"],
        "lock_order": ["mutex_lock(", "spin_lock(", "callback", "worker", "irq"],
        "info_leak_logging": ["printk", "dev_err", "pr_err", "%pa", "%px", "fault", "phys"],
        "width_mismatch_second_access": ["u32", "u64", "32", "64", "error", "value", "mapping_get"],
        "file_ops_lifecycle_gap": ["struct file_operations", ".release", ".flush", ".poll", ".mmap", ".open"],
        "compiler_shape_mismatch": ["matrix", "row", "column", "constructor", "vector", "expr.u.value"],
    }.get(mechanism, [])
    return _merge_hint_lists(base, extra, mechanism_extra)

def _normalize_candidate_dict(candidate, *, default_driver_context=False):
    fn = str(candidate.get("function_name") or "unknown").strip() or "unknown"
    try:
        line = max(1, int(candidate.get("line", 1)))
    except:
        line = 1
    mechanism = _normalize_mechanism(candidate.get("mechanism"), candidate.get("type"))
    vuln_type = _resolve_vulnerability_type(mechanism, candidate.get("type"))
    driver_context = bool(candidate.get("driver_context", default_driver_context))
    compiler_context = bool(candidate.get("compiler_context", False))
    normalized = {
        "function_name": fn,
        "line": line,
        "type": vuln_type,
        "mechanism": mechanism,
        "mechanism_family": _mechanism_family(mechanism, vuln_type),
        "severity": str(candidate.get("severity") or "medium").strip().lower(),
        "description": str(candidate.get("description") or "").strip(),
        "locality": str(candidate.get("locality") or "cross_file").strip(),
        "primary": bool(candidate.get("primary")),
        "cross_file_concern": bool(candidate.get("cross_file_concern")),
        "code_snippet": str(candidate.get("code_snippet") or ""),
        "investigation_hints": [str(h).strip() for h in (candidate.get("investigation_hints") or []) if str(h).strip()],
        "driver_context": driver_context,
        "compiler_context": compiler_context,
    }
    normalized["investigation_hints"] = _merge_hint_lists(
        normalized["investigation_hints"],
        _default_hints_for_candidate(normalized),
    )
    return normalized

def _parse_candidate_payload(raw, *, default_driver_context=False):
    parsed = parse_json_output(raw)
    if not isinstance(parsed, dict):
        return []
    candidates = parsed.get("candidates")
    if not isinstance(candidates, list):
        return []
    return [_normalize_candidate_dict(c, default_driver_context=default_driver_context) for c in candidates if isinstance(c, dict)]

def _parse_verdict_payload(raw):
    parsed = parse_json_output(raw)
    if not isinstance(parsed, dict):
        return None
    verdict = parsed.get("verdict")
    if not isinstance(verdict, dict):
        return None
    mechanism = _normalize_mechanism(verdict.get("mechanism"), verdict.get("vulnerability_type"))
    vtype = _resolve_vulnerability_type(mechanism, verdict.get("vulnerability_type"))
    verdict["mechanism"] = mechanism
    verdict["mechanism_family"] = _mechanism_family(mechanism, vtype)
    verdict["vulnerability_type"] = vtype
    return verdict

def _prune_audit_candidates(candidates, limit=25):
    if not candidates:
        return []
    merged = {}
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        normalized = _normalize_candidate_dict(candidate, default_driver_context=bool(candidate.get("driver_context")))
        key = (
            normalized["function_name"],
            normalized["line"],
            normalized["mechanism_family"],
            normalized["mechanism"],
            normalized["type"],
        )
        existing = merged.get(key)
        if existing is None:
            merged[key] = normalized
            continue
        if _candidate_priority_key(normalized) < _candidate_priority_key(existing):
            better = normalized
            worse = existing
        else:
            better = existing
            worse = normalized
        better["investigation_hints"] = _merge_hint_lists(
            better.get("investigation_hints") or [],
            worse.get("investigation_hints") or [],
        )
        if len(str(worse.get("description") or "")) > len(str(better.get("description") or "")):
            better["description"] = str(worse.get("description") or "")
        if not str(better.get("code_snippet") or "") and str(worse.get("code_snippet") or ""):
            better["code_snippet"] = str(worse.get("code_snippet") or "")
        better["primary"] = bool(better.get("primary")) or bool(worse.get("primary"))
        better["cross_file_concern"] = bool(better.get("cross_file_concern")) or bool(worse.get("cross_file_concern"))
        better["driver_context"] = bool(better.get("driver_context")) or bool(worse.get("driver_context"))
        better["compiler_context"] = bool(better.get("compiler_context")) or bool(worse.get("compiler_context"))
        if better.get("locality") != "local_direct" and worse.get("locality") == "local_direct":
            better["locality"] = "local_direct"
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        if sev_order.get(str(worse.get("severity") or "medium").lower(), 5) < sev_order.get(str(better.get("severity") or "medium").lower(), 5):
            better["severity"] = str(worse.get("severity") or "medium").lower()
        merged[key] = better
    ordered = sorted(merged.values(), key=_candidate_priority_key)
    pruned = []
    seen_primary_local = set()
    for candidate in ordered:
        group_key = (candidate["function_name"], candidate["line"], candidate["mechanism_family"])
        if candidate.get("primary") and candidate.get("locality") == "local_direct":
            seen_primary_local.add(group_key)
            pruned.append(candidate)
            continue
        if group_key in seen_primary_local and str(candidate.get("type") or "") in {"toctou", "other", "integer_overflow", "null_deref"}:
            continue
        pruned.append(candidate)
    return pruned[:limit]

def _find_first_matching_line(body_lines, tokens):
    for idx, line in enumerate(body_lines):
        if any(token in line for token in tokens):
            return idx
    return 0

def _extract_local_call_relations(file_content):
    bodies = _collect_function_bodies(file_content)
    names = [name for name, _, _ in bodies]
    calls = {name: set() for name in names}
    reverse = {name: set() for name in names}
    body_map = {name: (start, lines) for name, start, lines in bodies}
    for name, _, body_lines in bodies:
        body_text = "\n".join(body_lines)
        for other in names:
            if other == name:
                continue
            if re.search(r"\b" + re.escape(other) + r"\s*\(", body_text):
                calls[name].add(other)
                reverse[other].add(name)
    return body_map, calls, reverse

def _function_name_seed_key(name):
    parts = [p for p in str(name or "").split("_") if p]
    return "_".join(parts[:2]) if parts else str(name or "")

def _build_same_file_clusters(file_content, seed_functions, *, max_clusters=4, max_functions_per_cluster=6):
    body_map, calls, reverse = _extract_local_call_relations(file_content)
    if not body_map:
        return []
    results = []
    seen = set()
    all_names = list(body_map.keys())
    for seed in seed_functions:
        if seed not in body_map or seed in seen:
            continue
        seen.add(seed)
        cluster = [seed]
        cluster.extend(sorted(calls.get(seed, []))[:2])
        cluster.extend(sorted(reverse.get(seed, []))[:2])
        prefix = _function_name_seed_key(seed)
        for name in all_names:
            if name in cluster:
                continue
            if prefix and _function_name_seed_key(name) == prefix:
                cluster.append(name)
            if len(cluster) >= max_functions_per_cluster:
                break
        start, body_lines = body_map[seed]
        body_text = "\n".join(body_lines)
        helper_keywords = ("worker", "timer", "dump", "flush", "release", "destroy", "close", "poll", "suspend", "prepare")
        for name in all_names:
            if name in cluster:
                continue
            if any(k in name.lower() for k in helper_keywords) and re.search(r"\b" + re.escape(name) + r"\s*\(", body_text):
                cluster.append(name)
            if len(cluster) >= max_functions_per_cluster:
                break
        cluster = sorted(dict.fromkeys(cluster), key=lambda n: body_map[n][0])[:max_functions_per_cluster]
        code_parts = []
        for name in cluster:
            start, lines = body_map[name]
            snippet = "\n".join(f"{start+i}: {line}" for i, line in enumerate(lines))
            code_parts.append(f"--- {name} (line {start}) ---\n{snippet[:6000]}")
        results.append({
            "seed": seed,
            "functions": cluster,
            "code": "\n\n".join(code_parts),
        })
        if len(results) >= max_clusters:
            break
    return results


_REVIEW_FILE_LARGE_FILE_CHAR_THRESHOLD = 120000
_REVIEW_FILE_LARGE_FILE_LINE_THRESHOLD = 2500
_REVIEW_FILE_FULL_PROMPT_BUDGET = 60000
_REVIEW_FILE_TARGET_PROMPT_BUDGET = 45000
_REVIEW_FILE_LOCAL_PROMPT_BUDGET = 35000
_REVIEW_FILE_MAX_GENERAL_SEEDS = 8
_REVIEW_FILE_MAX_GENERAL_CLUSTERS = 4
_REVIEW_FILE_MAX_CLUSTER_FUNCTIONS = 6

_REVIEW_FILE_GENERAL_INTEREST_TOKENS = (
    "queue_work(", "schedule_work(", "cancel_work_sync(", "destroy_workqueue(",
    "del_timer_sync(", "timer_shutdown_sync(", "hrtimer_cancel(",
    "get_user_pages", "put_page(", "mapping_get", "mapping_put",
    "pm_runtime_get_sync(", "enable_gpu_power_control(", "flush_noretain",
    "reset", "doorbell", "enabled", "terminated", "override",
    "gpu_mappings", "alias", "refcount", "NO_USER_FREE", "DONT_NEED",
    "struct file_operations", ".release", ".flush", ".poll", ".open",
    "printk(", "dev_err(", "pr_err(", "%pa", "%px",
    "u32", "u64", "uint32_t", "uint64_t",
    "matrix", "vector", "constructor", "column", "row", "expr.u.value",
)

def _is_large_review_file(file_content):
    text = str(file_content or "")
    if len(text) >= _REVIEW_FILE_LARGE_FILE_CHAR_THRESHOLD:
        return True
    return text.count("\n") >= _REVIEW_FILE_LARGE_FILE_LINE_THRESHOLD

def _safe_numbered_excerpt(content, max_chars):
    numbered = _number_lines(content)
    if len(numbered) <= max_chars:
        return numbered
    return numbered[:max_chars] + "\n... [truncated for large-file review]"

def _derive_large_file_seed_functions(file_content, max_seeds=_REVIEW_FILE_MAX_GENERAL_SEEDS):
    bodies = _collect_function_bodies(file_content)
    if not bodies:
        return []

    scored = []
    lowered_tokens = tuple(t.lower() for t in _REVIEW_FILE_GENERAL_INTEREST_TOKENS)
    for name, start, body_lines in bodies:
        body = "\n".join(body_lines).lower()
        score = sum(1 for token in lowered_tokens if token in body)
        if score > 0:
            scored.append((-score, start, name))

    if not scored:
        return [name for name, _, _ in bodies[:max_seeds]]

    scored.sort()
    seeds = []
    seen = set()
    for _, _, name in scored:
        if name in seen:
            continue
        seen.add(name)
        seeds.append(name)
        if len(seeds) >= max_seeds:
            break
    return seeds

def _safe_build_same_file_clusters(file_content, seed_functions, *, max_clusters=4, max_functions_per_cluster=6):
    try:
        return _build_same_file_clusters(
            file_content,
            seed_functions,
            max_clusters=max_clusters,
            max_functions_per_cluster=max_functions_per_cluster,
        )
    except Exception as e:
        logger.warning("Same-file cluster build failed: %s", e)
        return []

def _build_large_file_review_payload(file_path, file_content, max_chars=_REVIEW_FILE_FULL_PROMPT_BUDGET):
    seeds = _derive_large_file_seed_functions(file_content, max_seeds=_REVIEW_FILE_MAX_GENERAL_SEEDS)
    clusters = _safe_build_same_file_clusters(
        file_content,
        seeds,
        max_clusters=_REVIEW_FILE_MAX_GENERAL_CLUSTERS,
        max_functions_per_cluster=_REVIEW_FILE_MAX_CLUSTER_FUNCTIONS,
    )

    if not clusters:
        return _safe_numbered_excerpt(file_content, max_chars)

    parts = []
    total = 0
    for cluster in clusters:
        part = f"== CLUSTER seed: {cluster['seed']} ==\n{cluster['code']}"
        if total + len(part) > max_chars and parts:
            break
        if total + len(part) > max_chars:
            part = part[: max(0, max_chars - total)]
        parts.append(part)
        total += len(part)
        if total >= max_chars:
            break

    if not parts:
        return _safe_numbered_excerpt(file_content, max_chars)

    payload = "\n\n".join(parts)
    if len(payload) > max_chars:
        payload = payload[:max_chars]
    if len(payload) < max_chars and len(payload) < len(file_content):
        payload += "\n\n... [truncated large-file cluster excerpt]"
    return payload

def _build_prompt_ready_file_content(file_path, file_content, *, focus_function=None, focus_line=None, max_chars=_REVIEW_FILE_FULL_PROMPT_BUDGET):
    if not _is_large_review_file(file_content):
        return _safe_numbered_excerpt(file_content, max_chars)

    sections = []

    if focus_function and str(focus_function).strip() not in {"", "unknown", "file_operations"}:
        clusters = _safe_build_same_file_clusters(
            file_content,
            [str(focus_function).strip()],
            max_clusters=1,
            max_functions_per_cluster=_REVIEW_FILE_MAX_CLUSTER_FUNCTIONS,
        )
        if clusters:
            sections.append("== FOCUS CLUSTER ==\n" + clusters[0]["code"])

    if focus_line:
        try:
            focus_line = max(1, int(focus_line))
        except Exception:
            focus_line = 1
        local = _line_context_from_content(file_content, focus_line, context=25, max_chars=max_chars // 3)
        if local:
            sections.append("== FOCUS WINDOW ==\n" + local)

    remaining_budget = max_chars - len("\n\n".join(sections))
    if remaining_budget > max_chars // 3:
        general = _build_large_file_review_payload(file_path, file_content, max_chars=remaining_budget)
        if general:
            sections.append("== LARGE FILE EXCERPT ==\n" + general)

    if not sections:
        return _safe_numbered_excerpt(file_content, max_chars)

    payload = "\n\n".join(sections)
    if len(payload) > max_chars:
        payload = payload[:max_chars]
    return payload

def _detect_obvious_local_candidates(file_content):
    lines = file_content.splitlines()
    function_starts = _collect_function_starts(lines)
    candidates = []
    command_tokens = ("system(", "popen(", "_popen(", "execl(", "execv(", "execvp(", "execve(")
    open_tokens = ("std::ifstream", "std::ofstream", "ifstream ", "ofstream ", "fopen(", "open(", "freopen(")
    for idx, line in enumerate(lines):
        stripped = line.strip()
        line_number = idx + 1
        function_name = _function_name_for_line(function_starts, line_number)
        local_window = "\n".join(lines[max(0, idx - 4):min(len(lines), idx + 3)])
        code_snippet = _line_context_from_content(file_content, line_number, context=3)
        if any(token in stripped for token in command_tokens):
            if any(token in local_window for token in (' + ', '.append(', 'std::string', 'command', 'cmd', 'destination', 'path', '.string()')):
                candidates.append({
                    "function_name": function_name,
                    "line": line_number,
                    "type": "command_injection",
                    "mechanism": "generic_memory",
                    "severity": "high",
                    "description": "Shell command execution uses variable data in the target file, which is a classic command-injection pattern.",
                    "locality": "local_direct",
                    "primary": True,
                    "cross_file_concern": False,
                    "code_snippet": code_snippet,
                    "investigation_hints": [f"{function_name}(", "system(", "popen("] if function_name != "unknown" else ["system(", "popen("]})
        if any(token in stripped for token in ("sprintf(", "vsprintf(", "strcpy(", "strcat(", "gets(")):
            candidates.append({
                "function_name": function_name,
                "line": line_number,
                "type": "buffer_overflow",
                "mechanism": "generic_memory",
                "severity": "high",
                "description": "The target file contains an unbounded write primitive into a caller-visible buffer or local buffer.",
                "locality": "local_direct",
                "primary": True,
                "cross_file_concern": False,
                "code_snippet": code_snippet,
                "investigation_hints": [f"{function_name}(", "sprintf(", "strcpy("] if function_name != "unknown" else ["sprintf(", "strcpy("]})
        if any(token in stripped for token in ("sscanf(", "scanf(")) and "%s" in local_window:
            candidates.append({
                "function_name": function_name,
                "line": line_number,
                "type": "sscanf_overflow",
                "mechanism": "generic_memory",
                "severity": "high",
                "description": "The target file uses scanf-style parsing with %s, which can overflow fixed buffers when width is not constrained.",
                "locality": "local_direct",
                "primary": True,
                "cross_file_concern": False,
                "code_snippet": code_snippet,
                "investigation_hints": [f"{function_name}(", "sscanf(", "%s"] if function_name != "unknown" else ["sscanf(", "%s"]})
        if any(token in stripped for token in open_tokens):
            path_window = "\n".join(lines[max(0, idx - 5):idx + 1])
            if any(token in path_window for token in (' + "/" + ', '+ "/" +', 'std::filesystem::path', 'fs::path', ' / (', '/ (', '.append("/")', 'path =', '.string()', '.c_str()')):
                candidates.append({
                    "function_name": function_name,
                    "line": max(1, line_number - 1),
                    "type": "path_traversal",
                    "mechanism": "generic_memory",
                    "severity": "high",
                    "description": "The target file constructs a filesystem path from variable input and then opens it without visible normalization or validation.",
                    "locality": "local_direct",
                    "primary": True,
                    "cross_file_concern": False,
                    "code_snippet": _line_context_from_content(file_content, max(1, line_number - 1), context=3),
                    "investigation_hints": [f"{function_name}(", "ifstream", "fopen("] if function_name != "unknown" else ["ifstream", "fopen("]})
        if any(token in stripped for token in ("malloc(", "calloc(", "realloc(")) and "*" in stripped:
            candidates.append({
                "function_name": function_name,
                "line": line_number,
                "type": "integer_overflow",
                "mechanism": "generic_memory",
                "severity": "medium",
                "description": "The target file performs size arithmetic in an allocation expression, which may overflow if inputs are large.",
                "locality": "local_direct",
                "primary": False,
                "cross_file_concern": False,
                "code_snippet": code_snippet,
                "investigation_hints": [f"{function_name}(", "malloc(", "realloc("] if function_name != "unknown" else ["malloc(", "realloc("]})
    return _prune_audit_candidates(candidates, limit=25)

def _detect_driver_specific_candidates(file_path, file_content):
    if not _looks_driver_file(file_path, file_content):
        return []

    candidates = []
    acquire_release_specs = [
        (("get_user_pages", "pin_user_pages", "get_page("), ("put_page(", "unpin_user_page", "release_pages"), "partial_cleanup",
         "The function acquires page references from user memory but does not show a clearly balanced release path on failure/teardown."),
        (("dma_buf_get(", "kbase_phy_alloc_mapping_get(", "mapping_get"), ("dma_buf_put(", "kbase_phy_alloc_mapping_put(", "mapping_put"), "cleanup_symmetry",
         "The function acquires a mapping/resource object and appears to have an error or teardown path without the matching release."),
        (("alloc_workqueue(", "timer_setup(", "hrtimer_init(", "init_timer("), ("destroy_workqueue(", "cancel_work_sync(", "cancel_delayed_work_sync(", "del_timer_sync(", "timer_shutdown_sync(", "hrtimer_cancel("), "cleanup_symmetry",
         "The function creates asynchronous resources but does not show a clearly symmetric teardown path across failure/cleanup."),
        (("list_add(", "rb_link_node(", "xa_store(", "idr_alloc"), ("list_del(", "rb_erase(", "xa_erase(", "idr_remove"), "rollback_gap",
         "The function inserts state into a tracking structure but does not show a clear rollback/removal path on failure."),
    ]

    for function_name, start_line, body_lines in _collect_function_bodies(file_content):
        body = "\n".join(body_lines)
        errorish = any(token in body for token in ("goto", "err_", "fail:", "error:", "return -", "return NULL", "return false", "return 0"))
        schedule_tokens = ("queue_work(", "schedule_work(", "schedule_delayed_work(", "mod_delayed_work(", "add_timer(", "mod_timer(", "hrtimer_start(", "tasklet_schedule(")
        cancel_tokens = ("cancel_work_sync(", "cancel_delayed_work_sync(", "flush_workqueue(", "del_timer_sync(", "timer_shutdown_sync(", "hrtimer_cancel(", "tasklet_kill(")
        free_tokens = ("kfree(", "free(", "vfree(", "kvfree(", "destroy_workqueue(", "delete_queue", "terminate", "remove_group", "release_", "destroy_", "__free")

        if any(token in body for token in schedule_tokens) and any(token in body for token in free_tokens) and not any(token in body for token in cancel_tokens):
            line = start_line + _find_first_matching_line(body_lines, schedule_tokens + free_tokens)
            candidates.append({
                "function_name": function_name,
                "line": line,
                "type": "deferred_work_uaf",
                "mechanism": "deferred_callback_after_teardown",
                "severity": "high",
                "description": "The function schedules deferred work or timers and also tears down or frees related state without an obvious synchronous cancellation path, which can leave asynchronous callbacks dereferencing freed objects.",
                "locality": "local_direct",
                "primary": True,
                "cross_file_concern": False,
                "code_snippet": _line_context_from_content(file_content, line, context=4),
                "investigation_hints": [f"{function_name}(", "queue_work(", "cancel_work_sync(", "del_timer_sync("],
                "driver_context": True,
            })

        if any(token in body for token in ("pm_runtime_get_sync(", "enable_gpu_power_control(", "disable_gpu_power_control(", "flush_noretain", "soft_reset", "GPU_COMMAND_CLEAR_FAULT", "gpu_powered", "kbase_mmu_disable", "kbase_mmu_flush")):
            line = start_line + _find_first_matching_line(body_lines, ("pm_runtime_get_sync(", "enable_gpu_power_control(", "flush_noretain", "soft_reset", "GPU_COMMAND_CLEAR_FAULT", "gpu_powered", "kbase_mmu_disable", "kbase_mmu_flush"))
            candidates.append({
                "function_name": function_name,
                "line": line,
                "type": "ordering_race",
                "mechanism": "ordering_gap",
                "severity": "high",
                "description": "The function manipulates GPU power, reset, MMU, cache, or fault-handling state in an order that may expose partially transitioned state or race with concurrent teardown/restart paths.",
                "locality": "local_direct",
                "primary": True,
                "cross_file_concern": False,
                "code_snippet": _line_context_from_content(file_content, line, context=4),
                "investigation_hints": [f"{function_name}(", "pm_runtime_get_sync(", "enable_gpu_power_control(", "reset", "flush_noretain"],
                "driver_context": True,
            })

        if any(token in body for token in ("active_protm_grp", "protected_transition_override", "doorbell", "enabled", "dying", "terminated", "gpu_mappings")):
            if any(token in body for token in ("kfree(", "free(", "remove_", "delete_", "destroy_", "terminate", "disable")):
                line = start_line + _find_first_matching_line(body_lines, ("active_protm_grp", "protected_transition_override", "doorbell", "enabled", "dying", "terminated", "gpu_mappings"))
                desc = "The function updates or relies on lifecycle-critical state but also performs teardown or disable operations in the same flow, which suggests stale state may remain visible after the object is no longer valid."
                ctype = "stale_state"
                mechanism = "state_transition"
                if any(token in body for token in ("enable", "disable", "terminated", "override", "doorbell")):
                    ctype = "state_transition_bug"
                    desc = "The function exposes, enables, or preserves lifecycle state before validation completes or fails to clear it on teardown, which can leave hardware or later code observing an invalid state transition."
                candidates.append({
                    "function_name": function_name,
                    "line": line,
                    "type": ctype,
                    "mechanism": mechanism,
                    "severity": "high",
                    "description": desc,
                    "locality": "local_direct",
                    "primary": True,
                    "cross_file_concern": False,
                    "code_snippet": _line_context_from_content(file_content, line, context=4),
                    "investigation_hints": [f"{function_name}(", "state", "enabled", "terminated", "doorbell", "override"],
                    "driver_context": True,
                })

        if any(token in body for token in ("KBASE_REG_GPU_WR", "KBASE_REG_CPU_WR", "KBASE_REG_GPU_RD", "KBASE_REG_CPU_RD", "BASE_MEM_", "VM_", "PROT_", "READ", "WRITE")):
            if any(token in body for token in ("permission", "flags", "access", "check", "if (", "&&", "||")):
                line = start_line + _find_first_matching_line(body_lines, ("KBASE_REG_GPU_WR", "KBASE_REG_CPU_WR", "KBASE_REG_GPU_RD", "KBASE_REG_CPU_RD", "BASE_MEM_", "VM_", "PROT_"))
                ctype = "permission_mismatch" if any(token in body for token in ("GPU_WR", "CPU_WR", "GPU_RD", "CPU_RD")) else "flag_semantic_bug"
                desc = "The function appears to validate access using one permission or flag domain while later behavior depends on a different permission, flag, or semantic condition."
                candidates.append({
                    "function_name": function_name,
                    "line": line,
                    "type": ctype,
                    "mechanism": "permission_domain_mismatch",
                    "severity": "high",
                    "description": desc,
                    "locality": "local_direct",
                    "primary": True,
                    "cross_file_concern": False,
                    "code_snippet": _line_context_from_content(file_content, line, context=4),
                    "investigation_hints": [f"{function_name}(", "permission", "flags", "GPU_WR", "CPU_WR", "BASE_MEM_"],
                    "driver_context": True,
                })

        if any(token in body for token in ("gpu_mappings", "refcount", "mapping_count", "alias", "evictable", "DONT_NEED", "NO_USER_FREE", "shrink", "free", "remove")):
            if any(token in body for token in ("alias", "gpu_mappings", "refcount", "mapping_count")):
                line = start_line + _find_first_matching_line(body_lines, ("gpu_mappings", "refcount", "mapping_count", "alias", "evictable", "DONT_NEED", "NO_USER_FREE"))
                ctype = "accounting_mismatch"
                desc = "The function mutates or relies on allocation/accounting state in a way that may let aliases, mappings, or lifetime counters drift out of sync with the real backing object lifecycle."
                if any(token in body for token in ("alias", "NO_USER_FREE", "gpu_mappings")):
                    ctype = "lifetime_invariant_break"
                    desc = "The function combines alias/mapping state with free, shrink, or eviction behavior in a way that may break lifetime invariants between a source object and derived mappings."
                candidates.append({
                    "function_name": function_name,
                    "line": line,
                    "type": ctype,
                    "mechanism": "accounting_drift",
                    "severity": "high",
                    "description": desc,
                    "locality": "local_direct",
                    "primary": True,
                    "cross_file_concern": False,
                    "code_snippet": _line_context_from_content(file_content, line, context=4),
                    "investigation_hints": [f"{function_name}(", "gpu_mappings", "alias", "refcount", "NO_USER_FREE", "DONT_NEED"],
                    "driver_context": True,
                })

        nested_locks = body.count("mutex_lock(") + body.count("spin_lock(") + body.count("spin_lock_irqsave(") + body.count("mutex_lock_nested(")
        if nested_locks >= 2 and any(token in body for token in ("callback", "queue_work", "timer", "trace", "irq", "worker")):
            line = start_line + _find_first_matching_line(body_lines, ("mutex_lock(", "spin_lock(", "spin_lock_irqsave(", "mutex_lock_nested("))
            candidates.append({
                "function_name": function_name,
                "line": line,
                "type": "lock_order_inversion",
                "mechanism": "lock_order",
                "severity": "medium",
                "description": "The function acquires multiple locks in logic that also interacts with callbacks, timers, workers, or IRQ paths, which is a classic setup for lock-order inversion or deadlock across codepaths.",
                "locality": "cross_file",
                "primary": True,
                "cross_file_concern": True,
                "code_snippet": _line_context_from_content(file_content, line, context=4),
                "investigation_hints": [f"{function_name}(", "mutex_lock(", "spin_lock(", "callback", "worker"],
                "driver_context": True,
            })

        if errorish:
            for acquire_tokens, release_tokens, mechanism, description in acquire_release_specs:
                if any(token in body for token in acquire_tokens) and not any(token in body for token in release_tokens):
                    line = start_line + _find_first_matching_line(body_lines, acquire_tokens)
                    candidates.append({
                        "function_name": function_name,
                        "line": line,
                        "mechanism": mechanism,
                        "severity": "high",
                        "description": description,
                        "locality": "local_direct",
                        "primary": True,
                        "cross_file_concern": False,
                        "code_snippet": _line_context_from_content(file_content, line, context=4),
                        "investigation_hints": _merge_hint_lists([f"{function_name}("], list(acquire_tokens), list(release_tokens)),
                        "driver_context": True,
                    })
    return _prune_audit_candidates(candidates, limit=25)

def _detect_stale_after_unlock_candidates(file_path, file_content):
    if not _looks_driver_file(file_path, file_content):
        return []
    candidates = []
    unlock_tokens = ("mutex_unlock(", "spin_unlock(", "spin_unlock_irqrestore(", "up_write(", "up_read(")
    relock_tokens = ("mutex_lock(", "spin_lock(", "spin_lock_irqsave(", "down_write(", "down_read(")
    assign_re = re.compile(r"\b([A-Za-z_]\w*)\s*=\s*[^;]*(?:->|\.)")
    for function_name, start_line, body_lines in _collect_function_bodies(file_content):
        body = "\n".join(body_lines)
        if not any(t in body for t in unlock_tokens) or not any(t in body for t in relock_tokens):
            continue
        if body.find("unlock") > body.rfind("lock"):
            continue
        before_unlock = []
        found_unlock = False
        relock_seen = False
        stale_var = None
        for line in body_lines:
            if not found_unlock:
                for m in assign_re.finditer(line):
                    before_unlock.append(m.group(1))
                if any(t in line for t in unlock_tokens):
                    found_unlock = True
            else:
                if any(t in line for t in relock_tokens):
                    relock_seen = True
                if relock_seen:
                    for var in before_unlock[-8:]:
                        if re.search(r"\b" + re.escape(var) + r"\b", line):
                            stale_var = var
                            break
            if stale_var:
                break
        if stale_var:
            line = start_line + _find_first_matching_line(body_lines, unlock_tokens)
            candidates.append({
                "function_name": function_name,
                "line": line,
                "type": "lifetime_invariant_break",
                "mechanism": "stale_after_unlock",
                "severity": "high",
                "description": "The function saves pointer- or state-derived locals, drops a lock, later reacquires synchronization, and appears to reuse the stale local without refreshing it, which can make the later access inconsistent with current object lifetime.",
                "locality": "local_direct",
                "primary": True,
                "cross_file_concern": False,
                "code_snippet": _line_context_from_content(file_content, line, context=5),
                "investigation_hints": [f"{function_name}(", stale_var, "unlock", "lock"],
                "driver_context": True,
            })
    return _prune_audit_candidates(candidates, limit=10)

def _detect_width_mismatch_candidates(file_path, file_content):
    candidates = []
    for function_name, start_line, body_lines in _collect_function_bodies(file_content):
        body = "\n".join(body_lines)
        if not any(tok in body for tok in ("u32", "uint32_t", "32-bit", "U32")):
            continue
        if not any(tok in body for tok in ("u64", "uint64_t", "64-bit", "U64")):
            continue
        if not any(tok in body for tok in ("mapping_get", "phy_alloc", "wait", "set", "error", "value", "addr", "field")):
            continue
        line = start_line + _find_first_matching_line(body_lines, ("u32", "uint32_t", "u64", "uint64_t"))
        candidates.append({
            "function_name": function_name,
            "line": line,
            "type": "out_of_bounds",
            "mechanism": "width_mismatch_second_access",
            "severity": "high",
            "description": "The function mixes 32-bit and 64-bit views of mapped or structured data, which is a classic signal that one checked access may be followed by a stronger or wider second access without proving the object is large enough.",
            "locality": "local_direct",
            "primary": True,
            "cross_file_concern": False,
            "code_snippet": _line_context_from_content(file_content, line, context=5),
            "investigation_hints": [f"{function_name}(", "u32", "u64", "error", "value"],
            "driver_context": _looks_driver_file(file_path, file_content),
            "compiler_context": _looks_compilerish_file(file_path, file_content),
        })
    return _prune_audit_candidates(candidates, limit=10)

def _detect_fileops_candidates(file_path, file_content):
    if not _looks_driver_file(file_path, file_content):
        return []
    candidates = []
    if "struct file_operations" not in file_content:
        return []
    lines = file_content.splitlines()
    for idx, line in enumerate(lines):
        if "struct file_operations" not in line:
            continue
        window = "\n".join(lines[idx:min(len(lines), idx + 80)])
        has_release = ".release" in window
        has_flush = ".flush" in window
        has_poll = ".poll" in window
        has_open = ".open" in window
        if has_release and not has_flush:
            candidates.append({
                "function_name": "file_operations",
                "line": idx + 1,
                "type": "lifetime_invariant_break",
                "mechanism": "file_ops_lifecycle_gap",
                "severity": "high",
                "description": "The file_operations table defines release-time teardown but omits flush handling, which can leave shared file-descriptor or duplicate-descriptor lifetimes mismatched with object teardown.",
                "locality": "cross_file",
                "primary": True,
                "cross_file_concern": True,
                "code_snippet": _line_context_from_content(file_content, idx + 1, context=6),
                "investigation_hints": ["struct file_operations", ".release", ".flush", ".poll"],
                "driver_context": True,
            })
        if has_poll and has_release and has_open:
            candidates.append({
                "function_name": "file_operations",
                "line": idx + 1,
                "type": "lifetime_invariant_break",
                "mechanism": "file_ops_lifecycle_gap",
                "severity": "medium",
                "description": "The file_operations table exposes open/poll/release style entry points that may race unless the same object lifetime is guarded consistently across flush, poll, and teardown paths.",
                "locality": "cross_file",
                "primary": False,
                "cross_file_concern": True,
                "code_snippet": _line_context_from_content(file_content, idx + 1, context=6),
                "investigation_hints": ["struct file_operations", ".poll", ".release", ".open", ".flush"],
                "driver_context": True,
            })
        break
    return _prune_audit_candidates(candidates, limit=8)

def _detect_logging_candidates(file_path, file_content):
    candidates = []
    log_tokens = ("printk(", "dev_err(", "dev_warn(", "pr_err(", "pr_warn(", "trace_", "seq_printf(")
    leak_tokens = ("%pa", "%pap", "%px", "%pK", "%llx", "phys", "physical", "fault->addr", "bus_fault", "gpu_fault", "addr")
    lines = file_content.splitlines()
    for idx, line in enumerate(lines):
        if any(tok in line for tok in log_tokens) and any(tok in line for tok in leak_tokens):
            function_name = _function_name_for_line(_collect_function_starts(lines), idx + 1)
            candidates.append({
                "function_name": function_name,
                "line": idx + 1,
                "type": "information_disclosure",
                "mechanism": "info_leak_logging",
                "severity": "medium",
                "description": "Logging in the target file appears to print raw fault or address information in a way that may disclose sensitive internal or physical-address state.",
                "locality": "local_direct",
                "primary": True,
                "cross_file_concern": False,
                "code_snippet": _line_context_from_content(file_content, idx + 1, context=4),
                "investigation_hints": [f"{function_name}(", "printk", "dev_err", "%pa", "%px", "fault"],
                "driver_context": _looks_driver_file(file_path, file_content),
            })
    return _prune_audit_candidates(candidates, limit=8)

def _detect_compiler_semantic_candidates(file_path, file_content):
    if not _looks_compilerish_file(file_path, file_content):
        return []
    candidates = []
    for function_name, start_line, body_lines in _collect_function_bodies(file_content):
        body = "\n".join(body_lines)
        if not any(tok in body.lower() for tok in ("matrix", "vector", "constructor", "column", "row")):
            continue
        if not any(tok in body for tok in ("rows", "cols", "columns", "elements", "expr.u.value", "alloc", "malloc", "calloc", "new ")):
            continue
        if body.count("for (") == 0 and body.count("while (") == 0:
            continue
        line = start_line + _find_first_matching_line(body_lines, ("matrix", "vector", "constructor", "column", "row"))
        candidates.append({
            "function_name": function_name,
            "line": line,
            "type": "out_of_bounds",
            "mechanism": "compiler_shape_mismatch",
            "severity": "high",
            "description": "The function appears to allocate or synthesize matrix/vector/container storage using one shape or dimension and later iterate or write using a different dimension, which is a common compiler/front-end bounds bug.",
            "locality": "local_direct",
            "primary": True,
            "cross_file_concern": False,
            "code_snippet": _line_context_from_content(file_content, line, context=5),
            "investigation_hints": [f"{function_name}(", "matrix", "row", "column", "constructor", "expr.u.value"],
            "compiler_context": True,
        })
    return _prune_audit_candidates(candidates, limit=10)

def _candidate_is_local_direct(candidate):
    if str(candidate.get("locality") or "").strip() == "local_direct":
        return True
    return str(candidate.get("type") or "").strip() in {
        "command_injection", "buffer_overflow", "sscanf_overflow", "path_traversal",
        "format_string", "integer_overflow", "out_of_bounds", "null_deref",
        "state_transition_bug", "stale_state", "ordering_race", "teardown_race",
        "deferred_work_uaf", "cleanup_asymmetry", "partial_failure_cleanup",
        "permission_mismatch", "flag_semantic_bug", "accounting_mismatch",
        "lifetime_invariant_break", "rollback_invariant_bug", "information_disclosure",
    }


# Graph builder


_EXTRACTION_SYSTEM_PROMPT = """\
You are a C and C++ static analysis tool. Analyze the following source file and \
extract ALL function definitions with their security relevant metadata.

For each function defined in this file (with body), provide:
1. \"name\": the function name
2. \"line\": line number where the function definition starts
3. \"calls\": list of ALL function and macro names called inside this function body
4. \"is_source\": true if this function directly receives or processes external/untrusted input
5. \"source_reason\": if is_source, briefly explain why
6. \"is_sink\": true if this function performs operations that could be dangerous with attacker-controlled input
7. \"sink_type\": if is_sink, one of: buffer_overflow, use_after_free, double_free, null_deref, \
command_injection, format_string, integer_overflow, path_traversal, race_condition, \
uninitialized_memory, type_confusion, out_of_bounds, other
8. \"sink_reason\": if is_sink, briefly explain the danger

Source indicators — mark is_source=true when a function:
- Reads from stdin, files, network sockets, pipes, IPC
- Processes command-line arguments (argc/argv) or environment variables
- Is a callback or handler for external events
- Is main() or an entry point that receives external parameters

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

A function CAN be both a source and a sink.
Do NOT include mere declarations/prototypes (no body).
DO include static, inline, and helper functions.

Return ONLY valid JSON:
{\"functions\": [{\"name\": \"example\", \"line\": 1, \"calls\": [], \"is_source\": false, \
\"source_reason\": \"\", \"is_sink\": false, \"sink_type\": \"\", \"sink_reason\": \"\"}]}

If the file has no function definitions, return: {\"functions\": []}"""

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
                    for n in fut.result(): graph.add_node(n)
                except Exception as e: errors.append(f"{os.path.basename(fp)}: {e}")
                if progress_callback: progress_callback({"event": "extraction_progress", "completed": done, "total": total, "file": fp})
        graph.resolve_all_calls()
        if progress_callback:
            progress_callback({"event": "extraction_done", "nodes": graph.node_count(), "edges": graph.edge_count(),
                "sources": len(graph.get_sources()), "sinks": len(graph.get_sinks()), "errors": errors})
        return graph

    def _extract(self, file_path, codebase_path):
        content = read_file_content(file_path)
        if not content or not content.strip(): return []
        base = os.path.abspath(codebase_path)
        rel = os.path.relpath(file_path, base)
        kw = self._u.hooks.chat_model_kwargs()
        chat = self._p.get_chat_model(model=self._m, max_tokens=self._t, temperature=0.0, **kw)
        prompt = ChatPromptTemplate.from_messages([("system", _EXTRACTION_SYSTEM_PROMPT), ("user", _EXTRACTION_USER_TEMPLATE)])
        raw = (prompt | chat | StrOutputParser()).invoke({"file_path": rel, "file_content": _number_lines(content)}).strip()
        parsed = parse_json_output(raw)
        if not isinstance(parsed, dict): return []
        fns = parsed.get("functions")
        if not isinstance(fns, list): return []
        nodes, seen = [], set()
        for e in fns:
            if not isinstance(e, dict): continue
            name = str(e.get("name") or "").strip()
            if not name: continue
            u = f"{rel}::{name}"
            if u in seen: continue
            seen.add(u)
            calls = [str(c).strip() for c in (e.get("calls") or []) if str(c).strip()]
            line = 1
            try: line = max(1, int(e.get("line", 1)))
            except: pass
            nodes.append(FunctionNode(
                unique_name=u, file_path=rel, name=name, line_number=line,
                is_source=bool(e.get("is_source")), is_sink=bool(e.get("is_sink")),
                calls=calls, source_reason=str(e.get("source_reason") or ""),
                sink_type=str(e.get("sink_type") or ""), sink_reason=str(e.get("sink_reason") or "")))
        return nodes


# path tracer

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


# reachability confirmer, at this point we should already have a pretty good idea of the vulnerable paths, 
# so we can use the LLM to confirm if they are likely to be true positives or not, and also to provide more context and evidence for each finding. 
# The idea is that this can help prioritize the findings and reduce false positives.

_CONFIRM_SYS = """\
You are a security researcher specializing in C and C++ code analysis.
You are given reachable call paths from attacker input sources to flagged sinks, with relevant source code.
For EACH path determine if it is a real exploitable vulnerability:
1. Does attacker input actually propagate through every hop?
2. Are there sanitization or bounds checks?
3. Is the sink truly dangerous as called?
4. Identify the PRIMARY bug mechanism separately from the final vulnerability label. \
Mechanism examples: state_transition, ordering_gap, partial_cleanup, rollback_gap, stale_after_unlock, \
permission_domain_mismatch, deferred_callback_after_teardown, accounting_drift, lock_order, \
info_leak_logging, width_mismatch_second_access, file_ops_lifecycle_gap, generic_memory.
Return ONLY valid JSON:
{\"findings\": [{\"path_index\": 0, \"is_vulnerable\": true, \"mechanism\": \"generic_memory\", \
\"vulnerability_type\": \"buffer_overflow\", \"severity\": \"high\", \"confidence\": \"high\", \
\"description\": \"...\", \"root_cause\": \"...\", \"evidence\": \"...\"}]}
severity: critical, high, medium, low. confidence: high, medium, low. Be conservative."""

_CONFIRM_USR = "{paths_section}\n\n{code_section}"

_FILE_CONFIRM_SYS = """\
You are a security researcher specializing in C and C++ code analysis.
You are reviewing ONE target file from a larger codebase.
You are given:
- reachable call paths from external or attacker-controlled sources
- the relevant code from the target file
- supporting code for upstream/downstream functions on the path
Only report a vulnerability when the primary bug mechanism is actually present in the TARGET FILE code shown.
For EACH path determine if it is a real exploitable vulnerability in the target file:
1. Does attacker input actually propagate through the path into the target file logic?
2. Does the target file contain the missing validation, unsafe state transition, or dangerous sink usage?
3. Are there checks or lifecycle constraints that make the path non-exploitable?
4. Is the root cause in the target file rather than merely elsewhere on the path?
5. Identify the PRIMARY mechanism separately from the final vulnerability label.
Return ONLY valid JSON:
{\"findings\": [{\"path_index\": 0, \"is_vulnerable\": true, \"mechanism\": \"state_transition\", \
\"vulnerability_type\": \"state_transition_bug\", \"severity\": \"high\", \"confidence\": \"high\", \
\"description\": \"...\", \"root_cause\": \"...\", \"evidence\": \"...\"}]}
severity: critical, high, medium, low. confidence: high, medium, low. Be conservative."""

_FILE_CONFIRM_USR = """Target file: {target_file}
{paths_section}
== TARGET FILE CODE ==
{target_file_code}
== RELATED PATH CODE ==
{related_code_section}
"""

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
- A file_operations/vtable shape leaves one lifetime path unimplemented or inconsistent

For each finding, identify both the focus-file function involved AND the caller \
function in the other file where the misuse occurs.

Return ONLY valid JSON:
{\"findings\": [{\"path_index\": 0, \"is_vulnerable\": true, \"mechanism\": \"file_ops_lifecycle_gap\", \
\"vulnerability_type\": \"lifetime_invariant_break\", \"severity\": \"high\", \"confidence\": \"high\", \
\"description\": \"...\", \"root_cause\": \"...\", \"evidence\": \"...\"}]}
severity: critical, high, medium, low. confidence: high, medium, low."""

_CROSS_FILE_USR = """Focus file: {target_file}

{paths_section}

== FOCUS FILE CODE (functions defined here) ==
{target_file_code}

== CALLER CODE (other files that use the focus file's functions) ==
{related_code_section}
"""

_LOCAL_CONFIRM_SYS = """\
You are a security researcher confirming a single candidate vulnerability in one C/C++ source file.

For obvious unsafe sink patterns in the target file, you may conclude based on the target file alone.
Do NOT require repo-level proof of attacker reachability when the target file itself shows a classic,
direct vulnerability pattern such as:
- std::system/popen/exec with variable or attacker-controlled data in the command string
- sprintf/strcpy/strcat/gets/scanf %s into fixed or caller-sized buffers without bounds checks
- filesystem path construction from variable input followed by file open without validation
- direct format-string use of attacker-controlled data
- direct integer-overflow-prone allocation math in the same function
- deferred work, timers, or callbacks that can still run after free/termination because cancel/sync is missing
- partial-failure cleanup where pages, mappings, timers, work items, or inserted state are not unwound
- wrong permission/flag validation where the check does not protect the later behavior actually performed
- invalid state transitions where the code exposes, preserves, or fails to clear lifecycle-critical state
- unsafe ordering of power/reset/MMU/cache/fault-handling operations that leaves partially transitioned state visible
- stale locals reused after unlock/relock
- logging that discloses sensitive fault or physical-address information
- file_operations tables whose lifetime callbacks are clearly incomplete in the same file

Prefer the PRIMARY direct bug over speculative secondary issues.
For example, if a function constructs a shell command from variable input and calls system(),
prefer command_injection over toctou.

Only reject the candidate if clear mitigation is visible in the shown code.
Return ONLY valid JSON:
{\"verdict\": {
  \"is_vulnerable\": true,
  \"mechanism\": \"generic_memory\",
  \"vulnerability_type\": \"command_injection\",
  \"severity\": \"high\",
  \"confidence\": \"high\",
  \"function_name\": \"SendReport\",
  \"line\": 0,
  \"description\": \"...\",
  \"root_cause\": \"...\",
  \"evidence\": \"...\",
  \"reachability_chain\": \"Target file local path\"
}}

Set is_vulnerable to false only if the shown code clearly mitigates the issue."""

_LOCAL_CONFIRM_USR = """Candidate type: {candidate_type}
Candidate mechanism: {candidate_mechanism}
Candidate description: {candidate_description}
Function: {function_name}
Line: {line}

== TARGET FILE CODE ==
{target_file_code}

== LOCAL CONTEXT ==
{local_context}
"""


class VulnerabilityConfirmer:
    def __init__(self, llm_provider, model, usage_runtime, codebase_path, max_tokens=4096):
        self._p = llm_provider; self._m = model; self._u = usage_runtime
        self._cb = os.path.abspath(codebase_path); self._t = max_tokens

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
                    except Exception as e: logger.warning("Confirm fail %s: %s", sn, e)
                    with lock: done[0] += 1
                    if progress_callback: progress_callback({"event": "confirmation_progress", "completed": done[0], "total": total, "sink": sn})
        finally:
            if fh: fh.close()
        if progress_callback: progress_callback({"event": "confirmation_done", "confirmed": len(all_f)})
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
        kw = self._u.hooks.chat_model_kwargs()
        chat = self._p.get_chat_model(model=self._m, max_tokens=self._t, temperature=0.1, **kw)
        prompt = ChatPromptTemplate.from_messages([("system", _CONFIRM_SYS), ("user", _CONFIRM_USR)])
        raw = (prompt | chat | StrOutputParser()).invoke({"paths_section": "\n".join(ps), "code_section": "\n".join(cs)}).strip()
        return self._parse_confirm(raw, batch, graph)

    def _parse_confirm(self, raw, batch, graph):
        parsed = parse_json_output(raw)
        if not isinstance(parsed, dict): return []
        fl = parsed.get("findings")
        if not isinstance(fl, list): return []
        results = []
        for e in fl:
            if not isinstance(e, dict) or not e.get("is_vulnerable"): continue
            idx = int(e.get("path_index", -1))
            if idx < 0 or idx >= len(batch): continue
            rp = batch[idx]; sn = graph.get_node(rp.source); sk = graph.get_node(rp.sink)
            mechanism = _normalize_mechanism(e.get("mechanism"), e.get("vulnerability_type") or rp.sink_type)
            vtype = _resolve_vulnerability_type(mechanism, e.get("vulnerability_type") or rp.sink_type or "other")
            results.append(VulnerabilityFinding(
                id=uuid.uuid4().hex[:16], vulnerability_type=vtype,
                severity=str(e.get("severity") or "medium"), confidence=str(e.get("confidence") or "medium"),
                source_function=rp.source, source_file=sn.file_path if sn else "", source_line=sn.line_number if sn else 0,
                sink_function=rp.sink, sink_file=sk.file_path if sk else "", sink_line=sk.line_number if sk else 0,
                path=list(rp.path), description=str(e.get("description") or ""),
                root_cause=str(e.get("root_cause") or ""), evidence=str(e.get("evidence") or ""), analysis_type="reachability",
                mechanism=mechanism, mechanism_family=_mechanism_family(mechanism, vtype)))
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
        kw = self._u.hooks.chat_model_kwargs()
        chat = self._p.get_chat_model(model=self._m, max_tokens=self._t, temperature=0.1, **kw)
        prompt = ChatPromptTemplate.from_messages([("system", _FILE_CONFIRM_SYS), ("user", _FILE_CONFIRM_USR)])
        raw = (prompt | chat | StrOutputParser()).invoke({
            "target_file": target_file, "paths_section": "\n".join(ps),
            "target_file_code": "\n".join(tc), "related_code_section": "\n".join(rc)}).strip()
        return self._parse_confirm(raw, batch, graph)

    def confirm_cross_file(self, target_file, paths, graph, *, max_workers=4, progress_callback=None):
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
                if n.file_path == target_file: target_nodes[u] = n
                else: caller_nodes[u] = n
        if not target_nodes or not caller_nodes: return []
        ps = ["== PATHS INVOLVING FOCUS FILE FUNCTIONS =="]
        for i, p in enumerate(batch):
            sn, sk = graph.get_node(p.source), graph.get_node(p.sink)
            ps.append(f"\nPath {i}:\n Chain: {' -> '.join(p.path)}")
            if sn: ps.append(f" Source: {sn.unique_name} (line {sn.line_number}) - {sn.source_reason}")
            if sk: ps.append(f" Sink: {sk.unique_name} (line {sk.line_number}) [{sk.sink_type}] - {sk.sink_reason}")
            focus_fns = [u for u in p.path if graph.get_node(u) and graph.get_node(u).file_path == target_file]
            if focus_fns: ps.append(f" Focus-file functions on this path: {', '.join(focus_fns)}")
        tc = ["-- FOCUS FILE: functions defined here --"]
        for u, n in target_nodes.items():
            body = _read_function_body(self._cb, n, 5000)
            if body: tc.append(f"\n--- {u} (line {n.line_number}) ---\n{body}")
        rc = ["-- CALLERS: code in other files that uses focus-file functions --"]
        for u, n in caller_nodes.items():
            body = _read_function_body(self._cb, n, 3000)
            if body: rc.append(f"\n--- {u} (line {n.line_number} in {n.file_path}) ---\n{body}")
        kw = self._u.hooks.chat_model_kwargs()
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
            idx = int(e.get("path_index", -1))
            if idx < 0 or idx >= len(batch): continue
            rp = batch[idx]; sn = graph.get_node(rp.source); sk = graph.get_node(rp.sink)
            focus_fn = None
            for u in rp.path:
                n = graph.get_node(u)
                if n and n.file_path == target_file: focus_fn = n; break
            sink_file = target_file
            sink_fn = focus_fn.unique_name if focus_fn else rp.sink
            sink_line = focus_fn.line_number if focus_fn else (sk.line_number if sk else 0)
            mechanism = _normalize_mechanism(e.get("mechanism"), e.get("vulnerability_type"))
            vtype = _resolve_vulnerability_type(mechanism, e.get("vulnerability_type") or "other")
            results.append(VulnerabilityFinding(
                id=uuid.uuid4().hex[:16], vulnerability_type=vtype,
                severity=str(e.get("severity") or "medium"), confidence=str(e.get("confidence") or "medium"),
                source_function=rp.source, source_file=sn.file_path if sn else "",
                source_line=sn.line_number if sn else 0,
                sink_function=sink_fn, sink_file=sink_file, sink_line=sink_line,
                path=list(rp.path), description=str(e.get("description") or ""),
                root_cause=str(e.get("root_cause") or ""), evidence=str(e.get("evidence") or ""),
                analysis_type="cross_file", mechanism=mechanism, mechanism_family=_mechanism_family(mechanism, vtype)))
        return results

    def confirm_local_candidate(self, candidate, target_file, target_file_content):
        kw = self._u.hooks.chat_model_kwargs()
        chat = self._p.get_chat_model(model=self._m, max_tokens=self._t, temperature=0.1, **kw)
        local_context = str(candidate.get("code_snippet") or "")
        if not local_context:
            local_context = _line_context_from_content(target_file_content, candidate.get("line") or 1, context=5)
        local_context = local_context[:6000] if len(local_context) > 6000 else local_context

        target_payload = _build_prompt_ready_file_content(
            target_file,
            target_file_content,
            focus_function=str(candidate.get("function_name") or "unknown"),
            focus_line=int(candidate.get("line") or 1),
            max_chars=_REVIEW_FILE_LOCAL_PROMPT_BUDGET,
        )

        prompt = ChatPromptTemplate.from_messages([("system", _LOCAL_CONFIRM_SYS), ("user", _LOCAL_CONFIRM_USR)])
        raw = (prompt | chat | StrOutputParser()).invoke({
            "candidate_type": str(candidate.get("type") or "other"),
            "candidate_mechanism": str(candidate.get("mechanism") or "generic_memory"),
            "candidate_description": str(candidate.get("description") or ""),
            "function_name": str(candidate.get("function_name") or "unknown"),
            "line": int(candidate.get("line") or 1),
            "target_file_code": target_payload,
            "local_context": local_context,
        }).strip()
        return _parse_verdict_payload(raw)


# supplementary analyzer, only for review code for now


_RESOURCE_KW = frozenset({"free", "malloc", "calloc", "realloc", "close", "destroy", "release", "delete", "munmap", "unref", "grow", "compact", "resize"})
_AUTH_KW = frozenset({"auth", "login", "check", "verify", "compare", "validate", "token", "password", "permit", "deny", "match", "level", "permission"})

_INTRA_SYS = """\
You are a C/C++ vulnerability expert. Examine each function below for bugs WITHIN the function itself.
Look for:
1. DOUBLE-FREE / DOUBLE-CLOSE: Can any path free/close the same resource twice? goto to cleanup that frees something already freed.
2. AUTH / COMPARISON LOGIC ERRORS: Is the CORRECT string used for length? Can empty input bypass a check?
3. INTEGER OVERFLOW IN SIZE CALCULATIONS: Can (count * sizeof(T)) wrap size_t? Struct sizes are often 100-2000 bytes!
4. ARRAY INDEX OUT OF BOUNDS: arr[flags & 0x0F] with arr[4] — mask allows 0-15.
5. RESOURCE LEAKS on error paths.
Return ONLY valid JSON:
{\"findings\": [{\"vulnerability_type\": \"double_free\", \"severity\": \"high\", \"confidence\": \"high\", \
\"function_name\": \"handle_set\", \"line\": 55, \"description\": \"...\", \"root_cause\": \"...\", \"evidence\": \"...\"}]}
Return {\"findings\": []} if none found. Be thorough."""

_INTRA_USR = "File: {file_path}\n\n{functions_code}"

_LIFE_SYS = """\
You are analyzing a C/C++ codebase for USE-AFTER-FREE, DANGLING POINTER, and LIFETIME bugs spanning MULTIPLE functions.
Below are ALL functions. Analyze their INTERACTIONS:
1. USE-AFTER-FREE: Function A frees a resource, Function B later dereferences it.
2. DANGLING POINTERS: Pointers in global/shared structures not NULLed when target freed.
3. LIFETIME MISMATCH: Object A stores pointer to B, but B can be destroyed while A exists.
Return ONLY valid JSON:
{\"findings\": [{\"vulnerability_type\": \"use_after_free\", \"severity\": \"high\", \"confidence\": \"high\", \
\"free_function\": \"session_close\", \"use_function\": \"store_lookup\", \
\"description\": \"...\", \"root_cause\": \"...\", \"evidence\": \"...\"}]}
Return {\"findings\": []} if none found."""

_LIFE_USR = "{all_functions_code}"

_OWN_SYS = """\
You are analyzing a C/C++ codebase for RESOURCE OWNERSHIP, POINTER INVALIDATION, and CLEANUP COORDINATION bugs.
Examine ALL functions below for:
1. DOUBLE-FREE / DOUBLE-CLOSE ACROSS FUNCTIONS: Function A frees on error, caller also frees.
2. USE-AFTER-REALLOC / STALE POINTERS: Code caches pointer then calls function that may realloc/grow/compact.
3. CALLBACK / REGISTRATION LIFECYCLE: Register callback with object as context, free object without unregistering.
4. REFCOUNT IMBALANCE: store_ref then store_unref called unequally.
Return ONLY valid JSON:
{\"findings\": [{\"vulnerability_type\": \"double_free\", \"severity\": \"high\", \"confidence\": \"high\", \
\"function_a\": \"proto_parse\", \"function_b\": \"dispatch\", \
\"description\": \"...\", \"root_cause\": \"...\", \"evidence\": \"...\"}]}
Return {\"findings\": []} if none found."""

_OWN_USR = "{all_functions_code}"

_SEM_SYS = """\
You are analyzing a C/C++ codebase for SEMANTIC, TYPE, and DATA-FLOW correctness bugs.
Examine ALL functions below for:
1. BOOLEAN COERCION OF RICH RETURNS: Function returns level/enum/count, caller checks with if (!func()).
2. WRONG ENUM / CONSTANT: Permission check uses wrong resource type constant.
3. TYPE CONFUSION / VOID* MISCAST: void* from generic store cast without checking type tag.
4. WRONG STRUCT FIELD: raw_len used where data_len needed.
5. FIELD STALENESS AFTER MUTATION: Data sanitized but old length stored — callers use stale length.
6. LENGTH OFF-BY-ONE: title_len = copied + 1 but serialize copies title_len bytes.
7. ARRAY INDEX vs SIZE MISMATCH: arr[flags & 0x0F] where array has fewer than 16 entries.
8. INTEGER OVERFLOW IN ALLOCATION: new_cap * sizeof(large_struct) wraps size_t.
9. UNINITIALIZED DATA EXPOSURE: malloc + partial init + memcpy entire struct to network.
Return ONLY valid JSON:
{\"findings\": [{\"vulnerability_type\": \"boolean_coercion\", \"severity\": \"high\", \"confidence\": \"high\", \
\"function_name\": \"dispatch\", \"related_function\": \"auth_get_level\", \
\"description\": \"...\", \"root_cause\": \"...\", \"evidence\": \"...\"}]}
Return {\"findings\": []} if none found. Be EXTREMELY thorough."""

_SEM_USR = "{all_functions_code}"


class SupplementaryAnalyzer:
    def __init__(self, llm_provider, audit_model, strong_model, usage_runtime, codebase_path,
                 audit_max_tokens=8192, strong_max_tokens=16384):
        self._p = llm_provider; self._am = audit_model; self._sm = strong_model
        self._u = usage_runtime; self._cb = os.path.abspath(codebase_path)
        self._at = audit_max_tokens; self._st = strong_max_tokens

    def analyze(self, graph, *, max_workers=8, progress_callback=None):
        findings = []
        findings.extend(self._pass_intra(graph, max_workers, progress_callback))
        findings.extend(self._pass_lifecycle(graph, progress_callback))
        findings.extend(self._pass_ownership(graph, progress_callback))
        findings.extend(self._pass_semantic(graph, progress_callback))
        if progress_callback:
            by_type = defaultdict(int)
            for f in findings: by_type[f.analysis_type] += 1
            progress_callback({"event": "supplementary_done", **dict(by_type), "total": len(findings)})
        return findings

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
        seen, targets = set(), []
        for n in graph.nodes.values():
            nl = n.name.lower(); cl = [c.lower() for c in n.calls]; ac = nl + " " + " ".join(cl)
            if n.is_sink or n.is_source or any(k in ac for k in _RESOURCE_KW) or any(k in ac for k in _AUTH_KW) or "goto" in ac:
                if n.unique_name not in seen: seen.add(n.unique_name); targets.append(n)
        return targets

    def _audit_file(self, file_path, functions):
        bodies = []
        for fn in functions:
            b = _read_function_body(self._cb, fn, 4096)
            if b: bodies.append(f"--- {fn.unique_name} (line {fn.line_number}) ---\n{b}")
        if not bodies: return []
        kw = self._u.hooks.chat_model_kwargs()
        chat = self._p.get_chat_model(model=self._am, max_tokens=self._at, temperature=0.1, **kw)
        prompt = ChatPromptTemplate.from_messages([("system", _INTRA_SYS), ("user", _INTRA_USR)])
        raw = (prompt | chat | StrOutputParser()).invoke({"file_path": file_path, "functions_code": "\n\n".join(bodies)}).strip()
        return self._parse_intra(raw, functions)

    def _parse_intra(self, raw, functions):
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
            vtype = str(e.get("vulnerability_type") or "other")
            mechanism = _normalize_mechanism(e.get("mechanism"), vtype)
            results.append(VulnerabilityFinding(
                id=uuid.uuid4().hex[:16], vulnerability_type=_resolve_vulnerability_type(mechanism, vtype),
                severity=str(e.get("severity") or "medium"), confidence=str(e.get("confidence") or "medium"),
                source_function=fn.unique_name, source_file=fn.file_path, source_line=line,
                sink_function=fn.unique_name, sink_file=fn.file_path, sink_line=line,
                path=[fn.unique_name], description=str(e.get("description") or ""),
                root_cause=str(e.get("root_cause") or ""), evidence=str(e.get("evidence") or ""),
                analysis_type="intra_function", mechanism=mechanism, mechanism_family=_mechanism_family(mechanism, vtype)))
        return results

    def _pass_lifecycle(self, graph, cb):
        fns = list(graph.nodes.values())
        if not fns: return []
        if cb: cb({"event": "lifecycle_audit_start", "functions": len(fns)})
        code = _build_all_code(self._cb, fns)
        if not code: return []
        kw = self._u.hooks.chat_model_kwargs()
        chat = self._p.get_chat_model(model=self._sm, max_tokens=self._st, temperature=0.1, **kw)
        prompt = ChatPromptTemplate.from_messages([("system", _LIFE_SYS), ("user", _LIFE_USR)])
        raw = (prompt | chat | StrOutputParser()).invoke({"all_functions_code": code}).strip()
        results = self._parse_cross(raw, fns, "lifecycle", "free_function", "use_function")
        if cb: cb({"event": "lifecycle_audit_done", "findings": len(results)})
        return results

    def _pass_ownership(self, graph, cb):
        fns = list(graph.nodes.values())
        if not fns: return []
        if cb: cb({"event": "ownership_audit_start", "functions": len(fns)})
        code = _build_all_code(self._cb, fns)
        if not code: return []
        kw = self._u.hooks.chat_model_kwargs()
        chat = self._p.get_chat_model(model=self._sm, max_tokens=self._st, temperature=0.1, **kw)
        prompt = ChatPromptTemplate.from_messages([("system", _OWN_SYS), ("user", _OWN_USR)])
        raw = (prompt | chat | StrOutputParser()).invoke({"all_functions_code": code}).strip()
        results = self._parse_cross(raw, fns, "ownership", "function_a", "function_b")
        if cb: cb({"event": "ownership_audit_done", "findings": len(results)})
        return results

    def _pass_semantic(self, graph, cb):
        fns = list(graph.nodes.values())
        if not fns: return []
        if cb: cb({"event": "semantic_audit_start", "functions": len(fns)})
        code = _build_all_code(self._cb, fns)
        if not code: return []
        kw = self._u.hooks.chat_model_kwargs()
        chat = self._p.get_chat_model(model=self._sm, max_tokens=self._st, temperature=0.1, **kw)
        prompt = ChatPromptTemplate.from_messages([("system", _SEM_SYS), ("user", _SEM_USR)])
        raw = (prompt | chat | StrOutputParser()).invoke({"all_functions_code": code}).strip()
        results = self._parse_semantic(raw, fns)
        if cb: cb({"event": "semantic_audit_done", "findings": len(results)})
        return results

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
            vtype = str(e.get("vulnerability_type") or "use_after_free")
            mechanism = _normalize_mechanism(e.get("mechanism"), vtype)
            results.append(VulnerabilityFinding(
                id=uuid.uuid4().hex[:16], vulnerability_type=_resolve_vulnerability_type(mechanism, vtype),
                severity=str(e.get("severity") or "high"), confidence=str(e.get("confidence") or "medium"),
                source_function=fa.unique_name, source_file=fa.file_path, source_line=fa.line_number,
                sink_function=fb.unique_name, sink_file=fb.file_path, sink_line=fb.line_number,
                path=[fa.unique_name, fb.unique_name], description=str(e.get("description") or ""),
                root_cause=str(e.get("root_cause") or ""), evidence=str(e.get("evidence") or ""),
                analysis_type=analysis_type, mechanism=mechanism, mechanism_family=_mechanism_family(mechanism, vtype)))
        return results

    def _parse_semantic(self, raw, all_fns):
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
            vtype = str(e.get("vulnerability_type") or "other")
            mechanism = _normalize_mechanism(e.get("mechanism"), vtype)
            results.append(VulnerabilityFinding(
                id=uuid.uuid4().hex[:16], vulnerability_type=_resolve_vulnerability_type(mechanism, vtype),
                severity=str(e.get("severity") or "medium"), confidence=str(e.get("confidence") or "medium"),
                source_function=src_fn.unique_name, source_file=src_fn.file_path, source_line=src_fn.line_number,
                sink_function=fn.unique_name, sink_file=fn.file_path, sink_line=fn.line_number,
                path=[src_fn.unique_name, fn.unique_name] if rf else [fn.unique_name],
                description=str(e.get("description") or ""), root_cause=str(e.get("root_cause") or ""),
                evidence=str(e.get("evidence") or ""), analysis_type="semantic",
                mechanism=mechanism, mechanism_family=_mechanism_family(mechanism, vtype)))
        return results


# deduplicator

class Deduplicator:
    @staticmethod
    def deduplicate(findings, *, max_per_sink=3):
        if not findings: return [], 0, 0
        groups = defaultdict(list)
        for f in findings:
            mechanism_family = getattr(f, "mechanism_family", "") or _mechanism_family(getattr(f, "mechanism", ""), f.vulnerability_type)
            groups[(f.sink_function, mechanism_family)].append(f)
        selected = []
        for g in groups.values(): selected.extend(_select_diverse(g, max_per_sink))
        return selected, len(findings), len(findings) - len(selected)

def _select_diverse(findings, limit):
    if len(findings) <= limit: return list(findings)
    sev = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    fs = sorted(findings, key=lambda f: (
        sev.get(f.severity, 5),
        _ROOT_CAUSE_FAMILY_ORDER_DRIVER.get(getattr(f, "mechanism_family", "") or _mechanism_family(getattr(f, "mechanism", ""), f.vulnerability_type), 50),
        len(f.path)))
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


# service

_FILE_AUDIT_SYS = """\
You are a world-class C/C++ security auditor performing an exhaustive review of a \
single source file from a larger codebase. Your job is to find EVERY potential \
security issue — confirmed bugs AND suspicious patterns that MIGHT be exploitable \
depending on how the rest of the codebase uses this file's functions.

## Categories to check thoroughly

1. MEMORY SAFETY: buffer overflow, heap/stack overflow (including via sscanf %s \
into fixed buffers), use-after-free, double-free, NULL dereference before check, \
out-of-bounds read/write, uninitialized memory exposure
2. RESOURCE MANAGEMENT: file descriptor leaks on error paths, double-close, \
pool_alloc() freed with free() (allocator mismatch), missing cleanup on early return
3. AUTH & ACCESS CONTROL: missing permission/auth checks before privileged operations, \
wrong permission constants (e.g. RES_MSG where RES_CHANNEL needed), boolean coercion \
of rich return values (treating enum/level as bool with if(!func())), ignored return \
values from auth/verify functions, any handler that performs a sensitive action \
without checking the caller's role or auth status
4. DATA FLOW: user-controlled data passed as printf format string, sscanf with \
unbounded %s, sign confusion (int32 vs uint32 vs size_t), integer overflow in \
size calculations (count * sizeof(large_struct))
5. CROSS-FILE HAZARDS — flag these even if you cannot confirm exploitability:
   - Functions that free/close resources (callers may also free/close the same thing)
   - Functions returning pointers to static/global buffers (callers may store the pointer \
     and call the function again, overwriting previous return)
   - Functions with ambiguous ownership on error paths (sometimes frees, sometimes doesn't)
   - Functions whose return values callers might misinterpret
   - Functions that sanitize/transform data without updating length/size metadata
   - Functions that register callbacks/timers but don't unregister on cleanup
   - Functions using pool allocators where callers might use free() instead of pool_free()
6. LOGIC ERRORS: assignment (=) instead of comparison (==) in conditions, off-by-one \
in capacity/indexing (e.g. capacity = requested - 1), TOCTOU (stat then open), \
stale data after mutation
7. CONCURRENCY: unsynchronized increment/decrement of shared counters, global state \
modified without locks, non-atomic read-modify-write on shared variables
8. DRIVER / STATE MACHINES: stale state after teardown, invalid lifecycle transitions, \
unsafe ordering of power/reset/MMU/cache/fault handling, deferred work/timer/callback use \
after free, cleanup asymmetry on partial failure, rollback bugs after partially inserted \
state, lock-order inversions, permission/flag semantic mismatches, accounting mismatches \
between source objects and aliases/mappings
9. LOGGING / DIAGNOSTICS: fault or trace logging that prints sensitive addresses or \
hardware/internal identifiers
10. SAME-FILE MULTI-FUNCTION BUGS: bugs whose root cause spans 2 to 4 functions in this file \
such as setup/teardown, suspend/cleanup, open/poll/release, or callback/free pairs

## Output format

Prefer the PRIMARY direct bug over speculative secondary issues. For example:
- prefer command injection over toctou when a shell command is built from variable input
- prefer buffer_overflow over vague downstream memory-corruption concerns when sprintf/strcpy is present
- prefer path_traversal when a path is built from variable input and opened without validation

Important for driver-like code:
- Do NOT down-rank state bugs, accounting bugs, cleanup bugs, lock-order bugs, deferred-work \
  lifecycle bugs, or permission/flag semantic bugs merely because no classic unsafe sink appears.
- If the real issue is a stale state transition, rollback bug, cleanup mismatch, or wrong permission \
  domain, report that directly instead of translating it into a nearby overflow/null/leak issue.

For EACH candidate include BOTH:
- mechanism: the root-cause mechanism
- type: the final vulnerability label

Preferred mechanisms when applicable:
state_transition, ordering_gap, partial_cleanup, cleanup_symmetry, rollback_gap, stale_after_unlock, \
permission_domain_mismatch, deferred_callback_after_teardown, accounting_drift, lock_order, \
info_leak_logging, width_mismatch_second_access, file_ops_lifecycle_gap, compiler_shape_mismatch, generic_memory

Preferred candidate types when applicable:
command_injection, buffer_overflow, sscanf_overflow, path_traversal, format_string, integer_overflow, \
out_of_bounds, use_after_free, double_free, null_deref, state_transition_bug, stale_state, \
ordering_race, teardown_race, deferred_work_uaf, cleanup_asymmetry, partial_failure_cleanup, \
lock_order_inversion, permission_mismatch, flag_semantic_bug, accounting_mismatch, \
lifetime_invariant_break, rollback_invariant_bug, boolean_coercion, wrong_constant, stale_length, \
information_disclosure, other

For each issue found, classify locality:
- local_direct: the target file itself shows a classic unsafe sink, missing validation, stale-state bug, \
  cleanup mismatch, rollback problem, wrong permission/flag semantic, logging leak, or ordering issue that can be \
  confirmed from this file alone
- cross_file: the issue likely depends on caller behavior, ownership across files, or wider repo context

Return ONLY valid JSON. For each issue found, include investigation_hints — short \
grep patterns or function names a reviewer should search for in the rest of the \
codebase to determine reachability and exploitability.

{\"candidates\": [
  {\"function_name\": \"func_name\", \"line\": 42, \"mechanism\": \"file_ops_lifecycle_gap\", \"type\": \"lifetime_invariant_break\",
    \"severity\": \"high\", \"description\": \"conn_close closes c->fd but caller may also close the same fd\",
    \"locality\": \"cross_file\", \"primary\": false,
    \"cross_file_concern\": true,
    \"code_snippet\": \"...\",
    \"investigation_hints\": [\"conn_close(\", \"close(cfd)\"]}
]}

If you find NOTHING, return {\"candidates\": []}. But be thorough — err on the side \
of flagging suspicious patterns. It is much better to flag a false positive than to \
miss a real vulnerability."""

_FILE_AUDIT_USR = "File under review: {file_path}\n\n{file_content}"

_FILE_CLEANUP_SYS = """\
You are auditing ONE C/C++ source file for cleanup symmetry and partial-failure cleanup bugs.

Focus on these questions:
1. What gets pinned, mapped, referenced, inserted, scheduled, registered, enabled, allocated, or locked?
2. On EVERY error path, abort path, rollback path, and teardown path, is the inverse operation guaranteed?
3. Are partially acquired pages, mappings, list/rbtree entries, timers, work items, workqueues, or references leaked or left live?
4. Can asynchronous work or timers still run after related object teardown?
5. Extract the acquire/release families and compare them: page pins, mapping refs, rb/list insertions, \
   workqueue/timer registration, locks, kfree/destroy/unregister helpers.

Prefer these mechanisms and types when appropriate:
partial_cleanup -> partial_failure_cleanup
cleanup_symmetry -> cleanup_asymmetry
deferred_callback_after_teardown -> deferred_work_uaf
rollback_gap -> rollback_invariant_bug
accounting_drift -> accounting_mismatch
stale_after_unlock -> lifetime_invariant_break

Return ONLY valid JSON:
{\"candidates\": [
  {\"function_name\": \"func_name\", \"line\": 42, \"mechanism\": \"partial_cleanup\", \"type\": \"partial_failure_cleanup\",
    \"severity\": \"high\", \"description\": \"...\", \"locality\": \"local_direct\",
    \"primary\": true, \"cross_file_concern\": false, \"code_snippet\": \"...\",
    \"investigation_hints\": [\"func_name(\", \"put_page(\", \"goto err\"]}
]}

If none, return {\"candidates\": []}."""

_FILE_CLEANUP_USR = "File under review: {file_path}\n\n{file_content}"

_FILE_STATE_SYS = """\
You are auditing ONE C/C++ source file for driver-style state-machine, teardown, ordering, and deferred-work bugs.

Use subsystem-aware vocabulary when present:
- MMU / flush / invalidate / disable / fault / power / reset / runtime PM
- queue / enabled / terminate / doorbell / scheduler / protected mode
- tracking page / alias / shrink / remap / evictable / dont_need
- workqueue / timer / callback / async dump / close / destroy

Look specifically for:
1. field/state set before validation completes
2. resource exposed before enable check finishes
3. callback/work/timer can run after free/termination
4. power/reset/MMU/cache/fault handling done in the wrong order
5. lifecycle bits, pointers, or overrides not cleared on all exit paths
6. lock-order inversions or teardown races across callback/worker/IRQ style code

Prefer these mechanisms and types when appropriate:
state_transition -> state_transition_bug
ordering_gap -> ordering_race
deferred_callback_after_teardown -> deferred_work_uaf
lock_order -> lock_order_inversion
stale_after_unlock -> lifetime_invariant_break

Return ONLY valid JSON:
{\"candidates\": [
  {\"function_name\": \"func_name\", \"line\": 42, \"mechanism\": \"state_transition\", \"type\": \"state_transition_bug\",
    \"severity\": \"high\", \"description\": \"...\", \"locality\": \"local_direct\",
    \"primary\": true, \"cross_file_concern\": false, \"code_snippet\": \"...\",
    \"investigation_hints\": [\"func_name(\", \"state\", \"enable\", \"terminate\"]}
]}

If none, return {\"candidates\": []}."""

_FILE_STATE_USR = "File under review: {file_path}\n\n{file_content}"

_FILE_SEMANTIC_SYS = """\
You are auditing ONE C/C++ source file for permission, flag, accounting, alias-lifetime, and semantic correctness bugs.

Look specifically for:
1. wrong permission constant or wrong access domain checked
2. wrong address class or object class validated
3. one bound/width checked, but a later access needs a stronger bound
4. source-object lifetime not reflected in alias/derived mapping metadata
5. check validates A, but later use depends on B
6. tracking/accounting fields drifting out of sync with the real object lifecycle

Prefer these mechanisms and types when appropriate:
permission_domain_mismatch -> permission_mismatch or flag_semantic_bug
width_mismatch_second_access -> out_of_bounds
accounting_drift -> accounting_mismatch or lifetime_invariant_break
rollback_gap -> rollback_invariant_bug
file_ops_lifecycle_gap -> lifetime_invariant_break

Return ONLY valid JSON:
{\"candidates\": [
  {\"function_name\": \"func_name\", \"line\": 42, \"mechanism\": \"permission_domain_mismatch\", \"type\": \"permission_mismatch\",
    \"severity\": \"high\", \"description\": \"...\", \"locality\": \"local_direct\",
    \"primary\": true, \"cross_file_concern\": false, \"code_snippet\": \"...\",
    \"investigation_hints\": [\"func_name(\", \"flags\", \"permission\", \"GPU_WR\"]}
]}

If none, return {\"candidates\": []}."""

_FILE_SEMANTIC_USR = "File under review: {file_path}\n\n{file_content}"

_FILE_STALE_UNLOCK_SYS = """\
You are auditing ONE C/C++ source file for stale-local-after-unlock bugs.

Look for this exact shape:
1. code reads pointer/size/index/state into a local
2. code drops a lock or relinquishes exclusive synchronization
3. code does work or allows state transition
4. code reacquires lock or resumes protected execution
5. code uses the stale local without refreshing it

This is common in kernel/driver code and can lead to use-after-free, stale-region access, bad indexing, \
or state corruption.

Return ONLY valid JSON:
{\"candidates\": [
  {\"function_name\": \"func_name\", \"line\": 42, \"mechanism\": \"stale_after_unlock\", \"type\": \"lifetime_invariant_break\",
    \"severity\": \"high\", \"description\": \"...\", \"locality\": \"local_direct\",
    \"primary\": true, \"cross_file_concern\": false, \"code_snippet\": \"...\",
    \"investigation_hints\": [\"func_name(\", \"unlock\", \"lock\", \"stale\"]}
]}

If none, return {\"candidates\": []}."""

_FILE_STALE_UNLOCK_USR = "File under review: {file_path}\n\n{file_content}"

_FILE_WIDTH_SYS = """\
You are auditing ONE C/C++ source file for secondary-access bugs where the second access is wider or stronger than what was validated.

Look specifically for:
1. validates one field, then reads/writes adjacent field without proving object size
2. validates 32-bit view, later uses 64-bit access
3. validates header, then uses trailing variable-length region as string or array
4. validates one address class, but second operation assumes stronger guarantees

Return ONLY valid JSON:
{\"candidates\": [
  {\"function_name\": \"func_name\", \"line\": 42, \"mechanism\": \"width_mismatch_second_access\", \"type\": \"out_of_bounds\",
    \"severity\": \"high\", \"description\": \"...\", \"locality\": \"local_direct\",
    \"primary\": true, \"cross_file_concern\": false, \"code_snippet\": \"...\",
    \"investigation_hints\": [\"func_name(\", \"u32\", \"u64\", \"field\", \"value\"]}
]}

If none, return {\"candidates\": []}."""

_FILE_WIDTH_USR = "File under review: {file_path}\n\n{file_content}"

_FILE_FILEOPS_SYS = """\
You are auditing ONE C/C++ source file for file_operations / vtable completeness and lifetime bugs.

Look specifically for:
1. release exists but flush is missing
2. poll and flush/release can race on the same object
3. object teardown exists in one file-op path but not another
4. duplicated/shared descriptors can keep state alive unexpectedly
5. open/mmap/ioctl/poll/release combinations assume inconsistent lifetimes

Return ONLY valid JSON:
{\"candidates\": [
  {\"function_name\": \"file_operations\", \"line\": 42, \"mechanism\": \"file_ops_lifecycle_gap\", \"type\": \"lifetime_invariant_break\",
    \"severity\": \"high\", \"description\": \"...\", \"locality\": \"cross_file\",
    \"primary\": true, \"cross_file_concern\": true, \"code_snippet\": \"...\",
    \"investigation_hints\": [\"struct file_operations\", \".release\", \".flush\", \".poll\"]}
]}

If none, return {\"candidates\": []}."""

_FILE_FILEOPS_USR = "File under review: {file_path}\n\n{file_content}"

_FILE_LOGGING_SYS = """\
You are auditing ONE C/C++ source file for information disclosure through logging, diagnostics, tracing, or fault reporting.

Look specifically for:
1. printk/dev_err/dev_warn/pr_err/trace logging of physical or kernel addresses
2. fixed format specifiers that expose internal address state
3. logs that reveal secrets, handles, tokens, or hardware identifiers
4. mismatch between logical address class and what is printed

Return ONLY valid JSON:
{\"candidates\": [
  {\"function_name\": \"func_name\", \"line\": 42, \"mechanism\": \"info_leak_logging\", \"type\": \"information_disclosure\",
    \"severity\": \"medium\", \"description\": \"...\", \"locality\": \"local_direct\",
    \"primary\": true, \"cross_file_concern\": false, \"code_snippet\": \"...\",
    \"investigation_hints\": [\"func_name(\", \"printk\", \"dev_err\", \"%pa\", \"%px\"]}
]}

If none, return {\"candidates\": []}."""

_FILE_LOGGING_USR = "File under review: {file_path}\n\n{file_content}"

_FILE_CLUSTER_SYS = """\
You are auditing a SAME-FILE function cluster because the likely bug spans multiple nearby functions in one source file.

The cluster may include:
- target function
- direct callees in the same file
- direct callers in the same file
- teardown helper
- callback/timer worker
- file-ops helper
- error/rollback helper

Your job is to identify the PRIMARY root-cause mechanism if the bug spans 2 to 4 functions here.
Prefer mechanisms:
state_transition, ordering_gap, partial_cleanup, cleanup_symmetry, rollback_gap, stale_after_unlock, \
permission_domain_mismatch, deferred_callback_after_teardown, accounting_drift, lock_order, \
width_mismatch_second_access, file_ops_lifecycle_gap, info_leak_logging, compiler_shape_mismatch

Do NOT downgrade the cluster to a nearby generic integer overflow or leak if the real bug is a stronger same-file state/lifecycle/semantic issue.

Return ONLY valid JSON:
{\"candidates\": [
  {\"function_name\": \"seed_func\", \"line\": 42, \"mechanism\": \"state_transition\", \"type\": \"state_transition_bug\",
    \"severity\": \"high\", \"description\": \"...\", \"locality\": \"local_direct\",
    \"primary\": true, \"cross_file_concern\": false, \"code_snippet\": \"...\",
    \"investigation_hints\": [\"seed_func(\", \"helper_func(\", \"state\", \"terminate\"]}
]}

If none, return {\"candidates\": []}."""

_FILE_CLUSTER_USR = """File under review: {file_path}
Cluster seed: {seed}
Cluster functions: {functions}

{cluster_code}
"""

_FILE_COMPILER_SYS = """\
You are auditing ONE C/C++ source file for compiler/front-end semantic bugs.

Look specifically for:
1. dimension mismatch between allocated shape and written shape
2. synthesized structure or matrix/vector initialization using wrong extent
3. row/column count mismatch
4. vector width or lane assumptions inconsistent with allocation
5. enum/table size mismatch
6. builder loops that write using destination dimension instead of allocated dimension

Return ONLY valid JSON:
{\"candidates\": [
  {\"function_name\": \"func_name\", \"line\": 42, \"mechanism\": \"compiler_shape_mismatch\", \"type\": \"out_of_bounds\",
    \"severity\": \"high\", \"description\": \"...\", \"locality\": \"local_direct\",
    \"primary\": true, \"cross_file_concern\": false, \"code_snippet\": \"...\",
    \"investigation_hints\": [\"func_name(\", \"matrix\", \"row\", \"column\", \"constructor\"]}
]}

If none, return {\"candidates\": []}."""

_FILE_COMPILER_USR = "File under review: {file_path}\n\n{file_content}"

_FILE_DEEP_DRIVER_AUDIT_SYS = """\
You are a world-class auditor performing a second-pass deep review of ONE driver-style C/C++ file because the first-pass results were weak or empty.

Your job is to surface the highest-signal 1 to 8 candidates in these families:
- stale state after teardown
- invalid state transition
- deferred work/timer/callback after free
- cleanup symmetry / partial failure cleanup
- rollback invariant bug after partial insertion
- ordering race in power/reset/MMU/cache/fault handling
- permission or flag semantic mismatch
- accounting / alias lifetime mismatch
- lock-order inversion
- stale locals reused after unlock/relock
- information disclosure through fault logging
- file_operations lifetime gaps

Do NOT default to nearby generic integer-overflow, NULL, or leak findings if a stronger state/lifecycle/semantic bug is present.

Return ONLY valid JSON:
{\"candidates\": [
  {\"function_name\": \"func_name\", \"line\": 42, \"mechanism\": \"state_transition\", \"type\": \"state_transition_bug\",
    \"severity\": \"high\", \"description\": \"...\", \"locality\": \"local_direct\",
    \"primary\": true, \"cross_file_concern\": false, \"code_snippet\": \"...\",
    \"investigation_hints\": [\"func_name(\", \"state\", \"terminate\", \"doorbell\"]}
]}

If none, return {\"candidates\": []}."""

_FILE_DEEP_DRIVER_AUDIT_USR = "File under review: {file_path}\n\n{file_content}"


class FileAuditor:
    """Phase 1: Strong model reviews a single file for all potential security issues."""

    def __init__(self, llm_provider, model, usage_runtime, max_tokens=16384):
        self._p = llm_provider
        self._m = model
        self._u = usage_runtime
        self._t = max_tokens

    def _invoke_candidates(self, system_prompt, user_template, file_path, file_content, *, default_driver_context=False):
        kw = self._u.hooks.chat_model_kwargs()
        chat = self._p.get_chat_model(model=self._m, max_tokens=self._t, temperature=0.1, **kw)
        prompt = ChatPromptTemplate.from_messages([
            ("system", system_prompt),
            ("user", user_template),
        ])
        prompt_ready_content = _build_prompt_ready_file_content(
            file_path,
            file_content,
            max_chars=_REVIEW_FILE_FULL_PROMPT_BUDGET,
        )
        raw = (prompt | chat | StrOutputParser()).invoke({
            "file_path": file_path,
            "file_content": prompt_ready_content,
        }).strip()
        return _parse_candidate_payload(raw, default_driver_context=default_driver_context)

    def _safe_invoke_candidates(self, label, system_prompt, user_template, file_path, file_content, *, default_driver_context=False):
        try:
            return self._invoke_candidates(
                system_prompt, user_template, file_path, file_content,
                default_driver_context=default_driver_context,
            )
        except Exception as e:
            logger.warning("Audit pass %s failed for %s: %s", label, file_path, e)
            return []

    def _invoke_cluster_candidates(self, file_path, cluster, *, default_driver_context=False):
        kw = self._u.hooks.chat_model_kwargs()
        chat = self._p.get_chat_model(model=self._m, max_tokens=self._t, temperature=0.1, **kw)
        prompt = ChatPromptTemplate.from_messages([
            ("system", _FILE_CLUSTER_SYS),
            ("user", _FILE_CLUSTER_USR),
        ])
        cluster_code = str(cluster.get("code") or "")
        if len(cluster_code) > _REVIEW_FILE_FULL_PROMPT_BUDGET:
            cluster_code = cluster_code[:_REVIEW_FILE_FULL_PROMPT_BUDGET] + "\n... [truncated cluster excerpt]"
        raw = (prompt | chat | StrOutputParser()).invoke({
            "file_path": file_path,
            "seed": cluster["seed"],
            "functions": ", ".join(cluster["functions"]),
            "cluster_code": cluster_code,
        }).strip()
        return _parse_candidate_payload(raw, default_driver_context=default_driver_context)

    def _safe_invoke_cluster_candidates(self, file_path, cluster, *, default_driver_context=False):
        try:
            return self._invoke_cluster_candidates(
                file_path, cluster, default_driver_context=default_driver_context,
            )
        except Exception as e:
            logger.warning("Cluster audit failed for %s [seed=%s]: %s", file_path, cluster.get("seed"), e)
            return []

    def audit(self, file_path, file_content):
        is_driver = _looks_driver_file(file_path, file_content)
        is_compilerish = _looks_compilerish_file(file_path, file_content)

        def _safe_collect(label, fn, *args):
            try:
                return fn(*args)
            except Exception as e:
                logger.warning("%s failed for %s: %s", label, file_path, e)
                return []

        try:
            result = self._safe_invoke_candidates(
                "primary",
                _FILE_AUDIT_SYS, _FILE_AUDIT_USR,
                file_path, file_content,
                default_driver_context=is_driver,
            )

            static_candidates = _safe_collect("obvious-local detector", _detect_obvious_local_candidates, file_content)
            driver_static_candidates = _safe_collect("driver-specific detector", _detect_driver_specific_candidates, file_path, file_content)
            stale_unlock_candidates = _safe_collect("stale-after-unlock detector", _detect_stale_after_unlock_candidates, file_path, file_content)
            width_candidates = _safe_collect("width-mismatch detector", _detect_width_mismatch_candidates, file_path, file_content)
            fileops_candidates = _safe_collect("fileops detector", _detect_fileops_candidates, file_path, file_content)
            logging_candidates = _safe_collect("logging detector", _detect_logging_candidates, file_path, file_content)
            compiler_static_candidates = _safe_collect("compiler-semantic detector", _detect_compiler_semantic_candidates, file_path, file_content)

            targeted_candidates = []

            if is_driver or not result:
                targeted_candidates.extend(self._safe_invoke_candidates(
                    "cleanup",
                    _FILE_CLEANUP_SYS, _FILE_CLEANUP_USR,
                    file_path, file_content,
                    default_driver_context=is_driver,
                ))
                targeted_candidates.extend(self._safe_invoke_candidates(
                    "state",
                    _FILE_STATE_SYS, _FILE_STATE_USR,
                    file_path, file_content,
                    default_driver_context=is_driver,
                ))
                targeted_candidates.extend(self._safe_invoke_candidates(
                    "semantic",
                    _FILE_SEMANTIC_SYS, _FILE_SEMANTIC_USR,
                    file_path, file_content,
                    default_driver_context=is_driver,
                ))
                targeted_candidates.extend(self._safe_invoke_candidates(
                    "stale-unlock",
                    _FILE_STALE_UNLOCK_SYS, _FILE_STALE_UNLOCK_USR,
                    file_path, file_content,
                    default_driver_context=is_driver,
                ))
                targeted_candidates.extend(self._safe_invoke_candidates(
                    "width",
                    _FILE_WIDTH_SYS, _FILE_WIDTH_USR,
                    file_path, file_content,
                    default_driver_context=is_driver,
                ))
                targeted_candidates.extend(self._safe_invoke_candidates(
                    "fileops",
                    _FILE_FILEOPS_SYS, _FILE_FILEOPS_USR,
                    file_path, file_content,
                    default_driver_context=is_driver,
                ))
                targeted_candidates.extend(self._safe_invoke_candidates(
                    "logging",
                    _FILE_LOGGING_SYS, _FILE_LOGGING_USR,
                    file_path, file_content,
                    default_driver_context=is_driver,
                ))

            if is_compilerish:
                targeted_candidates.extend(self._safe_invoke_candidates(
                    "compiler",
                    _FILE_COMPILER_SYS, _FILE_COMPILER_USR,
                    file_path, file_content,
                    default_driver_context=is_driver,
                ))

            combined = (
                result
                + targeted_candidates
                + static_candidates
                + driver_static_candidates
                + stale_unlock_candidates
                + width_candidates
                + fileops_candidates
                + logging_candidates
                + compiler_static_candidates
            )

            combined = _prune_audit_candidates([
                dict(c, driver_context=bool(c.get("driver_context")) or is_driver, compiler_context=bool(c.get("compiler_context")) or is_compilerish)
                for c in combined
            ], limit=40)

            seed_functions = []
            for c in combined[:8]:
                fn = str(c.get("function_name") or "").strip()
                if fn and fn != "unknown" and fn != "file_operations":
                    seed_functions.append(fn)
            if not seed_functions:
                seed_functions = [name for name, _, _ in _collect_function_bodies(file_content)[:4]]

            cluster_candidates = []
            clusters = _safe_build_same_file_clusters(
                file_content,
                seed_functions,
                max_clusters=4 if is_driver else 2,
                max_functions_per_cluster=_REVIEW_FILE_MAX_CLUSTER_FUNCTIONS,
            )
            for cluster in clusters:
                cluster_candidates.extend(
                    self._safe_invoke_cluster_candidates(
                        file_path, cluster, default_driver_context=is_driver,
                    )
                )

            combined.extend(cluster_candidates)

            family_coverage = {c.get("mechanism_family") for c in combined}
            if is_driver and (len(combined) < 5 or len(family_coverage) < 2):
                combined.extend(self._safe_invoke_candidates(
                    "deep-driver",
                    _FILE_DEEP_DRIVER_AUDIT_SYS, _FILE_DEEP_DRIVER_AUDIT_USR,
                    file_path, file_content,
                    default_driver_context=True,
                ))
            elif not combined:
                combined.extend(self._safe_invoke_candidates(
                    "deep-fallback",
                    _FILE_DEEP_DRIVER_AUDIT_SYS, _FILE_DEEP_DRIVER_AUDIT_USR,
                    file_path, file_content,
                    default_driver_context=is_driver,
                ))

            return _prune_audit_candidates([
                dict(c, driver_context=bool(c.get("driver_context")) or is_driver, compiler_context=bool(c.get("compiler_context")) or is_compilerish)
                for c in combined
            ], limit=25)

        except Exception as e:
            logger.exception("File audit crashed for %s: %s", file_path, e)
            fallback = []
            fallback.extend(_safe_collect("obvious-local detector", _detect_obvious_local_candidates, file_content))
            fallback.extend(_safe_collect("driver-specific detector", _detect_driver_specific_candidates, file_path, file_content))
            fallback.extend(_safe_collect("stale-after-unlock detector", _detect_stale_after_unlock_candidates, file_path, file_content))
            fallback.extend(_safe_collect("width-mismatch detector", _detect_width_mismatch_candidates, file_path, file_content))
            fallback.extend(_safe_collect("fileops detector", _detect_fileops_candidates, file_path, file_content))
            fallback.extend(_safe_collect("logging detector", _detect_logging_candidates, file_path, file_content))
            fallback.extend(_safe_collect("compiler-semantic detector", _detect_compiler_semantic_candidates, file_path, file_content))
            return _prune_audit_candidates([
                dict(c, driver_context=bool(c.get("driver_context")) or is_driver, compiler_context=bool(c.get("compiler_context")) or is_compilerish)
                for c in fallback
            ], limit=25)


# file investigation

_INVESTIGATE_SYS = """\
You are a security researcher investigating whether a potential vulnerability in a \
C/C++ codebase is actually reachable and exploitable by an external attacker.

You are given:
- A candidate vulnerability description from a file audit
- The source code of the file containing the potential issue
- Optionally, some initial search results from the codebase

## Available actions

Output ONLY valid JSON with one of these formats:

### 1. Search the codebase (grep)
{\"actions\": [
  {\"type\": \"search\", \"pattern\": \"function_name\\\\(\"},
  {\"type\": \"search\", \"pattern\": \"close\\\\(cfd\\\\)\"}
]}
Maximum 5 search actions per turn. Use specific patterns to avoid huge results.

### 2. Read lines from a file
{\"actions\": [
  {\"type\": \"read\", \"path\": \"src/main.c\", \"start_line\": 28, \"end_line\": 60}
]}
Maximum 3 read actions per turn. Max 80 lines per read.

### 3. Conclude your investigation
{\"verdict\": {
  \"is_vulnerable\": true,
  \"mechanism\": \"file_ops_lifecycle_gap\",
  \"vulnerability_type\": \"double_close\",
  \"severity\": \"high\",
  \"confidence\": \"high\",
  \"function_name\": \"conn_close\",
  \"line\": 58,
  \"description\": \"conn_close closes c->fd, then handle_client also closes cfd which is the same descriptor\",
  \"root_cause\": \"Ambiguous fd ownership: conn_close takes ownership and closes c->fd, but handle_client still holds cfd and closes it after conn_close returns\",
  \"evidence\": \"src/connection.c:72 close(c->fd); src/main.c:46 close(cfd); cfd == c->fd from conn_create\",
  \"reachability_chain\": \"main -> handle_client -> conn_close -> close(c->fd) ... handle_client -> close(cfd)\"
}}

## Investigation strategy

1. First, use the investigation_hints from the audit to search for relevant callers/callees
2. Read the key functions you find to understand data flow
3. Determine: can an external attacker (network client, file input, etc.) actually reach this code?
4. Check for mitigating factors: bounds checks, auth checks, sanitization
5. When you have enough evidence, conclude with a verdict

For obvious unsafe sink patterns in the target file, local file evidence may be enough.
For driver-like bugs, also investigate:
- partial failure cleanup symmetry
- stale state after teardown or disable
- deferred work/timer/callbacks that can outlive the object
- unsafe power/reset/MMU/cache/fault ordering
- wrong permission/flag semantic checks
- alias/accounting/lifetime mismatches
- stale locals reused after unlock/relock
- width mismatches where a second access is stronger than the checked one
- file_operations/vtable completeness and poll/flush/release symmetry
- logging that may leak physical or internal addresses
Use grep mainly for ambiguous, cross-file, ownership, lifecycle, and caller-dependent issues.
Prefer the PRIMARY direct bug over speculative side issues.

If the vulnerability is NOT exploitable or NOT reachable, conclude with is_vulnerable: false.
Be thorough but efficient. Output ONLY valid JSON, no prose."""

_INVESTIGATE_CONCLUDE_SYS = """\
You must now conclude your investigation based on everything you have seen. \
Determine whether the vulnerability candidate is a real, exploitable issue.

For obvious unsafe sink patterns in the target file, do not require repo-level proof of attacker reachability.
If the target file itself shows a classic unsafe sink or missing validation pattern, you may confirm it based on local evidence.
The same applies to clear driver-style file-local bugs such as:
- deferred work/timers not synchronously canceled before free
- partial-failure cleanup omissions
- stale lifecycle state not cleared on teardown
- wrong permission/flag semantic checks in the same file
- unsafe ordering of power/reset/MMU/cache/fault state transitions
- stale locals reused after unlock/relock
- width mismatch where a second mapped access is stronger than the validated one
- logging that discloses sensitive addresses
- file_operations lifetime gaps visible in the same file
Prefer the PRIMARY direct bug over speculative secondary issues.

Output ONLY valid JSON:
{\"verdict\": {
  \"is_vulnerable\": true,
  \"mechanism\": \"ordering_gap\",
  \"vulnerability_type\": \"...\",
  \"severity\": \"high\",
  \"confidence\": \"high\",
  \"function_name\": \"...\",
  \"line\": 0,
  \"description\": \"...\",
  \"root_cause\": \"...\",
  \"evidence\": \"...\",
  \"reachability_chain\": \"func_a -> func_b -> func_c\"
}}

Set is_vulnerable to false if there is insufficient evidence of exploitability."""

_GREP_MAX_LINES = 60
_GREP_TIMEOUT = 10
_C_EXTENSIONS = ["*.c", "*.h", "*.cc", "*.cpp", "*.hpp", "*.hh", "*.hxx", "*.cxx"]


def _run_grep(pattern, codebase_path, max_lines=_GREP_MAX_LINES):
    """Execute grep on the codebase, returning truncated output."""
    try:
        cmd = ["grep", "-rn"]
        for ext in _C_EXTENSIONS:
            cmd.extend(["--include", ext])
        cmd.extend([pattern, "."])
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=_GREP_TIMEOUT, cwd=codebase_path,
        )
        output = result.stdout
        if not output.strip():
            return "(no matches found)"
        lines = output.splitlines()
        if len(lines) > max_lines:
            return "\n".join(lines[:max_lines]) + f"\n... ({len(lines) - max_lines} more lines truncated — use a more specific pattern)"
        return output.strip()
    except subprocess.TimeoutExpired:
        return "(search timed out — pattern too broad, use a more specific pattern)"
    except Exception as e:
        return f"(search error: {e})"


def _read_file_lines(codebase_path, rel_path, start_line, end_line, max_lines=80):
    """Read specific lines from a file in the codebase."""
    try:
        full_path = os.path.normpath(os.path.join(codebase_path, rel_path))
        if not full_path.startswith(os.path.abspath(codebase_path)):
            return "(path outside codebase)"
        content = read_file_content(full_path)
        if not content:
            return "(file not found or empty)"
        lines = content.splitlines()
        start = max(0, start_line - 1)
        end = min(len(lines), end_line)
        if end - start > max_lines:
            end = start + max_lines
        return "\n".join(f"{i+1}: {lines[i]}" for i in range(start, end))
    except Exception as e:
        return f"(read error: {e})"

def _structured_investigation_patterns(candidate):
    patterns = []
    mechanism = _normalize_mechanism(candidate.get("mechanism"), candidate.get("type"))
    ctype = str(candidate.get("type") or "").strip()

    if mechanism in {"deferred_callback_after_teardown", "cleanup_symmetry", "partial_cleanup"} or ctype in {"deferred_work_uaf", "cleanup_asymmetry", "partial_failure_cleanup"}:
        patterns.extend(["queue_work\\(", "schedule_work\\(", "cancel_work_sync\\(", "destroy_workqueue\\(", "del_timer_sync\\("])
    if mechanism in {"lock_order", "stale_after_unlock"}:
        patterns.extend(["mutex_lock\\(", "mutex_unlock\\(", "spin_lock\\(", "spin_unlock\\("])
    if mechanism == "permission_domain_mismatch":
        patterns.extend(["GPU_WR", "CPU_WR", "BASE_MEM_", "permission", "flags"])
    if mechanism == "accounting_drift":
        patterns.extend(["gpu_mappings", "alias", "refcount", "shrink", "NO_USER_FREE"])
    if mechanism == "file_ops_lifecycle_gap":
        patterns.extend(["struct file_operations", "\\.release", "\\.flush", "\\.poll", "\\.open"])
    if mechanism == "info_leak_logging":
        patterns.extend(["printk\\(", "dev_err\\(", "pr_err\\(", "%pa", "%px"])
    if mechanism == "width_mismatch_second_access":
        patterns.extend(["u32", "u64", "uint32_t", "uint64_t", "mapping_get"])
    if mechanism == "state_transition" or mechanism == "ordering_gap":
        patterns.extend(["enabled", "terminated", "doorbell", "pm_runtime_get_sync\\(", "reset", "flush_noretain"])
    if mechanism == "compiler_shape_mismatch":
        patterns.extend(["matrix", "row", "column", "constructor", "expr\\.u\\.value"])
    return patterns

def _structured_read_requests(candidate, target_file, target_file_content):
    fn = str(candidate.get("function_name") or "").strip()
    if not fn or fn in {"unknown", "file_operations"}:
        return []
    clusters = _safe_build_same_file_clusters(
        target_file_content,
        [fn],
        max_clusters=1,
        max_functions_per_cluster=5,
    )
    if not clusters:
        return []
    requests = []
    body_map, _, _ = _extract_local_call_relations(target_file_content)
    for name in clusters[0]["functions"][:3]:
        if name not in body_map:
            continue
        start, lines = body_map[name]
        requests.append({"path": target_file, "start_line": start, "end_line": start + min(80, len(lines) + 5)})
    return requests[:3]


class FindingInvestigator:
    """Phase 2: Multi-turn investigation of each candidate finding via grep."""

    def __init__(self, llm_provider, model, usage_runtime, codebase_path, max_tokens=4096):
        self._p = llm_provider
        self._m = model
        self._u = usage_runtime
        self._cb = os.path.abspath(codebase_path)
        self._t = max_tokens

    def investigate(self, candidate, target_file, target_file_content, *, max_turns=4):
        """Investigate a single candidate finding. Returns a verdict dict or None."""
        if _candidate_is_local_direct(candidate):
            local_verdict = self._confirm_local_direct(candidate, target_file, target_file_content)
            if isinstance(local_verdict, dict) and local_verdict.get("is_vulnerable"):
                return local_verdict
            if isinstance(local_verdict, dict) and not candidate.get("cross_file_concern"):
                return local_verdict

        kw = self._u.hooks.chat_model_kwargs()
        chat = self._p.get_chat_model(model=self._m, max_tokens=self._t, temperature=0.1, **kw)

        initial_user = self._build_initial_prompt(candidate, target_file, target_file_content)
        messages = [
            SystemMessage(content=_INVESTIGATE_SYS),
            HumanMessage(content=initial_user),
        ]

        for turn in range(max_turns):
            is_last_turn = (turn == max_turns - 1)

            if is_last_turn:
                messages.append(HumanMessage(content=(
                    "This is your final turn. You must conclude now with a verdict. "
                    "Based on everything you've seen, output your verdict JSON."
                )))
                call_messages = [SystemMessage(content=_INVESTIGATE_CONCLUDE_SYS)] + messages[1:]
            else:
                call_messages = messages

            try:
                response = chat.invoke(call_messages)
                raw = response.content if hasattr(response, 'content') else str(response)
            except Exception as e:
                logger.warning("Investigation call failed on turn %d: %s", turn, e)
                return None

            parsed = parse_json_output(raw.strip())
            if not isinstance(parsed, dict):
                messages.append(AIMessage(content=raw))
                messages.append(HumanMessage(content="Please output valid JSON only — either actions or a verdict."))
                continue

            verdict = parsed.get("verdict")
            if isinstance(verdict, dict):
                return _parse_verdict_payload(json.dumps({"verdict": verdict}))

            actions = parsed.get("actions")
            if not isinstance(actions, list) or not actions:
                messages.append(AIMessage(content=raw))
                messages.append(HumanMessage(content="Output actions to search/read the codebase, or a verdict to conclude."))
                continue

            results_text = self._execute_actions(actions)
            messages.append(AIMessage(content=raw))
            messages.append(HumanMessage(content=f"Results from your actions:\n\n{results_text}\n\nContinue investigating or conclude with a verdict."))

        return None

    def _confirm_local_direct(self, candidate, target_file, target_file_content):
        try:
            confirmer = VulnerabilityConfirmer(self._p, self._m, self._u, self._cb, max_tokens=self._t)
            verdict = confirmer.confirm_local_candidate(candidate, target_file, target_file_content)
            if isinstance(verdict, dict):
                return verdict
        except Exception as e:
            logger.warning("Local confirmation failed for %s/%s: %s", target_file, candidate.get("function_name"), e)
        return None

    def _build_initial_prompt(self, candidate, target_file, target_file_content):
        hints = _merge_hint_lists(candidate.get("investigation_hints", []), _default_hints_for_candidate(candidate))
        hints_text = ""
        if hints:
            hints_text = f"\nSuggested search patterns to start with: {', '.join(hints)}"

        auto_results = []
        expanded = _merge_hint_lists(hints[:3], _structured_investigation_patterns(candidate)[:5])
        if not _candidate_is_local_direct(candidate) or candidate.get("cross_file_concern"):
            for hint in expanded[:5]:
                result = _run_grep(hint, self._cb)
                auto_results.append(f"grep '{hint}':\n{result}")
        for req in _structured_read_requests(candidate, target_file, target_file_content):
            output = _read_file_lines(self._cb, req["path"], req["start_line"], req["end_line"])
            auto_results.append(f"read {req['path']}:{req['start_line']}-{req['end_line']}:\n{output}")

        target_payload = _build_prompt_ready_file_content(
            target_file,
            target_file_content,
            focus_function=str(candidate.get("function_name") or "unknown"),
            focus_line=int(candidate.get("line") or 1),
            max_chars=_REVIEW_FILE_TARGET_PROMPT_BUDGET,
        )

        auto_section = ""
        if auto_results:
            auto_section = "\n\n== INITIAL SEARCH RESULTS (auto-run from investigation hints) ==\n" + "\n\n".join(auto_results)

        return (
            f"== CANDIDATE VULNERABILITY ==\n"
            f"Function: {candidate['function_name']}\n"
            f"Line: {candidate['line']}\n"
            f"Mechanism: {candidate.get('mechanism', 'generic_memory')}\n"
            f"Type: {candidate['type']}\n"
            f"Severity: {candidate['severity']}\n"
            f"Locality: {candidate.get('locality', 'cross_file')}\n"
            f"Primary: {candidate.get('primary', False)}\n"
            f"Description: {candidate['description']}\n"
            f"Cross-file concern: {candidate.get('cross_file_concern', False)}\n"
            f"{hints_text}\n\n"
            f"== TARGET FILE: {target_file} ==\n"
            f"{target_payload}"
            f"{auto_section}\n\n"
            f"Investigate whether this vulnerability is reachable and exploitable. "
            f"Search for callers, check data flow from external input, look for mitigations. "
            f"For obvious local sink bugs in the target file, local evidence may be enough."
        )

    def _execute_actions(self, actions):
        results = []
        search_count = 0
        read_count = 0

        for action in actions:
            if not isinstance(action, dict):
                continue
            atype = str(action.get("type") or "").strip().lower()

            if atype == "search" and search_count < 5:
                pattern = str(action.get("pattern") or "").strip()
                if not pattern:
                    results.append("(empty search pattern — skipped)")
                    continue
                if len(pattern) > 200:
                    pattern = pattern[:200]
                output = _run_grep(pattern, self._cb)
                results.append(f"grep '{pattern}':\n{output}")
                search_count += 1

            elif atype == "read" and read_count < 3:
                path = str(action.get("path") or "").strip()
                try:
                    start = int(action.get("start_line", 1))
                except:
                    start = 1
                try:
                    end = int(action.get("end_line", start + 80))
                except:
                    end = start + 80
                if not path:
                    results.append("(empty path — skipped)")
                    continue
                output = _read_file_lines(self._cb, path, start, end)
                results.append(f"read {path}:{start}-{end}:\n{output}")
                read_count += 1

        if not results:
            return "(no valid actions were executed)"
        return "\n\n".join(results)



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

    def trace_paths(self, graph, *, max_path_length=25):
        return PathTracer(graph, max_path_length=max_path_length).find_all_paths()

    def run_supplementary_analysis(self, graph, *, audit_model="gpt-4.1-mini", strong_model=None, max_workers=8, progress_callback=None):
        sm = strong_model or self._config.llama_query_model
        return SupplementaryAnalyzer(self._llm_provider, audit_model, sm, self._usage_runtime, self._config.codebase_path
        ).analyze(graph, max_workers=max_workers, progress_callback=progress_callback)

    def confirm_paths(self, paths, graph, *, confirmation_model=None, max_workers=8, output_path=None, progress_callback=None):
        cm = confirmation_model or self._config.llama_query_model
        return VulnerabilityConfirmer(self._llm_provider, cm, self._usage_runtime, self._config.codebase_path).confirm_parallel(
            paths, graph, max_workers=max_workers, output_path=output_path, progress_callback=progress_callback)


    def _graph_cache_key(self, *, extraction_model, max_workers, max_paths, max_path_length):
        return (str(extraction_model or ""), int(max_workers), int(max_paths), int(max_path_length))

    def _supp_cache_key(self, *, extraction_model, confirmation_model, max_workers, max_paths, max_path_length):
        return (str(extraction_model or ""), str(confirmation_model or self._config.llama_query_model or ""),
                int(max_workers), int(max_paths), int(max_path_length))


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
                              max_workers=8, max_paths=0, max_path_length=25, progress_callback=None):
        key = self._supp_cache_key(extraction_model=extraction_model, confirmation_model=confirmation_model,
                                   max_workers=max_workers, max_paths=max_paths, max_path_length=max_path_length)
        with self._cache_lock:
            cached = self._supp_cache.get(key)
        if cached is not None: return cached
        findings = self.run_supplementary_analysis(
            graph, audit_model=extraction_model, strong_model=confirmation_model,
            max_workers=max_workers, progress_callback=progress_callback)
        with self._cache_lock: self._supp_cache[key] = findings
        return findings


    def _normalize_target_file(self, file_path):
        base_path = os.path.abspath(self._config.codebase_path)
        abs_target = file_path if os.path.isabs(file_path) else os.path.join(base_path, file_path)
        abs_target = os.path.abspath(abs_target)
        return abs_target, os.path.relpath(abs_target, base_path)

    def _split_paths_for_file(self, graph, paths, target_file):
        inbound, cross_file = [], []
        for p in paths:
            sink = graph.get_node(p.sink)
            has_target_node = False
            for node_name in p.path:
                node = graph.get_node(node_name)
                if node and node.file_path == target_file:
                    has_target_node = True; break
            if not has_target_node: continue
            if sink and sink.file_path == target_file: inbound.append(p)
            else: cross_file.append(p)
        return _dedupe_paths(inbound), _dedupe_paths(cross_file)

    def _supp_findings_for_file(self, supp_findings, target_file):
        return [f for f in supp_findings if f.sink_file == target_file or f.source_file == target_file]


    def review_codebase(self, *, extraction_model="gpt-4.1-mini", confirmation_model=None,
                        max_workers=8, max_paths=0, max_paths_per_sink=3, max_path_length=25, progress_callback=None):
        graph, paths = self._ensure_graph_and_paths(
            extraction_model=extraction_model, max_workers=max_workers,
            max_paths=max_paths, max_path_length=max_path_length, progress_callback=progress_callback)
        if graph.node_count() == 0: return []

        supp_findings = self._ensure_supplementary(
            graph, extraction_model=extraction_model, confirmation_model=confirmation_model,
            max_workers=max_workers, max_paths=max_paths, max_path_length=max_path_length,
            progress_callback=progress_callback)

        files_with_paths = set()
        for p in paths:
            for node_name in p.path:
                node = graph.get_node(node_name)
                if node: files_with_paths.add(node.file_path)
        files_with_supp = {f.sink_file for f in supp_findings if f.sink_file} | {f.source_file for f in supp_findings if f.source_file}
        all_target_files = sorted(files_with_paths | files_with_supp)

        if progress_callback: progress_callback({"event": "file_review_start", "files": len(all_target_files)})
        results = []; completed = 0
        for target_file in all_target_files:
            review = self._review_file_for_codebase(
                target_file, graph, paths, supp_findings,
                confirmation_model=confirmation_model, max_workers=max_workers,
                max_paths_per_sink=max_paths_per_sink, progress_callback=progress_callback)
            completed += 1
            if review and review.get("reviews"): results.append(review)
            if progress_callback: progress_callback({"event": "file_review_progress", "completed": completed, "total": len(all_target_files), "file": target_file})
        if progress_callback: progress_callback({"event": "file_review_done", "files": len(results)})
        return results

    def _review_file_for_codebase(self, target_file, graph, paths, supp_findings, *,
                                   confirmation_model=None, max_workers=8, max_paths_per_sink=3, progress_callback=None):
        """Graph-based per-file review used by review_codebase."""
        base_path = os.path.abspath(self._config.codebase_path)
        abs_target = os.path.join(base_path, target_file)

        file_supp = self._supp_findings_for_file(supp_findings, target_file)
        inbound_paths, cross_file_paths = self._split_paths_for_file(graph, paths, target_file)

        cm = confirmation_model or self._config.llama_query_model
        confirmer = VulnerabilityConfirmer(self._llm_provider, cm, self._usage_runtime, self._config.codebase_path)

        file_reach = []
        if inbound_paths:
            file_reach = confirmer.confirm_for_file(target_file, inbound_paths, graph, max_workers=max_workers, progress_callback=progress_callback)

        cross_findings = []
        if cross_file_paths:
            cross_findings = confirmer.confirm_cross_file(target_file, cross_file_paths, graph, max_workers=max_workers, progress_callback=progress_callback)

        all_findings = file_reach + cross_findings + file_supp
        if not all_findings:
            return {"file": target_file, "file_path": abs_target, "reviews": []}

        deduped, _, _ = Deduplicator.deduplicate(all_findings, max_per_sink=max_paths_per_sink)
        grouped = self._group_findings_as_reviews(deduped)
        review = None
        for item in grouped:
            if item.get("file") == target_file: review = item; break
        if review is None:
            review = {"file": target_file, "file_path": abs_target, "reviews": []}
        return review

    def review_single_file_from_codebase(self, file_path, *, extraction_model="gpt-4.1-mini", confirmation_model=None,
                                          max_workers=8, max_paths=0, max_paths_per_sink=3, max_path_length=25,
                                          max_investigation_turns=4, progress_callback=None):
        """Deep file review: Phase 1 (strong model audit) + Phase 2 (multi-turn grep investigation)."""
        abs_target = str(file_path)
        relative_target = str(file_path)

        try:
            abs_target, relative_target = self._normalize_target_file(file_path)

            content = read_file_content(abs_target)
            if not content or not content.strip():
                return {"file": relative_target, "file_path": abs_target, "reviews": []}

            strong_model = confirmation_model or self._config.llama_query_model

            if progress_callback:
                progress_callback({"event": "file_audit_start", "file": relative_target})

            auditor = FileAuditor(self._llm_provider, strong_model, self._usage_runtime)

            try:
                candidates = auditor.audit(relative_target, content)
            except Exception as e:
                logger.exception("File audit crashed for %s: %s", relative_target, e)
                candidates = _prune_audit_candidates(
                    _detect_obvious_local_candidates(content)
                    + _detect_driver_specific_candidates(relative_target, content)
                    + _detect_stale_after_unlock_candidates(relative_target, content)
                    + _detect_width_mismatch_candidates(relative_target, content)
                    + _detect_fileops_candidates(relative_target, content)
                    + _detect_logging_candidates(relative_target, content)
                    + _detect_compiler_semantic_candidates(relative_target, content),
                    limit=25,
                )

            if progress_callback:
                progress_callback({"event": "file_audit_done", "candidates": len(candidates), "file": relative_target})

            if not candidates:
                return {"file": relative_target, "file_path": abs_target, "reviews": []}

            if progress_callback:
                progress_callback({"event": "investigation_start", "total": len(candidates), "file": relative_target})

            try:
                investigator = FindingInvestigator(
                    self._llm_provider, strong_model, self._usage_runtime,
                    self._config.codebase_path,
                )
            except Exception as e:
                logger.exception("Investigator init failed for %s: %s", relative_target, e)
                return {"file": relative_target, "file_path": abs_target, "reviews": []}

            confirmed_findings = []
            lock = threading.Lock()
            done_count = [0]

            def _investigate_one(candidate):
                try:
                    return investigator.investigate(
                        candidate, relative_target, content,
                        max_turns=max_investigation_turns,
                    )
                except Exception as e:
                    logger.warning("Investigation failed for %s/%s: %s",
                                 relative_target, candidate.get("function_name"), e)
                    return None

            worker_count = max(1, min(max_workers, len(candidates)))
            with ThreadPoolExecutor(max_workers=worker_count) as ex:
                futs = {submit_with_current_context(ex, _investigate_one, c): c for c in candidates}
                for fut in as_completed(futs):
                    c = futs[fut]
                    try:
                        verdict = fut.result()
                        if verdict and verdict.get("is_vulnerable"):
                            with lock:
                                confirmed_findings.append(verdict)
                    except Exception as e:
                        logger.warning("Investigation error for %s/%s: %s", relative_target, c.get("function_name"), e)
                    with lock:
                        done_count[0] += 1
                    if progress_callback:
                        progress_callback({"event": "investigation_progress",
                                         "completed": done_count[0], "total": len(candidates),
                                         "file": relative_target})

            if progress_callback:
                progress_callback({"event": "investigation_done", "confirmed": len(confirmed_findings), "file": relative_target})

            if not confirmed_findings:
                return {"file": relative_target, "file_path": abs_target, "reviews": []}

            reviews = []
            seen_keys = set()
            normalized_verdicts = []
            for item in confirmed_findings:
                mechanism = _normalize_mechanism(item.get("mechanism"), item.get("vulnerability_type"))
                vtype = _resolve_vulnerability_type(mechanism, item.get("vulnerability_type") or "other")
                item["mechanism"] = mechanism
                item["mechanism_family"] = _mechanism_family(mechanism, vtype)
                item["vulnerability_type"] = vtype
                normalized_verdicts.append(item)

            for v in sorted(normalized_verdicts, key=lambda item: _candidate_priority_key({
                "type": str(item.get("vulnerability_type") or "other"),
                "mechanism": str(item.get("mechanism") or "generic_memory"),
                "mechanism_family": str(item.get("mechanism_family") or ""),
                "severity": str(item.get("severity") or "medium").lower(),
                "line": int(item.get("line") or 1),
                "primary": True,
                "locality": "local_direct" if str(item.get("reachability_chain") or "").startswith("Target file") else "cross_file",
                "driver_context": _looks_driver_file(relative_target, content),
            })):
                fn = str(v.get("function_name") or "unknown")
                vtype = str(v.get("vulnerability_type") or "other")
                mechanism = str(v.get("mechanism") or "generic_memory")
                mechanism_family = str(v.get("mechanism_family") or _mechanism_family(mechanism, vtype))
                line = 1
                try:
                    line = max(1, int(v.get("line", 1)))
                except Exception:
                    pass

                dedup_key = (fn, mechanism_family)
                if dedup_key in seen_keys:
                    continue
                seen_keys.add(dedup_key)

                code_snippet = _read_line_context(self._config.codebase_path, relative_target, line, context=2)

                chain = str(v.get("reachability_chain") or "")
                evidence = str(v.get("evidence") or "")
                root_cause = str(v.get("root_cause") or "")
                description = str(v.get("description") or f"{vtype.replace('_', ' ')} in {fn}")

                reasoning_parts = [f"Mechanism: {mechanism}"]
                if evidence:
                    reasoning_parts.append(evidence)
                if chain:
                    reasoning_parts.append(f"Reachability path: {chain}")
                if root_cause:
                    reasoning_parts.append(f"Root cause: {root_cause}")

                reviews.append({
                    "issue": description,
                    "line_number": line,
                    "code_snippet": code_snippet,
                    "cwe": _cwe_for(vtype, mechanism),
                    "severity": _severity_title(v.get("severity"), "Medium"),
                    "confidence": _severity_title(v.get("confidence"), "Medium"),
                    "reasoning": "\n".join(reasoning_parts),
                    "mitigation": root_cause,
                })

            return {"file": relative_target, "file_path": abs_target, "reviews": reviews}

        except Exception as e:
            logger.exception("review_single_file_from_codebase failed for %s: %s", file_path, e)
            if progress_callback:
                try:
                    progress_callback({"event": "review_file_error", "file": relative_target, "error": str(e)})
                except Exception:
                    pass
            return {"file": relative_target, "file_path": abs_target, "reviews": []}    


    def _group_findings_as_reviews(self, findings):
        grouped = defaultdict(list)
        base_path = os.path.abspath(self._config.codebase_path)
        for finding in findings:
            rel_file = finding.sink_file or finding.source_file
            if not rel_file: continue
            abs_file = rel_file if os.path.isabs(rel_file) else os.path.join(base_path, rel_file)
            grouped[(rel_file, os.path.abspath(abs_file))].append(self._finding_to_review(finding))
        return [{"file": rf, "file_path": af, "reviews": revs} for (rf, af), revs in grouped.items()]

    def _finding_to_review(self, finding):
        line_number = int(finding.sink_line or finding.source_line or 1)
        issue = str(finding.description).strip() if str(finding.description or "").strip() else f"{finding.vulnerability_type.replace('_', ' ')} in {finding.sink_function}"
        reasoning_parts = [f"Mechanism: {getattr(finding, 'mechanism', '') or _normalize_mechanism('', finding.vulnerability_type)}"]
        if str(finding.evidence or "").strip(): reasoning_parts.append(str(finding.evidence).strip())
        if finding.path: reasoning_parts.append(f"Reachability path: {' -> '.join(finding.path)}")
        if str(finding.root_cause or "").strip(): reasoning_parts.append(f"Root cause: {str(finding.root_cause).strip()}")
        code_snippet = ""
        target_file = finding.sink_file or finding.source_file
        if target_file: code_snippet = _read_line_context(self._config.codebase_path, target_file, line_number, context=2)
        return {
            "issue": issue, "line_number": line_number, "code_snippet": code_snippet,
            "cwe": _cwe_for(str(finding.vulnerability_type or "").strip(), getattr(finding, "mechanism", "")),
            "severity": _severity_title(finding.severity, "Medium"),
            "confidence": _severity_title(finding.confidence, "Medium"),
            "reasoning": "\n".join(reasoning_parts),
            "mitigation": str(finding.root_cause or "").strip(),
        }

    @staticmethod
    def deduplicate_and_write(findings, output_path, *, max_paths_per_sink=3):
        deduped, total, removed = Deduplicator.deduplicate(findings, max_per_sink=max_paths_per_sink)
        _write_jsonl(output_path, deduped)
        return deduped, total, removed


def _write_jsonl(path, findings):
    out = Path(path); out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        for f in findings: fh.write(json.dumps(f.to_dict(), ensure_ascii=False) + "\n")
