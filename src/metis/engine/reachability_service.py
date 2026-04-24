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

def _severity_rank(value):
    return {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(str(value or "medium").strip().lower(), 5)

def _type_rank(value):
    return {
        "command_injection": 0,
        "path_traversal": 1,
        "buffer_overflow": 2,
        "sscanf_overflow": 3,
        "format_string": 4,
        "out_of_bounds": 5,
        "integer_overflow": 6,
        "use_after_free": 7,
        "double_free": 8,
        "type_confusion": 9,
        "boolean_coercion": 10,
        "stale_length": 11,
        "wrong_constant": 12,
        "wrong_field": 13,
        "missing_auth": 14,
        "permission_escalation": 15,
        "toctou": 30,
        "null_deref": 31,
        "fd_leak": 32,
        "other": 40,
    }.get(str(value or "other").strip(), 50)

def _candidate_priority_key(candidate):
    return (
        0 if candidate.get("primary") else 1,
        0 if candidate.get("locality") == "local_direct" else 1,
        _severity_rank(candidate.get("severity")),
        _type_rank(candidate.get("type")),
        int(candidate.get("line") or 0),
    )

def _verdict_priority_key(verdict):
    locality = "local_direct" if str(verdict.get("reachability_chain") or "").startswith("Target file") else "cross_file"
    return (
        0 if locality == "local_direct" else 1,
        _severity_rank(verdict.get("severity")),
        _type_rank(verdict.get("vulnerability_type")),
        int(verdict.get("line") or 0),
    )

def _normalize_candidate(candidate):
    normalized = dict(candidate)
    normalized["function_name"] = str(normalized.get("function_name") or "unknown").strip() or "unknown"
    try:
        normalized["line"] = max(1, int(normalized.get("line", 1)))
    except:
        normalized["line"] = 1
    normalized["type"] = str(normalized.get("type") or "other").strip() or "other"
    normalized["severity"] = str(normalized.get("severity") or "medium").strip().lower()
    normalized["description"] = str(normalized.get("description") or "").strip()
    normalized["locality"] = str(normalized.get("locality") or "cross_file").strip()
    normalized["primary"] = bool(normalized.get("primary"))
    normalized["cross_file_concern"] = bool(normalized.get("cross_file_concern"))
    normalized["code_snippet"] = str(normalized.get("code_snippet") or "")
    normalized["investigation_hints"] = _merge_hint_lists(normalized.get("investigation_hints") or [])
    return normalized

def _candidate_is_direct_primary(candidate):
    return bool(candidate.get("primary")) and str(candidate.get("locality") or "") == "local_direct"

def _low_signal_type(candidate_type):
    return str(candidate_type or "").strip() in {
        "null_deref", "fd_leak", "toctou", "other", "ignored_return"
    }

def _candidate_group_key(candidate):
    return (
        str(candidate.get("function_name") or "unknown").strip(),
        int(candidate.get("line") or 1),
    )

def _prune_audit_candidates(candidates, limit=12):
    if not candidates:
        return []

    merged = {}
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        c = _normalize_candidate(candidate)
        key = (c["function_name"], c["line"], c["type"])
        existing = merged.get(key)
        if existing is None:
            merged[key] = c
            continue

        better, worse = (c, existing) if _candidate_priority_key(c) < _candidate_priority_key(existing) else (existing, c)
        better["investigation_hints"] = _merge_hint_lists(better.get("investigation_hints"), worse.get("investigation_hints"))
        better["primary"] = bool(better.get("primary")) or bool(worse.get("primary"))
        better["cross_file_concern"] = bool(better.get("cross_file_concern")) or bool(worse.get("cross_file_concern"))
        if better.get("locality") != "local_direct" and worse.get("locality") == "local_direct":
            better["locality"] = "local_direct"
        if len(str(worse.get("description") or "")) > len(str(better.get("description") or "")):
            better["description"] = str(worse.get("description") or "")
        if not str(better.get("code_snippet") or "") and str(worse.get("code_snippet") or ""):
            better["code_snippet"] = str(worse.get("code_snippet") or "")
        if _severity_rank(worse.get("severity")) < _severity_rank(better.get("severity")):
            better["severity"] = str(worse.get("severity") or "medium").lower()
        merged[key] = better

    ordered = sorted(merged.values(), key=_candidate_priority_key)

    strong_groups = {
        _candidate_group_key(c)
        for c in ordered
        if _candidate_is_direct_primary(c)
    }

    pruned = []
    per_group_counts = defaultdict(int)

    for candidate in ordered:
        group = _candidate_group_key(candidate)

        if group in strong_groups and not _candidate_is_direct_primary(candidate):
            if _low_signal_type(candidate.get("type")):
                continue

        if per_group_counts[group] >= (1 if group in strong_groups else 2):
            continue

        if _low_signal_type(candidate.get("type")) and not candidate.get("cross_file_concern") and not candidate.get("primary"):
            continue

        pruned.append(candidate)
        per_group_counts[group] += 1

    return pruned[:limit]

def _detect_obvious_local_candidates(file_content):
    lines = file_content.splitlines()
    function_starts = _collect_function_starts(lines)
    candidates = []

    command_re = re.compile(r"\b(?:system|popen|_popen|execl|execv|execvp|execve)\s*\(")
    format_sink_re = re.compile(r"\b(?:sprintf|vsprintf|strcpy|strcat|gets)\s*\(")
    scanf_re = re.compile(r"\b(?:sscanf|scanf)\s*\(")
    open_re = re.compile(r"\b(?:std::ifstream|std::ofstream|ifstream|ofstream|fopen|open|freopen)\b")
    alloc_mul_re = re.compile(r"\b(?:malloc|calloc|realloc)\s*\([^)]*\*[^)]*\)")
    printf_re = re.compile(r"\b(?:printf|fprintf|sprintf|snprintf|syslog)\s*\(")

    for idx, line in enumerate(lines):
        stripped = line.strip()
        line_number = idx + 1
        function_name = _function_name_for_line(function_starts, line_number)
        window_before = "\n".join(lines[max(0, idx - 5):idx + 1])
        window_local = "\n".join(lines[max(0, idx - 4):min(len(lines), idx + 4)])
        code_snippet = _line_context_from_content(file_content, line_number, context=3)

        if command_re.search(stripped):
            if any(token in window_local for token in (' + ', '.append(', 'command', 'cmd', '.string()', 'destination', 'path', 'report_name')):
                candidates.append({
                    "function_name": function_name,
                    "line": line_number,
                    "type": "command_injection",
                    "severity": "high",
                    "description": "Shell command execution uses variable data in the target file, which is a classic command-injection pattern.",
                    "locality": "local_direct",
                    "primary": True,
                    "cross_file_concern": False,
                    "code_snippet": code_snippet,
                    "investigation_hints": [f"{function_name}(", "system(", "popen("] if function_name != "unknown" else ["system(", "popen("],
                })

        if format_sink_re.search(stripped):
            candidates.append({
                "function_name": function_name,
                "line": line_number,
                "type": "buffer_overflow",
                "severity": "high",
                "description": "The target file contains an unbounded write primitive into a caller-visible or fixed-size buffer.",
                "locality": "local_direct",
                "primary": True,
                "cross_file_concern": False,
                "code_snippet": code_snippet,
                "investigation_hints": [f"{function_name}(", "sprintf(", "strcpy("] if function_name != "unknown" else ["sprintf(", "strcpy("],
            })

        if scanf_re.search(stripped) and "%s" in window_local:
            candidates.append({
                "function_name": function_name,
                "line": line_number,
                "type": "sscanf_overflow",
                "severity": "high",
                "description": "The target file uses scanf-style parsing with %s and no visible width bound, which can overflow fixed buffers.",
                "locality": "local_direct",
                "primary": True,
                "cross_file_concern": False,
                "code_snippet": code_snippet,
                "investigation_hints": [f"{function_name}(", "sscanf(", "%s"] if function_name != "unknown" else ["sscanf(", "%s"],
            })

        if open_re.search(stripped):
            if any(token in window_before for token in (' + "/" + ', '+ "/" +', 'std::filesystem::path', 'fs::path', ' / (', '/ (', '.append("/")', 'path =', '.string()', '.c_str()')):
                candidates.append({
                    "function_name": function_name,
                    "line": max(1, line_number - 1),
                    "type": "path_traversal",
                    "severity": "high",
                    "description": "The target file constructs a filesystem path from variable input and then opens it without visible normalization or validation.",
                    "locality": "local_direct",
                    "primary": True,
                    "cross_file_concern": False,
                    "code_snippet": _line_context_from_content(file_content, max(1, line_number - 1), context=3),
                    "investigation_hints": [f"{function_name}(", "ifstream", "fopen("] if function_name != "unknown" else ["ifstream", "fopen("],
                })

        if alloc_mul_re.search(stripped):
            candidates.append({
                "function_name": function_name,
                "line": line_number,
                "type": "integer_overflow",
                "severity": "medium",
                "description": "The target file performs multiplication inside an allocation expression, which can overflow and under-allocate memory.",
                "locality": "local_direct",
                "primary": False,
                "cross_file_concern": False,
                "code_snippet": code_snippet,
                "investigation_hints": [f"{function_name}(", "malloc(", "realloc("] if function_name != "unknown" else ["malloc(", "realloc("],
            })

        if printf_re.search(stripped):
            arg_text = stripped.split("(", 1)[1] if "(" in stripped else ""
            if arg_text and not arg_text.lstrip().startswith(("\"", "'")):
                if "printf(" in stripped or "fprintf(" in stripped or "syslog(" in stripped:
                    candidates.append({
                        "function_name": function_name,
                        "line": line_number,
                        "type": "format_string",
                        "severity": "high",
                        "description": "The target file appears to pass variable data as a format string in a printf-style API.",
                        "locality": "local_direct",
                        "primary": True,
                        "cross_file_concern": False,
                        "code_snippet": code_snippet,
                        "investigation_hints": [f"{function_name}(", "printf(", "fprintf("] if function_name != "unknown" else ["printf(", "fprintf("],
                    })

    return _prune_audit_candidates(candidates, limit=12)

def _candidate_is_local_direct(candidate):
    if str(candidate.get("locality") or "").strip() == "local_direct":
        return True
    return str(candidate.get("type") or "").strip() in {
        "command_injection", "buffer_overflow", "sscanf_overflow", "path_traversal",
        "format_string", "integer_overflow", "out_of_bounds",
    }

def _fallback_select_best_verdicts(verdicts, limit=3):
    if not verdicts:
        return []
    ordered = sorted(verdicts, key=_verdict_priority_key)
    selected = []
    seen = set()
    for verdict in ordered:
        key = (
            str(verdict.get("function_name") or "unknown"),
            str(verdict.get("vulnerability_type") or "other"),
        )
        if key in seen:
            continue
        seen.add(key)
        selected.append(verdict)
        if len(selected) >= limit:
            break
    return selected

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
}


# Graph builder


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
{{"functions": [{{"name": "example", "line": 1, "calls": [], "is_source": false, \
"source_reason": "", "is_sink": false, "sink_type": "", "sink_reason": ""}}]}}

If the file has no function definitions, return: {{"functions": []}}"""

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
Return ONLY valid JSON:
{{"findings": [{{"path_index": 0, "is_vulnerable": true, "vulnerability_type": "buffer_overflow",
"severity": "high", "confidence": "high", "description": "...", "root_cause": "...", "evidence": "..."}}]}}
vulnerability_type: buffer_overflow, use_after_free, double_free, null_deref, command_injection, format_string, \
integer_overflow, path_traversal, race_condition, uninitialized_memory, type_confusion, out_of_bounds, other.
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
Return ONLY valid JSON:
{{"findings": [{{"path_index": 0, "is_vulnerable": true, "vulnerability_type": "buffer_overflow",
"severity": "high", "confidence": "high", "description": "...", "root_cause": "...", "evidence": "..."}}]}}
vulnerability_type: buffer_overflow, use_after_free, double_free, null_deref, command_injection, format_string, \
integer_overflow, path_traversal, race_condition, uninitialized_memory, type_confusion, out_of_bounds, other.
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

For each finding, identify both the focus-file function involved AND the caller \
function in the other file where the misuse occurs.

Return ONLY valid JSON:
{{"findings": [{{"path_index": 0, "is_vulnerable": true, "vulnerability_type": "boolean_coercion",
"severity": "high", "confidence": "high",
"description": "...", "root_cause": "...", "evidence": "..."}}]}}

vulnerability_type: boolean_coercion, double_free, double_close, buffer_overflow, \
use_after_free, wrong_constant, stale_length, type_confusion, other.
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

Prefer the PRIMARY direct bug over speculative secondary issues.
For example, if a function constructs a shell command from variable input and calls system(),
prefer command_injection over toctou.

Only reject the candidate if clear mitigation is visible in the shown code.
Return ONLY valid JSON:
{{"verdict": {{
  "is_vulnerable": true,
  "vulnerability_type": "command_injection",
  "severity": "high",
  "confidence": "high",
  "function_name": "SendReport",
  "line": 0,
  "description": "...",
  "root_cause": "...",
  "evidence": "...",
  "reachability_chain": "Target file local path"
}}}}

Set is_vulnerable to false only if the shown code clearly mitigates the issue."""

_LOCAL_CONFIRM_USR = """Candidate type: {candidate_type}
Candidate description: {candidate_description}
Function: {function_name}
Line: {line}

== TARGET FILE CODE ==
{target_file_code}

== LOCAL CONTEXT ==
{local_context}
"""

_INVESTIGATE_VERIFY_SYS = """\
You are the strong verifier for a single-file C/C++ security review.

Your job is to decide whether the candidate is a real, report-worthy vulnerability after
reviewing:
- the candidate claim
- the full target file
- grep/read evidence collected from the repo
- an optional draft verdict from the reasoning model

Rules:
- Prefer the PRIMARY direct bug over speculative secondary bugs.
- For obvious unsafe sink patterns in the target file, local file evidence is sufficient.
- For cross-file, ownership, lifecycle, or caller-dependent issues, require repo evidence.
- Do not emit generic low-value findings when a stronger direct bug exists in the same function/area.
- Avoid duplicates and near-duplicates.
- Suppress allocation-failure-only, leak-only, and generic null-check findings unless they form the core security issue.

Return ONLY valid JSON:
{{"verdict": {{
  "is_vulnerable": true,
  "vulnerability_type": "command_injection",
  "severity": "high",
  "confidence": "high",
  "function_name": "SendReport",
  "line": 0,
  "description": "...",
  "root_cause": "...",
  "evidence": "...",
  "reachability_chain": "Target file local path"
}}}}

Set is_vulnerable to false if the candidate should not be kept."""

_INVESTIGATE_VERIFY_USR = """== CANDIDATE ==
Function: {function_name}
Line: {line}
Type: {candidate_type}
Severity: {severity}
Locality: {locality}
Primary: {primary}
Cross-file concern: {cross_file_concern}
Description: {description}

== TARGET FILE: {target_file} ==
{target_file_code}

== INVESTIGATION TRANSCRIPT ==
{transcript}

== DRAFT VERDICT ==
{draft_verdict}
"""

_SELECT_BEST_REVIEWS_SYS = """\
You are the final strong selector for single-file security review findings.

You are given several already-confirmed candidate findings for one target file.
Select the best 1 to 3 findings to keep.

Selection rules:
- Keep the strongest benchmark-relevant findings.
- Prefer primary direct bugs over secondary or speculative issues.
- Prefer command injection, path traversal, buffer overflow, format string, out-of-bounds,
  use-after-free, and direct integer-overflow-to-underallocation bugs.
- Drop duplicates and near-duplicates.
- Drop generic null checks, allocation-failure-only issues, leak-only issues, and weak
  secondary TOCTOU findings when a stronger direct sink bug exists in the same function.
- If multiple findings describe the same root cause family, keep only the strongest one.

Return ONLY valid JSON:
{{"selected_indices": [0, 2]}}
"""

_SELECT_BEST_REVIEWS_USR = """Target file: {target_file}

== TARGET FILE CODE ==
{target_file_code}

== CONFIRMED FINDINGS ==
{findings_section}
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
            results.append(VulnerabilityFinding(
                id=uuid.uuid4().hex[:16], vulnerability_type=str(e.get("vulnerability_type") or rp.sink_type or "other"),
                severity=str(e.get("severity") or "medium"), confidence=str(e.get("confidence") or "medium"),
                source_function=rp.source, source_file=sn.file_path if sn else "", source_line=sn.line_number if sn else 0,
                sink_function=rp.sink, sink_file=sk.file_path if sk else "", sink_line=sk.line_number if sk else 0,
                path=list(rp.path), description=str(e.get("description") or ""),
                root_cause=str(e.get("root_cause") or ""), evidence=str(e.get("evidence") or ""), analysis_type="reachability"))
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
            results.append(VulnerabilityFinding(
                id=uuid.uuid4().hex[:16], vulnerability_type=str(e.get("vulnerability_type") or "other"),
                severity=str(e.get("severity") or "medium"), confidence=str(e.get("confidence") or "medium"),
                source_function=rp.source, source_file=sn.file_path if sn else "",
                source_line=sn.line_number if sn else 0,
                sink_function=sink_fn, sink_file=sink_file, sink_line=sink_line,
                path=list(rp.path), description=str(e.get("description") or ""),
                root_cause=str(e.get("root_cause") or ""), evidence=str(e.get("evidence") or ""),
                analysis_type="cross_file"))
        return results

    def confirm_local_candidate(self, candidate, target_file, target_file_content):
        kw = self._u.hooks.chat_model_kwargs()
        chat = self._p.get_chat_model(model=self._m, max_tokens=self._t, temperature=0.1, **kw)
        local_context = str(candidate.get("code_snippet") or "")
        if not local_context:
            local_context = _line_context_from_content(target_file_content, candidate.get("line") or 1, context=5)
        prompt = ChatPromptTemplate.from_messages([("system", _LOCAL_CONFIRM_SYS), ("user", _LOCAL_CONFIRM_USR)])
        raw = (prompt | chat | StrOutputParser()).invoke({
            "candidate_type": str(candidate.get("type") or "other"),
            "candidate_description": str(candidate.get("description") or ""),
            "function_name": str(candidate.get("function_name") or "unknown"),
            "line": int(candidate.get("line") or 1),
            "target_file_code": _number_lines(target_file_content),
            "local_context": local_context,
        }).strip()
        parsed = parse_json_output(raw)
        if not isinstance(parsed, dict):
            return None
        verdict = parsed.get("verdict")
        if not isinstance(verdict, dict):
            return None
        return verdict


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
{{"findings": [{{"vulnerability_type": "double_free", "severity": "high", "confidence": "high", \
"function_name": "handle_set", "line": 55, "description": "...", "root_cause": "...", "evidence": "..."}}]}}
Return {{"findings": []}} if none found. Be thorough."""

_INTRA_USR = "File: {file_path}\n\n{functions_code}"

_LIFE_SYS = """\
You are analyzing a C/C++ codebase for USE-AFTER-FREE, DANGLING POINTER, and LIFETIME bugs spanning MULTIPLE functions.
Below are ALL functions. Analyze their INTERACTIONS:
1. USE-AFTER-FREE: Function A frees a resource, Function B later dereferences it.
2. DANGLING POINTERS: Pointers in global/shared structures not NULLed when target freed.
3. LIFETIME MISMATCH: Object A stores pointer to B, but B can be destroyed while A exists.
Return ONLY valid JSON:
{{"findings": [{{"vulnerability_type": "use_after_free", "severity": "high", "confidence": "high", \
"free_function": "session_close", "use_function": "store_lookup", \
"description": "...", "root_cause": "...", "evidence": "..."}}]}}
Return {{"findings": []}} if none found."""

_LIFE_USR = "{all_functions_code}"

_OWN_SYS = """\
You are analyzing a C/C++ codebase for RESOURCE OWNERSHIP, POINTER INVALIDATION, and CLEANUP COORDINATION bugs.
Examine ALL functions below for:
1. DOUBLE-FREE / DOUBLE-CLOSE ACROSS FUNCTIONS: Function A frees on error, caller also frees.
2. USE-AFTER-REALLOC / STALE POINTERS: Code caches pointer then calls function that may realloc/grow/compact.
3. CALLBACK / REGISTRATION LIFECYCLE: Register callback with object as context, free object without unregistering.
4. REFCOUNT IMBALANCE: store_ref then store_unref called unequally.
Return ONLY valid JSON:
{{"findings": [{{"vulnerability_type": "double_free", "severity": "high", "confidence": "high", \
"function_a": "proto_parse", "function_b": "dispatch", \
"description": "...", "root_cause": "...", "evidence": "..."}}]}}
Return {{"findings": []}} if none found."""

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
{{"findings": [{{"vulnerability_type": "boolean_coercion", "severity": "high", "confidence": "high", \
"function_name": "dispatch", "related_function": "auth_get_level", \
"description": "...", "root_cause": "...", "evidence": "..."}}]}}
Return {{"findings": []}} if none found. Be EXTREMELY thorough."""

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
            results.append(VulnerabilityFinding(
                id=uuid.uuid4().hex[:16], vulnerability_type=str(e.get("vulnerability_type") or "other"),
                severity=str(e.get("severity") or "medium"), confidence=str(e.get("confidence") or "medium"),
                source_function=fn.unique_name, source_file=fn.file_path, source_line=line,
                sink_function=fn.unique_name, sink_file=fn.file_path, sink_line=line,
                path=[fn.unique_name], description=str(e.get("description") or ""),
                root_cause=str(e.get("root_cause") or ""), evidence=str(e.get("evidence") or ""),
                analysis_type="intra_function"))
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
            results.append(VulnerabilityFinding(
                id=uuid.uuid4().hex[:16], vulnerability_type=str(e.get("vulnerability_type") or "use_after_free"),
                severity=str(e.get("severity") or "high"), confidence=str(e.get("confidence") or "medium"),
                source_function=fa.unique_name, source_file=fa.file_path, source_line=fa.line_number,
                sink_function=fb.unique_name, sink_file=fb.file_path, sink_line=fb.line_number,
                path=[fa.unique_name, fb.unique_name], description=str(e.get("description") or ""),
                root_cause=str(e.get("root_cause") or ""), evidence=str(e.get("evidence") or ""),
                analysis_type=analysis_type))
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
            results.append(VulnerabilityFinding(
                id=uuid.uuid4().hex[:16], vulnerability_type=str(e.get("vulnerability_type") or "other"),
                severity=str(e.get("severity") or "medium"), confidence=str(e.get("confidence") or "medium"),
                source_function=src_fn.unique_name, source_file=src_fn.file_path, source_line=src_fn.line_number,
                sink_function=fn.unique_name, sink_file=fn.file_path, sink_line=fn.line_number,
                path=[src_fn.unique_name, fn.unique_name] if rf else [fn.unique_name],
                description=str(e.get("description") or ""), root_cause=str(e.get("root_cause") or ""),
                evidence=str(e.get("evidence") or ""), analysis_type="semantic"))
        return results


# deduplicator

class Deduplicator:
    @staticmethod
    def deduplicate(findings, *, max_per_sink=3):
        if not findings: return [], 0, 0
        groups = defaultdict(list)
        for f in findings: groups[(f.sink_function, f.vulnerability_type)].append(f)
        selected = []
        for g in groups.values(): selected.extend(_select_diverse(g, max_per_sink))
        return selected, len(findings), len(findings) - len(selected)

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


# service

_FILE_AUDIT_SYS = """\
You are a world-class C/C++ security auditor performing an exhaustive review of a \
single source file from a larger codebase. Your job is to find EVERY potential \
security issue — confirmed bugs AND suspicious patterns that MIGHT be exploitable \
depending on how the rest of the codebase uses this file's functions.

## Categories to check thoroughly

1. MEMORY SAFETY: buffer overflow, heap/stack overflow (including via sscanf %%s \
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
unbounded %%s, sign confusion (int32 vs uint32 vs size_t), integer overflow in \
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

## Output format

Prefer the PRIMARY direct bug over speculative secondary issues. For example:
- prefer command injection over toctou when a shell command is built from variable input
- prefer buffer_overflow over vague downstream memory-corruption concerns when sprintf/strcpy is present
- prefer path_traversal when a path is built from variable input and opened without validation

Avoid noisy, low-value candidates unless they appear to be the actual main issue:
- generic null checks
- allocation-failure-only crashes
- leak-only findings
- weak secondary TOCTOU findings when a stronger direct sink is present

For each issue found, classify locality:
- local_direct: the target file itself shows a classic unsafe sink or missing validation pattern that can be confirmed from this file alone
- cross_file: the issue likely depends on caller behavior, ownership across files, or wider repo context

Return ONLY valid JSON. For each issue found, include investigation_hints — short \
grep patterns or function names a reviewer should search for in the rest of the \
codebase to determine reachability and exploitability.

{{"candidates": [
  {{"function_name": "func_name", "line": 42, "type": "double_close",
    "severity": "high", "description": "conn_close closes c->fd but caller may also close the same fd",
    "locality": "cross_file", "primary": false,
    "cross_file_concern": true,
    "code_snippet": "...",
    "investigation_hints": ["conn_close(", "close(cfd)"]}}
]}}

If you find NOTHING, return {{"candidates": []}}. But be thorough — err on the side \
of flagging suspicious patterns. It is much better to flag a false positive than to \
miss a real vulnerability."""

_FILE_AUDIT_USR = "File under review: {file_path}\n\n{file_content}"


class FileAuditor:
    """Phase 1: Strong model reviews a single file for all potential security issues."""

    def __init__(self, llm_provider, model, usage_runtime, max_tokens=16384):
        self._p = llm_provider
        self._m = model
        self._u = usage_runtime
        self._t = max_tokens

    def audit(self, file_path, file_content):
        kw = self._u.hooks.chat_model_kwargs()
        chat = self._p.get_chat_model(model=self._m, max_tokens=self._t, temperature=0.1, **kw)
        prompt = ChatPromptTemplate.from_messages([
            ("system", _FILE_AUDIT_SYS),
            ("user", _FILE_AUDIT_USR),
        ])
        raw = (prompt | chat | StrOutputParser()).invoke({
            "file_path": file_path,
            "file_content": _number_lines(file_content),
        }).strip()

        result = []
        parsed = parse_json_output(raw)
        if isinstance(parsed, dict):
            candidates = parsed.get("candidates")
            if isinstance(candidates, list):
                for c in candidates:
                    if not isinstance(c, dict):
                        continue
                    result.append(_normalize_candidate(c))

        static_candidates = _detect_obvious_local_candidates(file_content)
        return _prune_audit_candidates(result + static_candidates, limit=12)


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
{{"actions": [
  {{"type": "search", "pattern": "function_name\\\\("}},
  {{"type": "search", "pattern": "close\\\\(cfd\\\\)"}}
]}}
Maximum 5 search actions per turn. Use specific patterns to avoid huge results.

### 2. Read lines from a file
{{"actions": [
  {{"type": "read", "path": "src/main.c", "start_line": 28, "end_line": 60}}
]}}
Maximum 3 read actions per turn. Max 80 lines per read.

### 3. Conclude your investigation
{{"verdict": {{
  "is_vulnerable": true,
  "vulnerability_type": "double_close",
  "severity": "high",
  "confidence": "high",
  "function_name": "conn_close",
  "line": 58,
  "description": "conn_close closes c->fd, then handle_client also closes cfd which is the same descriptor",
  "root_cause": "Ambiguous fd ownership: conn_close takes ownership and closes c->fd, but handle_client still holds cfd and closes it after conn_close returns",
  "evidence": "src/connection.c:72 close(c->fd); src/main.c:46 close(cfd); cfd == c->fd from conn_create",
  "reachability_chain": "main -> handle_client -> conn_close -> close(c->fd) ... handle_client -> close(cfd)"
}}}}

## Investigation strategy

1. First, use the investigation_hints from the audit to search for relevant callers/callees
2. Read the key functions you find to understand data flow
3. Determine: can an external attacker (network client, file input, etc.) actually reach this code?
4. Check for mitigating factors: bounds checks, auth checks, sanitization
5. When you have enough evidence, conclude with a verdict

For obvious unsafe sink patterns in the target file, local file evidence may be enough.
Use grep mainly for ambiguous, cross-file, ownership, lifecycle, and caller-dependent issues.
Prefer the PRIMARY direct bug over speculative side issues.

If the vulnerability is NOT exploitable or NOT reachable, conclude with is_vulnerable: false.
Be thorough but efficient. Output ONLY valid JSON, no prose."""

_INVESTIGATE_CONCLUDE_SYS = """\
You must now conclude your investigation based on everything you have seen. \
Determine whether the vulnerability candidate is a real, exploitable issue.

For obvious unsafe sink patterns in the target file, do not require repo-level proof of attacker reachability.
If the target file itself shows a classic unsafe sink or missing validation pattern, you may confirm it based on local evidence.
Prefer the PRIMARY direct bug over speculative secondary issues.

Output ONLY valid JSON:
{{"verdict": {{
  "is_vulnerable": true,
  "vulnerability_type": "...",
  "severity": "high",
  "confidence": "high",
  "function_name": "...",
  "line": 0,
  "description": "...",
  "root_cause": "...",
  "evidence": "...",
  "reachability_chain": "func_a -> func_b -> func_c"
}}}}

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


class FindingInvestigator:
    """Phase 2: Multi-turn investigation of each candidate finding via grep."""

    def __init__(self, llm_provider, model, verifier_model, usage_runtime, codebase_path, max_tokens=4096):
        self._p = llm_provider
        self._m = model
        self._vm = verifier_model
        self._u = usage_runtime
        self._cb = os.path.abspath(codebase_path)
        self._t = max_tokens

    def investigate(self, candidate, target_file, target_file_content, *, max_turns=3):
        """Investigate a single candidate finding. Returns a verdict dict or None."""
        candidate = _normalize_candidate(candidate)

        if _candidate_is_local_direct(candidate):
            local_verdict = self._confirm_local_direct(candidate, target_file, target_file_content)
            if isinstance(local_verdict, dict) and local_verdict.get("is_vulnerable"):
                return local_verdict
            if isinstance(local_verdict, dict) and not candidate.get("cross_file_concern"):
                return local_verdict

        kw = self._u.hooks.chat_model_kwargs()
        reasoning_chat = self._p.get_chat_model(model=self._m, max_tokens=self._t, temperature=0.1, **kw)

        initial_user = self._build_initial_prompt(candidate, target_file, target_file_content)
        messages = [
            SystemMessage(content=_INVESTIGATE_SYS),
            HumanMessage(content=initial_user),
        ]
        transcript_parts = [initial_user]
        proposed_verdict = None

        for turn in range(max(1, min(max_turns, 3))):
            is_last_turn = (turn == max(1, min(max_turns, 3)) - 1)

            if is_last_turn:
                messages.append(HumanMessage(content=(
                    "This is your final reasoning turn. Either output a verdict now, or output no more actions."
                )))
                call_messages = [SystemMessage(content=_INVESTIGATE_CONCLUDE_SYS)] + messages[1:]
            else:
                call_messages = messages

            try:
                response = reasoning_chat.invoke(call_messages)
                raw = response.content if hasattr(response, "content") else str(response)
            except Exception as e:
                logger.warning("Investigation call failed on turn %d: %s", turn, e)
                break

            transcript_parts.append(f"=== MODEL TURN {turn + 1} ===\n{raw}")
            parsed = parse_json_output(str(raw).strip())
            if not isinstance(parsed, dict):
                messages.append(AIMessage(content=raw))
                messages.append(HumanMessage(content="Please output valid JSON only — either actions or a verdict."))
                transcript_parts.append("=== SYSTEM FEEDBACK ===\nPlease output valid JSON only.")
                continue

            verdict = parsed.get("verdict")
            if isinstance(verdict, dict):
                proposed_verdict = verdict
                break

            actions = parsed.get("actions")
            if not isinstance(actions, list) or not actions:
                messages.append(AIMessage(content=raw))
                messages.append(HumanMessage(content="Output actions to search/read the codebase, or a verdict to conclude."))
                transcript_parts.append("=== SYSTEM FEEDBACK ===\nNo valid actions or verdict returned.")
                continue

            results_text = self._execute_actions(actions)
            messages.append(AIMessage(content=raw))
            messages.append(HumanMessage(content=f"Results from your actions:\n\n{results_text}\n\nContinue investigating or conclude with a verdict."))
            transcript_parts.append(f"=== ACTION RESULTS ===\n{results_text}")

        return self._verify_with_strong(candidate, target_file, target_file_content, "\n\n".join(transcript_parts), proposed_verdict)

    def _confirm_local_direct(self, candidate, target_file, target_file_content):
        try:
            confirmer = VulnerabilityConfirmer(self._p, self._vm, self._u, self._cb, max_tokens=self._t)
            verdict = confirmer.confirm_local_candidate(candidate, target_file, target_file_content)
            if isinstance(verdict, dict):
                return verdict
        except Exception as e:
            logger.warning("Local confirmation failed for %s/%s: %s", target_file, candidate.get("function_name"), e)
        return None

    def _verify_with_strong(self, candidate, target_file, target_file_content, transcript, proposed_verdict):
        kw = self._u.hooks.chat_model_kwargs()
        strong_chat = self._p.get_chat_model(model=self._vm, max_tokens=self._t, temperature=0.1, **kw)
        prompt = ChatPromptTemplate.from_messages([
            ("system", _INVESTIGATE_VERIFY_SYS),
            ("user", _INVESTIGATE_VERIFY_USR),
        ])
        try:
            raw = (prompt | strong_chat | StrOutputParser()).invoke({
                "function_name": str(candidate.get("function_name") or "unknown"),
                "line": int(candidate.get("line") or 1),
                "candidate_type": str(candidate.get("type") or "other"),
                "severity": str(candidate.get("severity") or "medium"),
                "locality": str(candidate.get("locality") or "cross_file"),
                "primary": bool(candidate.get("primary")),
                "cross_file_concern": bool(candidate.get("cross_file_concern")),
                "description": str(candidate.get("description") or ""),
                "target_file": target_file,
                "target_file_code": _number_lines(target_file_content),
                "transcript": transcript or "(no investigation transcript)",
                "draft_verdict": json.dumps(proposed_verdict, ensure_ascii=False, indent=2) if isinstance(proposed_verdict, dict) else "(none)",
            }).strip()
        except Exception as e:
            logger.warning("Strong verification failed for %s/%s: %s", target_file, candidate.get("function_name"), e)
            return proposed_verdict if isinstance(proposed_verdict, dict) else None

        parsed = parse_json_output(raw)
        if not isinstance(parsed, dict):
            return proposed_verdict if isinstance(proposed_verdict, dict) else None
        verdict = parsed.get("verdict")
        if not isinstance(verdict, dict):
            return proposed_verdict if isinstance(proposed_verdict, dict) else None
        return verdict

    def _build_initial_prompt(self, candidate, target_file, target_file_content):
        hints = candidate.get("investigation_hints", [])
        hints_text = ""
        if hints:
            hints_text = f"\nSuggested search patterns to start with: {', '.join(hints)}"

        auto_results = []
        if not _candidate_is_local_direct(candidate):
            for hint in hints[:3]:
                result = _run_grep(hint, self._cb)
                auto_results.append(f"grep '{hint}':\n{result}")
        auto_section = ""
        if auto_results:
            auto_section = "\n\n== INITIAL SEARCH RESULTS (auto-run from investigation hints) ==\n" + "\n\n".join(auto_results)

        return (
            f"== CANDIDATE VULNERABILITY ==\n"
            f"Function: {candidate['function_name']}\n"
            f"Line: {candidate['line']}\n"
            f"Type: {candidate['type']}\n"
            f"Severity: {candidate['severity']}\n"
            f"Locality: {candidate.get('locality', 'cross_file')}\n"
            f"Primary: {candidate.get('primary', False)}\n"
            f"Description: {candidate['description']}\n"
            f"Cross-file concern: {candidate.get('cross_file_concern', False)}\n"
            f"{hints_text}\n\n"
            f"== TARGET FILE: {target_file} ==\n"
            f"{_number_lines(target_file_content)}"
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


class FinalReviewSelector:
    def __init__(self, llm_provider, model, usage_runtime, max_tokens=4096):
        self._p = llm_provider
        self._m = model
        self._u = usage_runtime
        self._t = max_tokens

    def select(self, target_file, target_file_content, verdicts, *, limit=3):
        if not verdicts:
            return []
        limit = max(1, min(int(limit or 3), 3))
        kw = self._u.hooks.chat_model_kwargs()
        chat = self._p.get_chat_model(model=self._m, max_tokens=self._t, temperature=0.1, **kw)

        findings_section_parts = []
        for i, verdict in enumerate(verdicts):
            findings_section_parts.append(
                f"[{i}] type={verdict.get('vulnerability_type')} severity={verdict.get('severity')} "
                f"confidence={verdict.get('confidence')} function={verdict.get('function_name')} "
                f"line={verdict.get('line')}\n"
                f"description={verdict.get('description')}\n"
                f"root_cause={verdict.get('root_cause')}\n"
                f"evidence={verdict.get('evidence')}\n"
                f"reachability_chain={verdict.get('reachability_chain')}\n"
            )

        prompt = ChatPromptTemplate.from_messages([
            ("system", _SELECT_BEST_REVIEWS_SYS),
            ("user", _SELECT_BEST_REVIEWS_USR),
        ])

        try:
            raw = (prompt | chat | StrOutputParser()).invoke({
                "target_file": target_file,
                "target_file_code": _number_lines(target_file_content),
                "findings_section": "\n\n".join(findings_section_parts),
            }).strip()
            parsed = parse_json_output(raw)
            if isinstance(parsed, dict):
                indices = parsed.get("selected_indices")
                if isinstance(indices, list):
                    selected = []
                    seen = set()
                    for idx in indices:
                        try:
                            i = int(idx)
                        except:
                            continue
                        if i < 0 or i >= len(verdicts) or i in seen:
                            continue
                        seen.add(i)
                        selected.append(verdicts[i])
                        if len(selected) >= limit:
                            break
                    if selected:
                        return selected
        except Exception as e:
            logger.warning("Final selector failed for %s: %s", target_file, e)

        return _fallback_select_best_verdicts(verdicts, limit=limit)



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
                                          max_investigation_turns=3, progress_callback=None):
        """Deep file review: Phase 1 (strong model audit) + Phase 2 (multi-turn grep investigation)."""
        abs_target, relative_target = self._normalize_target_file(file_path)

        content = read_file_content(abs_target)
        if not content or not content.strip():
            return {"file": relative_target, "file_path": abs_target, "reviews": []}

        reasoning_model = extraction_model or "gpt-4.1-mini"
        strong_model = confirmation_model or self._config.llama_query_model

        if progress_callback:
            progress_callback({"event": "file_audit_start", "file": relative_target})

        auditor = FileAuditor(self._llm_provider, reasoning_model, self._usage_runtime)
        candidates = auditor.audit(relative_target, content)

        if progress_callback:
            progress_callback({"event": "file_audit_done", "candidates": len(candidates), "file": relative_target})

        if not candidates:
            return {"file": relative_target, "file_path": abs_target, "reviews": []}

        if progress_callback:
            progress_callback({"event": "investigation_start", "total": len(candidates), "file": relative_target})

        investigator = FindingInvestigator(
            self._llm_provider, reasoning_model, strong_model, self._usage_runtime,
            self._config.codebase_path,
        )

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

        with ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(candidates)))) as ex:
            futs = {submit_with_current_context(ex, _investigate_one, c): c for c in candidates}
            for fut in as_completed(futs):
                c = futs[fut]
                try:
                    verdict = fut.result()
                    if verdict and verdict.get("is_vulnerable"):
                        with lock:
                            confirmed_findings.append(verdict)
                except Exception as e:
                    logger.warning("Investigation error: %s", e)
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

        selector = FinalReviewSelector(self._llm_provider, strong_model, self._usage_runtime)
        selected_findings = selector.select(
            relative_target,
            content,
            confirmed_findings,
            limit=min(3, max(1, int(max_paths_per_sink or 3))),
        )

        if not selected_findings:
            selected_findings = _fallback_select_best_verdicts(
                confirmed_findings,
                limit=min(3, max(1, int(max_paths_per_sink or 3))),
            )

        reviews = []
        seen_keys = set()
        for v in selected_findings:
            fn = str(v.get("function_name") or "unknown")
            vtype = str(v.get("vulnerability_type") or "other")
            line = 1
            try:
                line = max(1, int(v.get("line", 1)))
            except:
                pass

            dedup_key = (fn, vtype)
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

            code_snippet = _read_line_context(self._config.codebase_path, relative_target, line, context=2)

            chain = str(v.get("reachability_chain") or "")
            evidence = str(v.get("evidence") or "")
            root_cause = str(v.get("root_cause") or "")
            description = str(v.get("description") or f"{vtype.replace('_', ' ')} in {fn}")

            reasoning_parts = []
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
                "cwe": _VULN_TO_CWE.get(vtype),
                "severity": _severity_title(v.get("severity"), "Medium"),
                "confidence": _severity_title(v.get("confidence"), "Medium"),
                "reasoning": "\n".join(reasoning_parts),
                "mitigation": root_cause,
            })

        return {"file": relative_target, "file_path": abs_target, "reviews": reviews}


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
        reasoning_parts = []
        if str(finding.evidence or "").strip(): reasoning_parts.append(str(finding.evidence).strip())
        if finding.path: reasoning_parts.append(f"Reachability path: {' -> '.join(finding.path)}")
        if str(finding.root_cause or "").strip(): reasoning_parts.append(f"Root cause: {str(finding.root_cause).strip()}")
        code_snippet = ""
        target_file = finding.sink_file or finding.source_file
        if target_file: code_snippet = _read_line_context(self._config.codebase_path, target_file, line_number, context=2)
        return {
            "issue": issue, "line_number": line_number, "code_snippet": code_snippet,
            "cwe": _VULN_TO_CWE.get(str(finding.vulnerability_type or "").strip()),
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