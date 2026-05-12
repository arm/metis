# SPDX-FileCopyrightText: Copyright 2025-2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations
import json
import os
import re
from collections import defaultdict
from pathlib import Path

from metis.utils import read_file_content

from .models import FunctionNode


def _chat_model_kwargs(usage_runtime, *, reasoning_effort=None):
    kwargs = usage_runtime.hooks.chat_model_kwargs()
    if reasoning_effort and str(reasoning_effort).lower() not in {"none", "off", "false", "default"}:
        kwargs["reasoning_effort"] = reasoning_effort
    return kwargs

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

def _confidence_score(value, default=0.75):
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return max(0.0, min(1.0, round(float(value), 2)))

    text = str(value or "").strip().lower()
    if not text:
        return default
    try:
        return max(0.0, min(1.0, round(float(text), 2)))
    except ValueError:
        pass

    scores = {
        "very high": 0.99,
        "high": 0.95,
        "medium": 0.75,
        "moderate": 0.75,
        "low": 0.55,
        "very low": 0.35,
        "informational": 0.5,
        "info": 0.5,
    }
    return scores.get(text, default)

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
    "array_index_oob": "memory_bounds",
    "array_index_size_mismatch": "memory_bounds",
    "missing_bounds_check": "memory_bounds",
    "use_after_free": "lifetime",
    "deferred_uaf": "lifetime",
    "callback_uaf": "lifetime",
    "stale_pointer": "lifetime",
    "stale_pointer_after_realloc": "lifetime",
    "double_free": "double_release",
    "double_close": "double_release",
    "format_string": "format_string",
    "null_deref": "null_deref",
    "integer_overflow": "integer_overflow",
    "integer_overflow_in_allocation": "integer_overflow",
    "type_confusion": "type_confusion",
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
    "authorization_bypass": "authorization",
    "permission_mismatch": "authorization",
    "wrong_constant": "authorization",
    "boolean_coercion": "authorization",
    "auth_logic_error": "authorization",
    "auth_comparison_logic_error": "authorization",
    "accounting_drift": "accounting",
    "refcount_imbalance": "refcount",
    "info_leak": "information_disclosure",
    "uninitialized_data_exposure": "information_disclosure",
    "partial_cleanup_on_error": "cleanup",
    "ownership_overwrite": "cleanup",
    "wrong_struct_field": "wrong_field",
    "field_staleness_after_mutation": "stale_metadata",
    "stale_length": "stale_metadata",
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
    "integer_overflow_allocation": "integer_overflow_in_allocation",
    "integer_overflow_in_alloc": "integer_overflow_in_allocation",
    "allocation_overflow": "integer_overflow_in_allocation",
    "type-confusion": "type_confusion", "lock_inversion": "lock_order",
    "lock_order_inversion": "lock_order", "deadlock": "lock_order",
    "array_oob": "array_index_oob",
    "array_out_of_bounds": "array_index_oob",
    "array_index_size_mismatch": "array_index_oob",
    "state_ordering": "state_order",
    "field_staleness": "field_staleness_after_mutation",
    "stale_field": "field_staleness_after_mutation",
    "stale_length_field": "stale_length",
    "missing_cleanup": "partial_cleanup", "resource_leak": "partial_cleanup",
    "missing_authorization": "missing_auth", "missing_permission": "missing_auth",
    "authorization_bypass": "missing_auth", "auth_bypass": "missing_auth",
    "auth_logic": "auth_logic_error",
    "auth_comparison_logic": "auth_comparison_logic_error",
    "dangling_pointer": "use_after_free",
    "premature_publication": "state_order",
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

_C_CPP_EXTS = frozenset({".c", ".h", ".cc", ".cpp", ".hpp", ".hh", ".hxx", ".cxx"})
def _write_jsonl(path, findings):
    out = Path(path); out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        for f in findings: fh.write(json.dumps(f.to_dict(), ensure_ascii=False) + "\n")
