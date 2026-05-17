# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""False-positive post-filters for reachability findings."""
from __future__ import annotations


import re

from .finding_normalization import (
    _finding_file,
    _finding_function,
    _finding_line,
    _finding_text,
    _normalise_vuln_type,
)
from .source_context import _read_line_context, _read_named_function_body

_PRINTF_FORMAT_ARG_INDEX = {
    "printf": 0,
    "fprintf": 1,
    "sprintf": 1,
    "snprintf": 2,
    "vfprintf": 1,
    "vsnprintf": 2,
}


_PRINTF_CALL_RE = re.compile(
    r"\b(printf|fprintf|sprintf|snprintf|vfprintf|vsnprintf)\s*\(", re.IGNORECASE
)


_C_STRING_LITERAL_RE = re.compile(
    r'^\s*(?:(?:L|u8|u|U)?"(?:\\.|[^"\\])*"\s*)+$', re.DOTALL
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
                return text[open_paren_index + 1 : i]
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


def _is_fixed_literal_format_call_false_positive(body_or_context) -> bool:
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


def _finding_code_context(codebase_path, finding, *, context=8, max_chars=6000):
    target_file = _finding_file(finding)
    if not target_file:
        return ""
    line = _finding_line(finding) or 1
    line_context = _read_line_context(
        codebase_path, target_file, line, context=context, max_chars=max_chars
    )
    fn_name = _strip_function_qualifier(_finding_function(finding))
    body = _read_named_function_body(
        codebase_path, target_file, fn_name, line, max_chars=max_chars
    )
    return body or line_context


def _is_leak_misclassified_as_double_free(finding):
    if (
        _normalise_vuln_type(getattr(finding, "vulnerability_type", ""))
        != "double_free"
    ):
        return False
    text = _finding_text(finding).lower()
    leak_terms = (
        "leak",
        "partial cleanup",
        "missing cleanup",
        "not freed",
        "without freeing",
        "fails to free",
    )
    double_free_terms = (
        "double free",
        "double-free",
        "freed twice",
        "free twice",
        "same pointer twice",
        "already freed",
        "second free",
    )
    return any(term in text for term in leak_terms) and not any(
        term in text for term in double_free_terms
    )


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

        if vtype == "format_string":
            context = _finding_code_context(codebase_path, finding)
            if _is_fixed_literal_format_call_false_positive(context):
                continue

        filtered.append(finding)
    return filtered


def _strict_file_findings(findings):
    keep = []
    important_types = {
        "buffer_overflow",
        "out_of_bounds",
        "use_after_free",
        "double_free",
        "double_close",
        "format_string",
        "integer_overflow",
        "type_confusion",
        "info_leak",
        "stale_length",
        "missing_auth",
        "permission_mismatch",
        "refcount_imbalance",
        "accounting_drift",
        "null_deref",
    }
    important_analysis = {
        "reachability",
        "lifecycle",
        "ownership",
        "targeted_callback_lifecycle",
        "targeted_refcount",
        "targeted_permission",
        "classic_c_sink",
        "counter_symmetry",
    }
    low_signal_null_markers = (
        "caller-supplied",
        "pointer parameter",
        "parameters before",
        "localtime",
        "calloc",
        "allocation result",
    )
    for finding in findings:
        vtype = _normalise_vuln_type(finding.vulnerability_type)
        severity = str(finding.severity or "").lower()
        confidence = str(finding.confidence or "").lower()
        text = " ".join(
            [
                str(finding.description or ""),
                str(finding.root_cause or ""),
                str(finding.evidence or ""),
            ]
        ).lower()

        if vtype == "null_deref" and severity != "high":
            if finding.analysis_type != "classic_c_sink" or not any(
                marker in text for marker in ("before", "after", "lookup")
            ):
                if any(marker in text for marker in low_signal_null_markers):
                    continue
        if severity == "high":
            keep.append(finding)
            continue
        if confidence == "high" and (
            vtype in important_types or finding.analysis_type in important_analysis
        ):
            keep.append(finding)
    return keep
