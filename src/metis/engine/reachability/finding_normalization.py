# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Finding normalization and review-field helpers."""
from __future__ import annotations

import os
import re
import uuid

from .finding_taxonomy import _VTYPE_FAMILY, _VULN_TYPE_ALIASES
from .models import VulnerabilityFinding


def _lookup_fn(name, fn_by_name, fn_by_unique, all_fns):
    if not name:
        return None
    if name in fn_by_unique:
        return fn_by_unique[name]
    if name in fn_by_name:
        return fn_by_name[name]
    for fn in all_fns:
        if name in fn.name or name in fn.unique_name:
            return fn
    return None


def _severity_title(value, default="Medium"):
    text = str(value or "").strip().lower()
    if not text:
        return default
    return text[:1].upper() + text[1:]


def _confidence_score(value, default=0.75):
    """Normalize reachability confidence labels into the legacy numeric schema."""

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


def _safe_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


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


_CANONICAL_LINE_BUCKET_SIZE = 5


def _canonical_fields(
    entry, *, default_file, default_function, default_line, vulnerability_type="other"
):
    primary_file = str(entry.get("primary_file") or "").strip() or default_file or ""
    primary_function = (
        str(entry.get("primary_function") or "").strip() or default_function or ""
    )
    primary_line = _safe_int(entry.get("primary_line"), default_line or 0)
    if primary_line <= 0:
        primary_line = default_line or 0
    canonical_key = _canonical_key_from_parts(
        primary_file,
        primary_function,
        primary_line,
        vulnerability_type,
        _entry_root_cause_token(entry),
    )
    return primary_file, primary_function, primary_line, canonical_key


def _finding_from_llm_entry(
    entry,
    *,
    source_function,
    source_file,
    source_line,
    sink_function,
    sink_file,
    sink_line,
    path,
    analysis_type,
    default_file=None,
    default_function=None,
    default_line=None,
    default_vulnerability_type="other",
    default_severity="medium",
):
    vulnerability_type = _normalise_vuln_type(
        entry.get("vulnerability_type") or default_vulnerability_type
    )
    primary_file, primary_function, primary_line, canonical_key = _canonical_fields(
        entry,
        default_file=sink_file if default_file is None else default_file,
        default_function=(
            sink_function if default_function is None else default_function
        ),
        default_line=sink_line if default_line is None else default_line,
        vulnerability_type=vulnerability_type,
    )
    return VulnerabilityFinding(
        id=uuid.uuid4().hex[:16],
        vulnerability_type=vulnerability_type,
        severity=str(entry.get("severity") or default_severity),
        confidence=str(entry.get("confidence") or "medium"),
        source_function=source_function,
        source_file=source_file,
        source_line=source_line,
        sink_function=sink_function,
        sink_file=sink_file,
        sink_line=sink_line,
        path=list(path),
        description=str(entry.get("description") or ""),
        root_cause=str(entry.get("root_cause") or ""),
        evidence=str(entry.get("evidence") or ""),
        mitigation=str(entry.get("mitigation") or ""),
        analysis_type=analysis_type,
        primary_file=primary_file,
        primary_function=primary_function,
        primary_line=primary_line,
        canonical_key=canonical_key,
    )


def _canonical_finding_key(finding):
    return _canonical_key_from_parts(
        _finding_file(finding),
        _finding_function(finding),
        _finding_line(finding),
        getattr(finding, "vulnerability_type", ""),
        _canonical_root_token(getattr(finding, "canonical_key", "")),
    )


def _entry_root_cause_token(entry):
    for key in ("root_cause_id", "root_cause_token", "root_cause_key"):
        token = _canonical_root_token(entry.get(key))
        if token:
            return token
    return _canonical_root_token(entry.get("canonical_key"))


def _canonical_key_from_parts(
    primary_file, primary_function, primary_line, vulnerability_type, root_cause_token
):
    file_key = _canonical_path(primary_file)
    function_key = _canonical_function(primary_function)
    if not file_key or not function_key:
        return ""
    vtype = _normalise_vuln_type(vulnerability_type)
    family = _VTYPE_FAMILY.get(vtype, vtype)
    root_token = root_cause_token or f"line_{_line_bucket(primary_line)}"
    return f"{file_key}:{function_key}:{family}:{root_token}"


def _canonical_path(path):
    return _path_key(path).lower()


def _canonical_function(function_name):
    return re.sub(r"\s+", "", str(function_name or "").strip()).replace("\\", "/")


def _canonical_root_token(value):
    text = str(value or "").strip().lower()
    if not text:
        return ""
    if ":" in text:
        text = text.rsplit(":", 1)[-1]
    tokens = re.findall(r"[a-z0-9]+", text)
    return "_".join(tokens[:8])


def _line_bucket(line):
    line = max(0, _safe_int(line, 0))
    if line <= 0:
        return 0
    return (line - 1) // _CANONICAL_LINE_BUCKET_SIZE


def _normalise_vuln_type(raw):
    t = str(raw or "other").strip().lower().replace("-", "_").replace(" ", "_")
    return _VULN_TYPE_ALIASES.get(t, t)


def _mitigation_text(finding, vulnerability_type: str | None = None) -> str:
    explicit = str(getattr(finding, "mitigation", "") or "").strip()
    if explicit:
        return explicit

    vtype = _normalise_vuln_type(
        vulnerability_type or getattr(finding, "vulnerability_type", "")
    )
    label = _VTYPE_FAMILY.get(vtype, vtype).replace("_", " ")
    return (
        f"Address the {label} issue by adding the missing validation, ordering, "
        "ownership, or cleanup guard before the reachable operation executes."
    )


def _finding_text(f):
    return " ".join(
        str(part or "")
        for part in (
            getattr(f, "description", ""),
            getattr(f, "root_cause", ""),
            getattr(f, "evidence", ""),
            getattr(f, "canonical_key", ""),
        )
    )


def _finding_file(f):
    return (
        getattr(f, "primary_file", "")
        or getattr(f, "sink_file", "")
        or getattr(f, "source_file", "")
        or ""
    )


def _finding_function(f):
    return (
        getattr(f, "primary_function", "")
        or getattr(f, "sink_function", "")
        or getattr(f, "source_function", "")
        or ""
    )


def _finding_line(f):
    return _safe_int(
        getattr(f, "primary_line", 0)
        or getattr(f, "sink_line", 0)
        or getattr(f, "source_line", 0),
        0,
    )
