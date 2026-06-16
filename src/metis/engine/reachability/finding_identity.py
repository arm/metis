# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import os
import re

from .finding_values import _normalise_vuln_type, _safe_int

_CANONICAL_LINE_BUCKET_SIZE = 5


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


def _entry_root_cause_token(entry):
    for key in ("root_cause_id", "root_cause_token", "root_cause_key"):
        token = _canonical_root_token(entry.get(key))
        if token:
            return token
    return _canonical_root_token(entry.get("canonical_key"))


def _canonical_key_from_parts(
    primary_file,
    primary_function,
    primary_line,
    vulnerability_type,
    root_cause_token,
    *,
    anchor=None,
):
    file_key = _canonical_path(primary_file)
    function_key = _canonical_function(primary_function)
    if not file_key or not function_key:
        return ""
    vtype = _normalise_vuln_type(vulnerability_type)
    if root_cause_token:
        root_token = root_cause_token
    elif isinstance(anchor, dict) and anchor.get("content_hash"):
        root_token = f"anchor_{anchor['content_hash']}"
    else:
        root_token = f"line_{_line_bucket(primary_line)}"
    return f"{file_key}:{function_key}:{vtype}:{root_token}"


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
