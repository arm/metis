# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""C/C++ parser-control and external sink rules for reachability extraction."""

from __future__ import annotations

from .finding_normalization import _normalise_vuln_type

CONTROL_CALLS = {
    "if",
    "for",
    "while",
    "switch",
    "return",
    "sizeof",
    "alignof",
    "_Generic",
    "case",
    "do",
    "else",
    "typedef",
    "defined",
}

_C_FAMILY_SENSITIVE_EXTERNAL_APIS_BY_TYPE = {
    "buffer_overflow": {"memcpy", "memmove", "strcpy", "strncpy", "strcat", "gets"},
    "out_of_bounds": {"strlen", "strnlen"},
    "format_string": {
        "sprintf",
        "vsprintf",
        "snprintf",
        "vsnprintf",
        "printf",
        "fprintf",
        "vprintf",
        "vfprintf",
    },
    "command_injection": {
        "system",
        "popen",
        "execl",
        "execle",
        "execlp",
        "execv",
        "execve",
        "execvp",
    },
    "path_traversal": {"fopen", "open", "stat", "lstat", "access", "unlink", "rename"},
    "integer_overflow": {
        "malloc",
        "calloc",
        "realloc",
        "kmalloc",
        "kcalloc",
        "krealloc",
    },
    "use_after_free": {"free", "kfree", "vfree"},
    "other": {"close", "ioctl", "scanf", "sscanf", "fscanf"},
}

_C_FAMILY_SENSITIVE_EXTERNAL_API_TYPES = {
    call_name: sink_type
    for sink_type, call_names in _C_FAMILY_SENSITIVE_EXTERNAL_APIS_BY_TYPE.items()
    for call_name in call_names
}


def external_sink_type(call_name: str) -> str:
    call = str(call_name or "").lower()
    return _C_FAMILY_SENSITIVE_EXTERNAL_API_TYPES.get(call, "")


def _function_entries(raw, *, setting_name: str, allowed_keys: set[str]):
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ValueError(f"{setting_name} must be a list of objects")

    entries = []
    for index, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise ValueError(f"{setting_name}[{index}] must be an object")
        unknown_keys = set(entry) - allowed_keys
        if unknown_keys:
            unknown = ", ".join(sorted(unknown_keys))
            raise ValueError(f"{setting_name}[{index}] has unsupported keys: {unknown}")
        name = entry.get("name")
        if not isinstance(name, str) or not name.strip():
            raise ValueError(f"{setting_name}[{index}].name must be a non-empty string")
        entries.append((index, entry, name.strip()))
    return entries


def _optional_string(entry: dict, field: str, *, setting_name: str, index: int) -> str:
    value = entry.get(field)
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValueError(f"{setting_name}[{index}].{field} must be a string")
    return value.strip()


def _normalise_security_function_specs(raw):
    specs = {}
    setting_name = "reachability_security_functions"
    for index, entry, name in _function_entries(
        raw,
        setting_name=setting_name,
        allowed_keys={"name", "sink_type", "reason"},
    ):
        sink_type = _optional_string(
            entry, "sink_type", setting_name=setting_name, index=index
        )
        reason = _optional_string(
            entry, "reason", setting_name=setting_name, index=index
        )
        specs[name.lower()] = {
            "sink_type": _normalise_vuln_type(sink_type or "other"),
            "reason": reason or "configured in metis.yaml",
        }
    return specs


def _normalise_source_function_specs(raw):
    specs = {}
    setting_name = "reachability_source_functions"
    for index, entry, name in _function_entries(
        raw,
        setting_name=setting_name,
        allowed_keys={"name", "reason"},
    ):
        reason = _optional_string(
            entry, "reason", setting_name=setting_name, index=index
        )
        specs[name.lower()] = {
            "sink_type": "other",
            "reason": reason or "configured in metis.yaml",
        }
    return specs
