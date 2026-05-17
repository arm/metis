# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""C/C++ parser-control and external sink rules for reachability extraction."""

from __future__ import annotations

from .finding_normalization import _normalise_vuln_type
from .heuristic_data import _words

C_FAMILY_PLUGIN_NAMES = _words("c cpp")

CONTROL_CALLS = _words(
    "if for while switch return sizeof alignof _Generic case do else typedef defined"
)

_C_FAMILY_SENSITIVE_EXTERNAL_APIS = (
    (
        "buffer_overflow",
        _words("memcpy memmove strcpy strncpy strcat gets"),
    ),
    (
        "out_of_bounds",
        _words("strlen strnlen"),
    ),
    (
        "format_string",
        _words("sprintf vsprintf snprintf vsnprintf printf fprintf vprintf vfprintf"),
    ),
    (
        "command_injection",
        _words("system popen execl execle execlp execv execve execvp"),
    ),
    (
        "path_traversal",
        _words("fopen open stat lstat access unlink rename"),
    ),
    (
        "integer_overflow",
        _words("malloc calloc realloc kmalloc kcalloc krealloc"),
    ),
    (
        "use_after_free",
        _words("free kfree vfree"),
    ),
    (
        "other",
        _words("close ioctl scanf sscanf fscanf"),
    ),
)


def external_sink_type(call_name: str) -> str:
    call = str(call_name or "").lower()
    for sink_type, sink_calls in _C_FAMILY_SENSITIVE_EXTERNAL_APIS:
        if call in sink_calls:
            return sink_type
    return ""


def _normalise_function_specs(raw, *, string_value_field="sink_type"):
    specs = {}

    def add(name, *, sink_type="other", reason="configured in metis.yaml"):
        key = str(name or "").strip()
        if not key:
            return
        specs[key.lower()] = {
            "sink_type": _normalise_vuln_type(sink_type or "other"),
            "reason": str(reason or "configured in metis.yaml").strip(),
        }

    if isinstance(raw, dict):
        items = raw.items()
    elif isinstance(raw, (list, tuple, set)):
        items = ((None, item) for item in raw)
    else:
        return specs

    for key, value in items:
        if isinstance(value, str):
            if key is None:
                add(value, sink_type="other")
            elif string_value_field == "reason":
                add(key, reason=value)
            else:
                add(key, sink_type=value)
            continue
        if not isinstance(value, dict):
            add(key or value, sink_type="other")
            continue
        names = (
            value.get("names")
            or value.get("functions")
            or value.get("function_names")
            or value.get("name")
            or value.get("function")
            or value.get("function_name")
            or key
        )
        if isinstance(names, str):
            names = [names]
        for name in names or []:
            add(
                name,
                sink_type=value.get("sink_type") or value.get("type") or "other",
                reason=value.get("reason") or "configured in metis.yaml",
            )
    return specs


def _normalise_security_function_specs(raw):
    return _normalise_function_specs(raw)


def _normalise_source_function_specs(raw):
    return _normalise_function_specs(raw, string_value_field="reason")
