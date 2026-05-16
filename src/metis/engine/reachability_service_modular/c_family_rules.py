# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""C/C++ source, sink, and parser-control rules for reachability extraction."""

from __future__ import annotations

import re

C_FAMILY_PLUGIN_NAMES = frozenset({"c", "cpp"})

CONTROL_CALLS = frozenset(
    "if for while switch return sizeof alignof _Generic case do else typedef defined".split()
)

SOURCE_CALLS = frozenset(
    "read recv recvfrom fread scanf sscanf fscanf gets getenv copy_from_user "
    "copyin ioctl poll select accept".split()
)

SOURCE_NAME_RE = re.compile(
    r"(?:^main$|ioctl|sysfs|debugfs|netlink|callback|handler|irq|interrupt|"
    r"probe|open|read|write|recv|dispatch|parse|request|packet|firmware|fw)",
    re.IGNORECASE,
)

ENTRYPOINT_FIELDS = frozenset(
    "open release ioctl unlocked_ioctl compat_ioctl read write poll probe remove "
    "shutdown suspend resume callback fn handler worker".split()
)

_BUFFER_COPY_CALLS = frozenset("memcpy memmove strcpy strncpy strcat gets".split())
_BOUNDS_CALLS = frozenset({"strlen", "strnlen"})
_FORMAT_CALLS = frozenset(
    "sprintf vsprintf snprintf vsnprintf printf fprintf vprintf vfprintf".split()
)
_COMMAND_CALLS = frozenset(
    "system popen execl execle execlp execv execve execvp".split()
)
_PATH_CALLS = frozenset("fopen open stat lstat access unlink rename".split())
_FREE_CALLS = frozenset({"free", "kfree", "vfree"})
_CLOSE_CALLS = frozenset({"close"})
_ALLOC_CALLS = frozenset("malloc calloc realloc kmalloc kcalloc krealloc".split())
_IOCTL_CALLS = frozenset({"ioctl"})
_UNCATEGORIZED_SINK_CALLS = frozenset({"scanf", "sscanf", "fscanf"})
_LIFETIME_TEXT_RE = re.compile(r"\b(?:release|destroy|cleanup)\b")

_SINK_TYPE_CALL_RULES = (
    (_BUFFER_COPY_CALLS, "buffer_overflow"),
    (_BOUNDS_CALLS, "out_of_bounds"),
    (_FORMAT_CALLS, "format_string"),
    (_COMMAND_CALLS, "command_injection"),
    (_PATH_CALLS, "path_traversal"),
)
_FALLBACK_SINK_TYPE_CALL_RULES = (
    (_CLOSE_CALLS, "other"),
    (_ALLOC_CALLS, "integer_overflow"),
    (_IOCTL_CALLS, "other"),
)

SINK_CALLS = frozenset().union(
    *(calls for calls, _sink_type in _SINK_TYPE_CALL_RULES),
    *(calls for calls, _sink_type in _FALLBACK_SINK_TYPE_CALL_RULES),
    _FREE_CALLS,
    _UNCATEGORIZED_SINK_CALLS,
)


def sink_type_for_calls(calls: list[str], text: str = "") -> str:
    lower_calls = {str(call).lower() for call in calls}
    lowered_text = str(text or "").lower()
    for sink_calls, sink_type in _SINK_TYPE_CALL_RULES:
        if lower_calls & sink_calls:
            return sink_type
    if lower_calls & _FREE_CALLS or _LIFETIME_TEXT_RE.search(lowered_text):
        return "use_after_free"
    for sink_calls, sink_type in _FALLBACK_SINK_TYPE_CALL_RULES:
        if lower_calls & sink_calls:
            return sink_type
    return "other"


def is_source_function(
    name: str, calls: list[str], entrypoint_refs: set[str]
) -> tuple[bool, str]:
    lowered_calls = {str(call).lower() for call in calls}
    if name in entrypoint_refs:
        return True, "referenced by a global entrypoint/callback table"
    if SOURCE_NAME_RE.search(name or ""):
        return True, "function name matches external input or callback pattern"
    if lowered_calls & SOURCE_CALLS:
        return True, "function calls external input API"
    return False, ""


def is_sink_function(
    name: str, calls: list[str], text: str = ""
) -> tuple[bool, str, str]:
    lowered_calls = {str(call).lower() for call in calls}
    matched_calls = sorted(lowered_calls & SINK_CALLS)
    if matched_calls:
        return (
            True,
            sink_type_for_calls(matched_calls, text),
            f"calls sink API(s): {', '.join(matched_calls[:6])}",
        )
    return False, "", ""
