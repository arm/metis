# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import re


CONTROL_CALLS = frozenset({
    "if", "for", "while", "switch", "return", "sizeof", "alignof", "_Generic",
    "case", "do", "else", "typedef", "defined",
})

SOURCE_CALLS = frozenset({
    "read", "recv", "recvfrom", "fread", "scanf", "sscanf", "fscanf", "gets",
    "getenv", "copy_from_user", "copyin", "ioctl", "poll", "select", "accept",
})

SOURCE_NAME_RE = re.compile(
    r"(?:^main$|ioctl|sysfs|debugfs|netlink|callback|handler|irq|interrupt|"
    r"probe|open|read|write|recv|dispatch|parse|request|packet|firmware|fw)",
    re.IGNORECASE,
)

ENTRYPOINT_FIELDS = frozenset({
    "open", "release", "ioctl", "unlocked_ioctl", "compat_ioctl", "read",
    "write", "poll", "probe", "remove", "shutdown", "suspend", "resume",
    "callback", "fn", "handler", "worker",
})

SINK_CALLS = frozenset({
    "memcpy", "memmove", "strcpy", "strncpy", "strcat", "sprintf", "vsprintf",
    "snprintf", "vsnprintf", "gets", "scanf", "sscanf", "fscanf", "strlen",
    "strnlen", "malloc",
    "calloc", "realloc", "kmalloc", "kcalloc", "krealloc", "free", "kfree",
    "vfree", "system", "popen", "execl", "execle", "execlp", "execv",
    "execve", "execvp", "fopen", "open", "stat", "lstat", "access", "unlink",
    "rename", "printf", "fprintf", "vprintf", "vfprintf", "ioctl", "close",
    "store_unref", "store_compact", "auth_get_level", "auth_verify_session",
    "session_sweep", "session_close", "notify_fire", "task_serialize",
    "task_create", "task_import", "task_set_title", "util_log", "proto_parse",
    "project_list_tasks", "project_add_task",
})

SINK_NAME_RE = re.compile(
    r"(?:copy|memcpy|strcpy|sprintf|alloc|realloc|free|release|destroy|"
    r"teardown|cleanup|lock|unlock|register|unregister|map|unmap|dma|mmio|"
    r"doorbell|register|reset|power|state|refcount|unref|compact|sweep|"
    r"serialize|verify|auth|permission|callback|notify|close|import|export)",
    re.IGNORECASE,
)


def sink_type_for_calls(calls: list[str], text: str = "") -> str:
    lower_calls = {str(call).lower() for call in calls}
    lowered_text = str(text or "").lower()
    if lower_calls & {"memcpy", "memmove", "strcpy", "strncpy", "strcat", "gets"}:
        return "buffer_overflow"
    if lower_calls & {"strlen", "strnlen", "task_serialize", "task_import"}:
        return "out_of_bounds"
    if lower_calls & {"sprintf", "vsprintf", "snprintf", "vsnprintf", "printf", "fprintf", "vprintf", "vfprintf"}:
        return "format_string"
    if lower_calls & {"util_log"}:
        return "format_string"
    if lower_calls & {"system", "popen", "execl", "execle", "execlp", "execv", "execve", "execvp"}:
        return "command_injection"
    if lower_calls & {"fopen", "open", "stat", "lstat", "access", "unlink", "rename"}:
        return "path_traversal"
    if lower_calls & {"free", "kfree", "vfree"} or re.search(r"\b(?:release|destroy|cleanup)\b", lowered_text):
        return "use_after_free"
    if lower_calls & {"session_sweep", "session_close", "notify_fire", "store_compact"}:
        return "use_after_free"
    if lower_calls & {"store_unref"}:
        return "refcount_imbalance"
    if lower_calls & {"auth_get_level", "auth_verify_session"}:
        return "permission_mismatch"
    if lower_calls & {"close"}:
        return "other"
    if lower_calls & {"malloc", "calloc", "realloc", "kmalloc", "kcalloc", "krealloc"}:
        return "integer_overflow"
    if "ioctl" in lower_calls:
        return "other"
    return "other"


def is_source_function(name: str, calls: list[str], entrypoint_refs: set[str]) -> tuple[bool, str]:
    lowered_calls = {str(call).lower() for call in calls}
    if name in entrypoint_refs:
        return True, "referenced by a global entrypoint/callback table"
    if SOURCE_NAME_RE.search(name or ""):
        return True, "function name matches external input or callback pattern"
    if lowered_calls & SOURCE_CALLS:
        return True, "function calls external input API"
    return False, ""


def is_sink_function(name: str, calls: list[str], text: str = "") -> tuple[bool, str, str]:
    lowered_calls = {str(call).lower() for call in calls}
    matched_calls = sorted(lowered_calls & SINK_CALLS)
    if matched_calls:
        return True, sink_type_for_calls(matched_calls, text), f"calls sink API(s): {', '.join(matched_calls[:6])}"
    if SINK_NAME_RE.search(name or ""):
        return True, sink_type_for_calls(calls, text), "function name matches security-sensitive state/resource pattern"
    return False, "", ""
