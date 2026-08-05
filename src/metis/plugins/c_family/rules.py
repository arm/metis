# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

CONTROL_CALLS = set(
    "if for while switch return sizeof alignof _Generic case do else typedef defined".split()
)

LOCK_CALLS = frozenset(
    "pthread_mutex_lock mutex_lock spin_lock spin_lock_irqsave spin_lock_irq".split()
)
UNLOCK_CALLS = frozenset(
    "pthread_mutex_unlock mutex_unlock spin_unlock spin_unlock_irqrestore "
    "spin_unlock_irq".split()
)


def normalize_lock_expression(expression: object) -> str:
    value = "".join(str(expression or "").strip().split()).replace("->", ".")
    while value.startswith("(") and ")" in value:
        closing = value.find(")")
        inner = value[1:closing]
        suffix = value[closing + 1 :]
        value = suffix or inner
        value = value.strip("&")
    value = value.strip("&()")
    if value.endswith(".lock"):
        return ".".join(value.split(".")[-2:])
    return value


_SENSITIVE_EXTERNAL_APIS_BY_TYPE = {
    sink_type: set(calls.split())
    for sink_type, calls in (
        ("buffer_overflow", "memcpy memmove strcpy strncpy strcat gets"),
        ("out_of_bounds", "strlen strnlen"),
        (
            "format_string",
            "sprintf vsprintf snprintf vsnprintf printf fprintf vprintf vfprintf",
        ),
        ("command_injection", "system popen execl execle execlp execv execve execvp"),
        ("path_traversal", "fopen open stat lstat access unlink rename"),
        ("integer_overflow", "malloc calloc realloc kmalloc kcalloc krealloc"),
        ("use_after_free", "free kfree vfree"),
        ("other", "close ioctl scanf sscanf fscanf"),
    )
}

_SENSITIVE_EXTERNAL_API_TYPES = {
    call_name: sink_type
    for sink_type, call_names in _SENSITIVE_EXTERNAL_APIS_BY_TYPE.items()
    for call_name in call_names
}


def external_sink_type(call_name: str) -> str:
    return _SENSITIVE_EXTERNAL_API_TYPES.get(call_name.lower(), "")
