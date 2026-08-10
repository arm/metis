# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .session import span


def traced_step(workflow: str, name: str, function: Callable[..., Any]):
    """Wraps one inner-workflow node without changing its invocation contract."""

    def invoke(state, *args, **kwargs):
        with span(
            "step",
            f"{workflow}.{name}",
            lambda: {
                "workflow": workflow,
                "step": name,
                "input_keys": sorted(state) if isinstance(state, dict) else [],
                "input": state,
            },
        ) as step_span:
            result = function(state, *args, **kwargs)
            step_span.end(attributes={"output": result})
            return result

    return invoke
