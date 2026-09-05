# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from typing import TYPE_CHECKING
from typing import Any

from metis.runtime_settings import TriageOptions

if TYPE_CHECKING:
    from .core import ExecutionGraphError
    from .core import MetisEngine

__all__ = ["ExecutionGraphError", "MetisEngine", "TriageOptions"]


def __getattr__(name: str) -> Any:
    # Contract imports must not initialize the engine and its built-in nodes.
    if name in ("ExecutionGraphError", "MetisEngine"):
        from . import core

        return getattr(core, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
