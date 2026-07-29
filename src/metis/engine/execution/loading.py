# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib
from typing import Any
from typing import cast

from .contracts import ExecutionNode
from .contracts import NodeManifest


def load_execution_node(
    manifest: NodeManifest,
) -> ExecutionNode[Any, Any]:
    module_name, symbol_name = manifest.implementation.split(":", 1)
    module = importlib.import_module(module_name)
    implementation = getattr(module, symbol_name)
    return cast(ExecutionNode[Any, Any], implementation)
