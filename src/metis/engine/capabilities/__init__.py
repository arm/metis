# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from typing import TYPE_CHECKING
from typing import Any

from .manifest import CapabilityManifest
from .manifest import CapabilityOperationManifest

if TYPE_CHECKING:
    from .catalog import get_builtin_capability_manifests
    from .catalog import get_capability_contract
    from .catalog import get_capability_manifest
    from .index import IndexCapability
    from .navigation import NavigationCapability

__all__ = [
    "CapabilityManifest",
    "CapabilityOperationManifest",
    "IndexCapability",
    "NavigationCapability",
    "get_builtin_capability_manifests",
    "get_capability_contract",
    "get_capability_manifest",
]


def __getattr__(name: str) -> Any:
    if name == "IndexCapability":
        from .index import IndexCapability

        return IndexCapability
    if name == "NavigationCapability":
        from .navigation import NavigationCapability

        return NavigationCapability
    if name in (
        "get_builtin_capability_manifests",
        "get_capability_contract",
        "get_capability_manifest",
    ):
        from . import catalog

        return getattr(catalog, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
