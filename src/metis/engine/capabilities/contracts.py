# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel

from .manifest import CapabilityManifest


class CapabilityRepository(Protocol):
    def get_language_name_for_path(self, path: str) -> str | None: ...

    def normalize_match_path(self, path: str) -> str: ...


@dataclass(frozen=True, slots=True)
class CapabilityContext:
    codebase_path: Path
    repository: CapabilityRepository
    max_workers: int
    max_token_length: int


CapabilityFactory = Callable[[CapabilityContext, BaseModel], object]
CapabilityCloser = Callable[[object], None]


@dataclass(frozen=True, slots=True)
class CapabilityRegistration:
    """An engine-shared resource whose methods must support concurrent callers.

    Construction/cleanup are synchronized; operations own their synchronization.
    Engine-owned work drains before close. Direct callers own their lifetime.
    """

    manifest: CapabilityManifest
    configuration: type[BaseModel]
    factory: CapabilityFactory
    close: CapabilityCloser | None = None

    def __post_init__(self) -> None:
        name = self.manifest.name
        if not name.isidentifier():
            raise ValueError(f"Invalid capability name: {name!r}")
        if not self.manifest.active:
            raise ValueError(f"Capability {name!r} is not active")
        if not isinstance(self.configuration, type) or not issubclass(
            self.configuration, BaseModel
        ):
            raise TypeError("Capability configuration must be a Pydantic model")
        if not callable(self.factory):
            raise TypeError(f"Capability {name!r} factory must be callable")
        if self.close is not None and not callable(self.close):
            raise TypeError(f"Capability {name!r} close callback must be callable")
