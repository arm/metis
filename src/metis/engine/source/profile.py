# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Literal

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field


class ProfiledSourceReference(BaseModel):
    schema_version: Literal[1] = 1
    fingerprint: str = Field(min_length=1)
    compile_commands_path: str = Field(min_length=1)
    compile_commands_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    translation_units: int = Field(ge=1)
    source_views: int = Field(ge=1)
    profiled_files: int = Field(ge=0)
    ambiguous_files: int = Field(ge=0)
    active_line_count: int = Field(ge=0)
    compiler_names: tuple[str, ...] = ()

    model_config = ConfigDict(extra="forbid", frozen=True)


@dataclass(frozen=True, slots=True)
class SourceView:
    raw: bytes
    canonical: bytes


@dataclass(frozen=True, slots=True)
class ProfiledSourceArtifact:
    reference: ProfiledSourceReference
    languages: frozenset[str]
    raw_sources: Mapping[str, bytes]
    canonical_sources: Mapping[str, bytes]

    def __post_init__(self) -> None:
        languages = frozenset(language.strip().lower() for language in self.languages)
        if not languages or "" in languages:
            raise ValueError("Profiled source languages must be non-empty")
        raw_sources = {
            str(path): bytes(source) for path, source in self.raw_sources.items()
        }
        canonical_sources = {
            str(path): bytes(source) for path, source in self.canonical_sources.items()
        }
        if not set(canonical_sources) <= set(raw_sources):
            raise ValueError("Canonical source paths require raw snapshots")
        if not raw_sources:
            raise ValueError("Profiled source artifact requires source views")
        object.__setattr__(self, "languages", languages)
        object.__setattr__(self, "raw_sources", MappingProxyType(raw_sources))
        object.__setattr__(
            self, "canonical_sources", MappingProxyType(canonical_sources)
        )

    def view_for_path(self, codebase_path: str, path: str) -> SourceView | None:
        relative = self._relative_path(codebase_path, path)
        if relative is None or relative not in self.raw_sources:
            return None
        raw = self.raw_sources[relative]
        return SourceView(
            raw,
            self.canonical_sources.get(relative, raw),
        )

    def analysis_for_path(self, codebase_path: str, path: str) -> bytes | None:
        relative = self._relative_path(codebase_path, path)
        if relative is None or relative not in self.raw_sources:
            return None
        return self.canonical_sources.get(relative, b"")

    @staticmethod
    def _relative_path(codebase_path: str, path: str) -> str | None:
        root = Path(codebase_path).expanduser().resolve()
        candidate = Path(path)
        candidate = candidate if candidate.is_absolute() else root / candidate
        try:
            return candidate.resolve().relative_to(root).as_posix()
        except (OSError, ValueError):
            return None
