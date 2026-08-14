# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal
from typing import Protocol

from .models import CodeGraph


@dataclass(frozen=True, slots=True)
class CodeGraphDiagnostic:
    file_path: str
    message: str
    severity: Literal["warning", "error"] = "error"
    code: str = "codegraph.provider_error"
    phase: Literal["parse"] | None = None
    line: int | None = None
    start_byte: int | None = None
    end_byte: int | None = None
    partial_output: bool = False

    def __post_init__(self) -> None:
        if self.line is not None and self.line < 1:
            raise ValueError("Diagnostic line must be positive")
        if (self.start_byte is None) != (self.end_byte is None):
            raise ValueError("Diagnostic byte span must include both endpoints")
        if self.start_byte is not None and self.start_byte < 0:
            raise ValueError("Diagnostic byte span cannot be negative")
        if (
            self.start_byte is not None
            and self.end_byte is not None
            and self.end_byte < self.start_byte
        ):
            raise ValueError("Diagnostic byte span end precedes its start")


@dataclass(frozen=True, slots=True)
class CodeGraphResult:
    graph: CodeGraph
    processed_files: tuple[str, ...]
    diagnostics: tuple[CodeGraphDiagnostic, ...] = ()
    failed_files: tuple[str, ...] = ()


class CodeGraphProvider(Protocol):
    def build_graph(
        self,
        *,
        codebase_path: str,
        files: tuple[str, ...],
        progress_callback: Callable[[dict[str, object]], None] | None = None,
    ) -> CodeGraphResult: ...


@dataclass(frozen=True, slots=True)
class CodeGraphProviderContext:
    get_language_name_for_path: Callable[[str], str | None]
    has_language_file_role: Callable[[str, str], bool]


CodeGraphProviderFactory = Callable[
    [CodeGraphProviderContext],
    CodeGraphProvider,
]
