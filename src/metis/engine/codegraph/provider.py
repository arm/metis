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
