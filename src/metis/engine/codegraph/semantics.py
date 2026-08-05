# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from dataclasses import dataclass
from dataclasses import field
from typing import Protocol

from .models import Tag


@dataclass(frozen=True, slots=True)
class CodeGraphNodeFacts:
    unique_name: str
    file_path: str
    name: str
    language: str
    calls: tuple[str, ...]
    unresolved_calls: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CodeGraphAnnotations:
    is_source: bool = False
    source_reason: str = ""
    is_sink: bool = False
    sink_type: str = ""
    sink_reason: str = ""
    tags: dict[str, Tag] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.is_source != bool(self.source_reason):
            raise ValueError(
                "CodeGraph source annotations require is_source and source_reason"
            )
        has_sink_details = bool(self.sink_type and self.sink_reason)
        if self.is_sink != has_sink_details:
            raise ValueError(
                "CodeGraph sink annotations require is_sink, sink_type, and sink_reason"
            )
        if not isinstance(self.tags, dict) or not all(
            isinstance(key, str)
            and key
            and key.replace(".", "_").isidentifier()
            and isinstance(tag, Tag)
            for key, tag in self.tags.items()
        ):
            raise ValueError("CodeGraph annotation tags must map identifiers to Tag")


class CodeGraphSemantics(Protocol):
    def analyze_node(self, facts: CodeGraphNodeFacts) -> CodeGraphAnnotations: ...
