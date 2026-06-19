# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from dataclasses import dataclass, field


@dataclass
class FunctionNode:
    unique_name: str
    file_path: str
    name: str
    line_number: int
    is_source: bool
    is_sink: bool
    language: str = ""
    calls: list[str] = field(default_factory=list)
    resolved_calls: list[str] = field(default_factory=list)
    source_reason: str = ""
    sink_type: str = ""
    sink_reason: str = ""
    end_line: int = 0
    start_byte: int = 0
    end_byte: int = 0
    is_public_entrypoint: bool = False
    entrypoint_reason: str = ""
    has_internal_linkage: bool = False

    @property
    def anchor(self):
        from metis.engine.source.anchor import KIND_FUNCTION, CodeAnchor, content_hash

        return CodeAnchor(
            file_path=self.file_path,
            start_line=self.line_number,
            end_line=self.end_line or self.line_number,
            start_byte=self.start_byte,
            end_byte=self.end_byte,
            symbol=self.unique_name,
            kind=KIND_FUNCTION,
            content_hash=content_hash(self.name),
        )


@dataclass
class GlobalConstruct:
    unique_name: str
    file_path: str
    name: str
    line_number: int
    initializer: str = ""
    referenced_functions: list[str] = field(default_factory=list)


@dataclass
class ReachabilityPath:
    source: str
    sink: str
    path: list[str] = field(default_factory=list)
    sink_type: str = ""


@dataclass
class VulnerabilityFinding:
    id: str
    vulnerability_type: str
    severity: str
    confidence: float
    source_function: str
    source_file: str
    source_line: int
    sink_function: str
    sink_file: str
    sink_line: int
    path: list[str] = field(default_factory=list)
    description: str = ""
    root_cause: str = ""
    evidence: str = ""
    mitigation: str = ""
    cwe: str = ""
    analysis_type: str = "reachability"
    primary_file: str = ""
    primary_function: str = ""
    primary_line: int = 0
    canonical_key: str = ""
    primary_anchor: dict | None = None

    def __post_init__(self):
        if not self.primary_file:
            self.primary_file = self.sink_file or self.source_file
        if not self.primary_function:
            self.primary_function = self.sink_function or self.source_function
        if self.primary_anchor and not self.primary_line:
            self.primary_line = int(self.primary_anchor.get("end_line") or 0)
        if not self.primary_line:
            self.primary_line = self.sink_line or self.source_line or 0
