# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["critical", "high", "medium", "low"]


class ReachabilityFindingEntryModel(BaseModel):
    analysis_type: str = Field("", description="Requested analysis type.")
    vulnerability_type: str = Field(
        "other",
        description=(
            "Best concise vulnerability category chosen from the evidence; "
            "not restricted to a local taxonomy."
        ),
    )
    severity: Severity = Field(
        "medium", description="One of: critical, high, medium, low."
    )
    confidence: str | float = Field(
        "medium",
        description=(
            "One of high, medium, low; numeric values are accepted for compatibility."
        ),
    )
    cwe: str = Field("", description="Best matching CWE ID such as CWE-120, or empty.")
    function_name: str = Field(
        "", description="Actual function name where the issue is observed."
    )
    related_function: str = Field(
        "", description="Related function involved in the same root cause."
    )
    line: int | None = Field(
        None, description="Actual source line for the observed issue."
    )
    primary_file: str = Field(
        "", description="Source file containing the actual defective code."
    )
    primary_function: str = Field(
        "",
        description="Exact shown function identifier containing the defective code.",
    )
    primary_line: int | None = Field(
        None, description="Line of the actual defective operation or missing check."
    )
    root_cause_id: str = Field(
        "", description="Stable short snake_case token for this specific root cause."
    )
    canonical_key: str = Field(
        "",
        description=(
            "Stable key: src/file.c:src/file.c::function:vulnerability_type:"
            "root_cause_id."
        ),
    )
    description: str = Field("", description="Brief description of the vulnerability.")
    root_cause: str = Field("", description="Specific root cause, not a mitigation.")
    evidence: str = Field("", description="Concrete code evidence from shown source.")
    mitigation: str = Field(
        "", description="Fix recommendation, not restated evidence."
    )
    model_config = ConfigDict(extra="forbid")


class ReachabilityConfirmationFindingEntryModel(ReachabilityFindingEntryModel):
    path_index: int = Field(
        ge=0, description="Index of the candidate path that proves this finding."
    )
    is_vulnerable: bool = Field(
        description="Whether the candidate path proves a real vulnerability."
    )


class ReachabilityFindingResponseModel(BaseModel):
    findings: list[ReachabilityFindingEntryModel] = Field(
        default_factory=list, description="Structured reachability findings."
    )

    model_config = ConfigDict(extra="forbid")


class ReachabilityConfirmationResponseModel(BaseModel):
    findings: list[ReachabilityConfirmationFindingEntryModel] = Field(
        default_factory=list,
        description="Confirmed vulnerabilities for candidate paths.",
    )

    model_config = ConfigDict(extra="forbid")
