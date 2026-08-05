# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from typing import Literal

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field
from pydantic import constr
from pydantic import model_validator
from typing_extensions import NotRequired
from typing_extensions import Required
from typing_extensions import TypedDict

from metis.sarif.models import SarifPayload
from metis.sarif.triage import SarifFinding
from metis.sarif.triage import extract_findings


@dataclass(frozen=True, slots=True)
class TriageRun:
    sarif: SarifPayload
    remaining: tuple[SarifFinding, ...]
    total: int
    processed: int = 0

    @classmethod
    def from_payload(
        cls,
        payload: SarifPayload,
        *,
        include_triaged: bool = False,
    ) -> "TriageRun":
        findings = extract_findings(
            payload.model_dump(mode="json", by_alias=True),
            include_triaged=include_triaged,
        )
        return cls(payload, tuple(findings), len(findings))


class TriageRequest(TypedDict):
    finding_message: Required[str]
    finding_file_path: Required[str]
    finding_line: Required[int]
    finding_rule_id: Required[str]
    finding_snippet: Required[str]
    finding_source_tool: NotRequired[str]
    finding_is_metis: NotRequired[bool]
    finding_explanation: NotRequired[str]
    debug_callback: NotRequired[Any]
    triage_language: NotRequired[str]
    triage_language_guidance: NotRequired[str]
    threat_model_context: NotRequired[list[dict[str, Any]]]


class TriageState(TypedDict, total=False):
    finding_message: str
    finding_file_path: str
    finding_line: int
    finding_rule_id: str
    finding_snippet: str
    finding_source_tool: str
    finding_is_metis: bool
    finding_explanation: str
    debug_callback: Any
    triage_language: str
    triage_language_guidance: str
    threat_model_context: list[dict[str, Any]]
    triage_system_prompt: str
    triage_decision_prompt: str
    evidence_pack: str
    tool_transcript: str
    decision_status: str
    decision_reason: str
    decision_evidence: list[str]
    decision_resolution_chain: list[str]
    decision_unresolved_hops: list[str]
    evidence_gate_missing: list[str]
    evidence_obligations: list[str]
    obligation_coverage: dict[str, int]


class TriageDecisionModel(BaseModel):
    status: Literal["valid", "invalid", "inconclusive"] = Field(
        description="Whether the finding appears to be valid based on static evidence."
    )
    reason: constr(strip_whitespace=True, min_length=1) = Field(
        description="Short justification for the triage decision."
    )
    evidence: list[constr(strip_whitespace=True, min_length=1)] = Field(
        default_factory=list,
        description="Concrete evidence citations using file:line format.",
    )
    resolution_chain: list[constr(strip_whitespace=True, min_length=1)] = Field(
        default_factory=list,
        description=(
            "Resolution hops from reported symbol/behavior to concrete code evidence."
        ),
    )
    unresolved_hops: list[constr(strip_whitespace=True, min_length=1)] = Field(
        default_factory=list,
        description="Unresolved alias/wrapper/import/definition hops, if any.",
    )

    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="after")
    def _validate_evidence(self) -> "TriageDecisionModel":
        if self.status == "valid" and not self.evidence:
            raise ValueError(
                "Valid triage decisions must include at least one evidence citation."
            )
        if self.status == "valid" and not self.resolution_chain:
            raise ValueError(
                "Valid triage decisions must include a non-empty resolution chain."
            )
        if self.status == "inconclusive" and not self.unresolved_hops:
            raise ValueError(
                "Inconclusive triage decisions must include unresolved hops."
            )
        return self
