# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from typing import Literal

from pydantic import BaseModel, Field, constr, ConfigDict, model_validator


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
    def _validate_evidence(self):
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
