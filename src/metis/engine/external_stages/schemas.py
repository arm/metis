# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, constr, field_validator

from metis.engine.stages.triage.models import TriageDecisionModel

ANALYSIS_CONTRACT_VERSION = "metis.external.analysis/v1"
VALIDATION_CONTRACT_VERSION = "metis.external.validation/v1"
VALIDATION_RESULT_CONTRACT_VERSION = "metis.external.validation-result/v1"


class ExternalStageCommandModel(BaseModel):
    command: list[constr(strip_whitespace=True, min_length=1)] = Field(
        description="Command argv template. Placeholders are expanded by Metis."
    )
    timeout_seconds: int = Field(default=3600, gt=0)

    model_config = ConfigDict(extra="forbid")


class ExternalStagesConfigModel(BaseModel):
    analysis: dict[str, ExternalStageCommandModel] = Field(default_factory=dict)
    validation: dict[str, ExternalStageCommandModel] = Field(default_factory=dict)

    model_config = ConfigDict(extra="forbid")


class AnalysisRequestModel(BaseModel):
    contract_version: Literal["metis.external.analysis/v1"] = ANALYSIS_CONTRACT_VERSION
    run_id: constr(strip_whitespace=True, min_length=1)
    codebase_path: constr(strip_whitespace=True, min_length=1)
    commit: str | None = None
    scope: list[str] = Field(default_factory=list)
    prompt: constr(strip_whitespace=True, min_length=1)
    output_sarif: constr(strip_whitespace=True, min_length=1)
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(extra="forbid")


class ValidationRequestModel(BaseModel):
    contract_version: Literal["metis.external.validation/v1"] = (
        VALIDATION_CONTRACT_VERSION
    )
    run_id: constr(strip_whitespace=True, min_length=1)
    codebase_path: constr(strip_whitespace=True, min_length=1)
    input_sarif: constr(strip_whitespace=True, min_length=1)
    commit: str | None = None
    output_decision: constr(strip_whitespace=True, min_length=1)
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(extra="forbid")


class ExternalValidationDecisionModel(BaseModel):
    run_index: int = Field(ge=0)
    result_index: int = Field(ge=0)
    status: Literal["valid", "invalid", "inconclusive"]
    reason: constr(strip_whitespace=True, min_length=1)
    evidence: list[constr(strip_whitespace=True, min_length=1)] = Field(
        default_factory=list
    )
    resolution_chain: list[constr(strip_whitespace=True, min_length=1)] = Field(
        default_factory=list
    )
    unresolved_hops: list[constr(strip_whitespace=True, min_length=1)] = Field(
        default_factory=list
    )

    model_config = ConfigDict(extra="forbid")

    @field_validator("unresolved_hops", mode="after")
    @classmethod
    def _validate_decision_shape(cls, value, info):
        payload = dict(info.data)
        payload["unresolved_hops"] = value
        if "status" in payload and "reason" in payload:
            TriageDecisionModel.model_validate(
                {
                    "status": payload.get("status"),
                    "reason": payload.get("reason"),
                    "evidence": payload.get("evidence") or [],
                    "resolution_chain": payload.get("resolution_chain") or [],
                    "unresolved_hops": payload.get("unresolved_hops") or [],
                }
            )
        return value

    def triage_decision_metadata(self) -> dict[str, Any]:
        return {
            "evidence": list(self.evidence),
            "resolution_chain": list(self.resolution_chain),
            "unresolved_hops": list(self.unresolved_hops),
            "missing_evidence": list(self.unresolved_hops),
        }


class ValidationResultModel(BaseModel):
    contract_version: Literal["metis.external.validation-result/v1"] = (
        VALIDATION_RESULT_CONTRACT_VERSION
    )
    decisions: list[ExternalValidationDecisionModel] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid")
