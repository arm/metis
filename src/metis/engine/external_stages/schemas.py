# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, constr

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


class ExternalValidationDecisionModel(TriageDecisionModel):
    run_index: int = Field(ge=0)
    result_index: int = Field(ge=0)

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
