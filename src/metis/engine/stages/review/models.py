# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any
from typing import Literal
from typing import NotRequired
from typing import Required
from uuid import uuid4

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field
from pydantic import model_validator
from typing_extensions import TypedDict


class ReviewRequest(TypedDict):
    file_path: Required[str]
    snippet: Required[str]
    language_prompts: Required[dict[str, str]]
    default_prompt_key: NotRequired[str]
    relative_file: NotRequired[str | None]
    mode: NotRequired[str]
    original_file: NotRequired[str | None]
    threat_model_context: NotRequired[list[dict[str, Any]]]
    debug_callback: NotRequired[Any]


class ReviewState(TypedDict, total=False):
    file_path: str
    snippet: str
    chunk_start: int
    chunk_end: int
    source_map: Any
    relative_file: str | None
    mode: str
    original_file: str | None
    threat_model_context: list[dict[str, Any]]
    debug_callback: Any
    system_prompt: str
    parsed_reviews: list[dict[str, Any]]


class ReviewCommand(BaseModel):
    mode: Literal["code", "dir", "file", "patch"]
    target: str | None = None

    model_config = ConfigDict(extra="forbid", frozen=True)

    @model_validator(mode="after")
    def validate_target(self) -> ReviewCommand:
        if self.mode == "code" and self.target is not None:
            raise ValueError("Review mode 'code' does not accept a target")
        if self.mode != "code" and not self.target:
            raise ValueError(f"Review mode {self.mode!r} requires a target")
        return self


class ReviewFinding(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex, min_length=1)
    issue: str = Field(min_length=1)

    model_config = ConfigDict(extra="allow", frozen=True)


class ReviewGroup(BaseModel):
    reviews: list[ReviewFinding] = Field(default_factory=list)

    model_config = ConfigDict(extra="allow", frozen=True)


class StandardReviewResult(BaseModel):
    reviews: list[ReviewGroup]

    model_config = ConfigDict(extra="forbid", frozen=True)


class PatchReviewResult(BaseModel):
    reviews: list[ReviewGroup]
    overall_changes: str

    model_config = ConfigDict(extra="forbid", frozen=True)


ReviewResult = StandardReviewResult | PatchReviewResult


class ReviewStatus(str, Enum):
    SUCCEEDED = "succeeded"
    INCONCLUSIVE = "inconclusive"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class ReviewDiagnostic:
    code: str
    message: str
    severity: Literal["warning", "error"] = "error"


@dataclass(frozen=True, slots=True)
class ReviewRun:
    status: ReviewStatus
    result: ReviewResult | None
    diagnostics: tuple[ReviewDiagnostic, ...] = ()


class ReviewCheckpointRecord(BaseModel):
    metis_version: str
    producer: str = Field(min_length=1, pattern=r"^[A-Za-z_]\w*$")
    key: str = Field(min_length=1)
    record: dict[str, Any]

    model_config = ConfigDict(extra="forbid", frozen=True)


@dataclass(frozen=True, slots=True)
class FinalReviewRun:
    review: ReviewRun
