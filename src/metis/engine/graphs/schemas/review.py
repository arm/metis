# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from typing import Literal

from pydantic import BaseModel, Field, confloat, constr, field_validator, ConfigDict


_CWE_PATTERN = r"^(CWE-[1-9]\d*|CWE-Unknown)$"
_PROMPT_INDENT = "    "


class ReviewIssueModel(BaseModel):
    issue: constr(strip_whitespace=True, min_length=1) = Field(
        description="A short description of the vulnerability."
    )
    code_snippet: constr(strip_whitespace=True, min_length=1) = Field(
        description="""The exact lines of code that exhibit this vulnerability. This field should
                       only contain code found in the file."""
    )
    reasoning: constr(strip_whitespace=True, min_length=1) = Field(
        description="A detailed explanation of why you identified this as a vulnerability."
    )
    mitigation: constr(strip_whitespace=True, min_length=1) = Field(
        description="A recommended approach or fix to resolve the issue."
    )
    confidence: confloat(ge=0.0, le=1.0) = Field(
        description="""A float between 0 and 1 indicating your confidence in the finding.
                       Scoring guidelines:
                       1.0-0.9: Confirmed, trivial to exploit.
                       0.89-0.8: Strong evidence pointing to known vulnerability pattern.
                       0.79-0.7: Pattern appears exploitable but required specific preconditions. Limited evidence.
                       <0.69: Speculative issue, not enough information."""
    )
    cwe: constr(pattern=_CWE_PATTERN) = Field(
        description="""The most appropriate CWE identifier in the format "CWE-<number>"
                      '(e.g. "CWE-79"). If no suitable CWE exists, respond with "CWE-Unknown"."""
    )
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = Field(
        description="""A qualitative rating of the risk level based on CVSS 4.0.
                       Choose one of: LOW, MEDIUM, HIGH, CRITICAL."""
    )

    @field_validator("severity", mode="before")
    @classmethod
    def _normalize_severity(cls, value: str):
        if isinstance(value, str):
            normalized = value.strip().upper()
            mapping = {
                "MED": "MEDIUM",
                "MID": "MEDIUM",
                "CRIT": "CRITICAL",
            }
            return mapping.get(normalized, normalized)
        return value

    model_config = ConfigDict(extra="forbid")


class ReviewResponseModel(BaseModel):
    reviews: list[ReviewIssueModel] = Field(
        default_factory=list,
        description="Collection of structured security review findings",
    )

    model_config = ConfigDict(extra="allow")


def review_schema_json():
    """Return the JSON schema derived from the Pydantic response model."""
    return ReviewResponseModel.model_json_schema()


def review_schema_prompt():
    """
    Generate a bullet list describing the review schema for inclusion in prompts.
    """
    lines: list[str] = []
    for field_name, field_info in ReviewIssueModel.model_fields.items():
        description = field_info.description or ""
        lines.append(f'{_PROMPT_INDENT}- "{field_name}": {description}')
    return "\n".join(lines)
