# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import pytest
from pydantic import ValidationError

from metis.engine.graphs.schemas import ReviewResponseModel


def _make_issue(**overrides):
    base = {
        "issue": "Example vulnerability",
        "code_snippet": "int main() { return 0; }",
        "reasoning": "Demonstration reasoning text.",
        "mitigation": "Suggested fix text.",
        "confidence": 0.5,
        "cwe": "CWE-79",
        "severity": "HIGH",
    }
    base.update(overrides)
    return base


def test_review_issue_model_normalizes_severity_text():
    payload = {"reviews": [_make_issue(severity="Medium")]}
    model = ReviewResponseModel.model_validate(payload)
    assert model.reviews[0].severity == "MEDIUM"

    payload = {"reviews": [_make_issue(severity="crit")]}
    model = ReviewResponseModel.model_validate(payload)
    assert model.reviews[0].severity == "CRITICAL"


def test_review_issue_model_rejects_extra_fields():
    payload = {"reviews": [_make_issue(line_number=42)]}
    with pytest.raises(ValidationError):
        ReviewResponseModel.model_validate(payload)
