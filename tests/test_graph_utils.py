# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates
# SPDX-License-Identifier: Apache-2.0

from metis.engine.graphs.utils import get_review_schema, validate_json_schema


def test_get_review_schema_and_validate_true():
    schema = get_review_schema()
    valid = {
        "reviews": [
            {
                "issue": "Example",
                "code_snippet": "int main(){}",
                "reasoning": "why",
                "mitigation": "do X",
                "confidence": 0.9,
                "cwe": "CWE-79",
                "severity": "Low",
            }
        ]
    }
    assert validate_json_schema(valid, schema) is True


def test_validate_json_schema_false_on_missing_required():
    schema = get_review_schema()
    invalid = {"reviews": [{"issue": "Only issue field"}]}
    assert validate_json_schema(invalid, schema) is False
