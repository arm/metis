# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import pytest

from metis.engine.graphs.utils import (
    build_review_system_prompt,
    sanitize_review_payload,
)
from metis.engine.graphs.review import review_node_llm


def test_build_review_system_prompt_requires_placeholder():
    language_prompts = {
        "security_review_file": "Review intro text without placeholder.",
        "security_review_checks": "Checklist items.",
    }
    schema_section = '- "issue": description'
    with pytest.raises(ValueError):
        build_review_system_prompt(
            language_prompts,
            "security_review_file",
            report_prompt="Reporting instructions.",
            custom_prompt_text=None,
            custom_guidance_precedence="",
            schema_prompt_section=schema_section,
        )


def test_build_review_system_prompt_replaces_placeholder():
    language_prompts = {
        "security_review_file": "Intro [[REVIEW_SCHEMA_FIELDS]]",
        "security_review_checks": "Checklist items.",
    }
    schema_section = '- "issue": description'
    prompt = build_review_system_prompt(
        language_prompts,
        "security_review_file",
        report_prompt="Reporting instructions.",
        custom_prompt_text=None,
        custom_guidance_precedence="",
        schema_prompt_section=schema_section,
    )
    assert schema_section in prompt


def test_sanitize_review_payload_fills_missing_fields():
    payload = {
        "reviews": [
            {
                "issue": "Missing fields",
                "code_snippet": "secret = 'abc'",
                # reasoning / mitigation / cwe / severity / confidence absent
            }
        ]
    }

    sanitized = sanitize_review_payload(payload)

    assert len(sanitized) == 1
    entry = sanitized[0]
    assert entry["issue"] == "Missing fields"
    assert entry["reasoning"] == ""
    assert entry["mitigation"] == ""
    assert entry["cwe"] == ""
    assert entry["severity"] == ""
    assert entry["confidence"] == 0.0


def test_review_node_llm_keeps_partial_reviews():
    payload = {
        "reviews": [
            {
                "issue": "Partial",
                "code_snippet": "foo = 1",
            }
        ]
    }

    class _DummyNode:
        def __init__(self, response):
            self._response = response

        def invoke(self, _payload):
            return self._response

    state = {
        "file_path": "foo.py",
        "snippet": "print('hello')",
        "context": "",
        "mode": "file",
        "system_prompt": "",
    }

    result_state = review_node_llm(
        state,
        structured_node=_DummyNode(payload),
        fallback_node=None,
    )

    parsed = result_state["parsed_reviews"]
    assert len(parsed) == 1
    issue = parsed[0]
    assert issue["issue"] == "Partial"
    assert issue["reasoning"] == ""
    assert issue["mitigation"] == ""
    assert issue["cwe"] == ""
    assert issue["severity"] == ""
    assert issue["confidence"] == 0.0
