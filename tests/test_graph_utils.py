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


def test_build_review_system_prompt_preserves_legacy_context_prompt():
    language_prompts = {
        "security_review_file": (
            "Use FILE and RELEVANT_CONTEXT.\n"
            "2. RELEVANT_CONTEXT - information about what these changes do.\n"
            "[[REVIEW_SCHEMA_FIELDS]]"
        ),
        "security_review_checks": "- If RELEVANT_CONTEXT is empty, ignore it.",
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

    expected = (
        "Use FILE and RELEVANT_CONTEXT.\n"
        "2. RELEVANT_CONTEXT - information about what these changes do.\n"
        '- "issue": description \n '
        "- If RELEVANT_CONTEXT is empty, ignore it. \n Reporting instructions."
    )
    assert prompt == expected


def test_build_review_system_prompt_omits_relevant_context_when_disabled():
    language_prompts = {
        "security_review_file": (
            "Use FILE and RELEVANT_CONTEXT.\n"
            "2. RELEVANT_CONTEXT - information about what these changes do.\n"
            "3. ORIGINAL_FILE - original contents.\n"
            "Only produce findings justified by FILE and RELEVANT_CONTEXT.\n"
            "[[REVIEW_SCHEMA_FIELDS]]"
        ),
        "security_review_checks": "- If RELEVANT_CONTEXT is empty, ignore it.",
    }
    schema_section = '- "issue": description'
    prompt = build_review_system_prompt(
        language_prompts,
        "security_review_file",
        report_prompt="Reporting instructions.",
        custom_prompt_text=None,
        custom_guidance_precedence="",
        schema_prompt_section=schema_section,
        include_relevant_context=False,
    )

    assert "2. RELEVANT_CONTEXT" not in prompt
    assert "RELEVANT_CONTEXT" not in prompt
    assert "2. ORIGINAL_FILE" in prompt


def test_build_review_system_prompt_replaces_context_placeholders():
    language_prompts = {
        "security_review_file": (
            "1. FILE - source\n"
            "[[RELEVANT_CONTEXT_INPUT_CHANGES]]\n"
            "[[ORIGINAL_FILE_INDEX_DOT]] ORIGINAL_FILE - old\n"
            "[[REVIEW_SCHEMA_FIELDS]]"
        ),
        "security_review_checks": "[[RELEVANT_CONTEXT]]",
    }
    schema_section = '- "issue": description'

    with_context = build_review_system_prompt(
        language_prompts,
        "security_review_file",
        report_prompt="Reporting instructions.",
        custom_prompt_text=None,
        custom_guidance_precedence="",
        schema_prompt_section=schema_section,
    )
    without_context = build_review_system_prompt(
        language_prompts,
        "security_review_file",
        report_prompt="Reporting instructions.",
        custom_prompt_text=None,
        custom_guidance_precedence="",
        schema_prompt_section=schema_section,
        include_relevant_context=False,
    )

    assert (
        "2. RELEVANT_CONTEXT - information about what these changes do." in with_context
    )
    assert "- If it is empty, ignore it." in with_context
    assert "3. ORIGINAL_FILE - old" in with_context
    assert "[[RELEVANT_CONTEXT_" not in with_context
    assert (
        "RELEVANT_CONTEXT - information about what these changes do."
        not in without_context
    )
    assert "- If it is empty, ignore it." not in without_context
    assert "2. ORIGINAL_FILE - old" in without_context


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
