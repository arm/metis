# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import pytest

from metis.engine.graphs.utils import build_review_system_prompt


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
