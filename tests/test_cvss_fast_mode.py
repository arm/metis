# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import json
from unittest.mock import Mock

from metis.engine import MetisEngine


def test_cvss_fast_mode_combined_metrics(dummy_backend, dummy_llm):
    metrics_json = {
        "metrics": {
            "AV": "N",
            "AC": "L",
            "AT": "N",
            "PR": "N",
            "UI": "N",
            "VC": "H",
            "VI": "H",
            "VA": "H",
            "SC": "H",
            "SI": "H",
            "SA": "H",
        }
    }

    dummy_llm.call_llm = Mock(return_value=json.dumps(metrics_json))

    engine = MetisEngine(
        codebase_path="./tests/data",
        vector_backend=dummy_backend,
        language_plugin="c",
        llm_provider=dummy_llm,
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        response_mode="compact",
        cvss_fast_mode=True,
    )

    review = {
        "issue": "Test",
        "reasoning": "",
        "mitigation": "",
        "code_snippet": "",
        "confidence": 0.5,
    }

    general_prompts = engine.code_plugin.plugin_config.get("general_prompts", {})
    engine._attach_cvss_scoring(
        "file.c",
        "context",
        [review],
        general_prompts.get("cvss_metrics", {}),
        general_prompts.get("cvss_combined", ""),
    )

    assert "cvss" in review
    assert review["cvss"]["vector"].startswith("CVSS:4.0/")
    assert review["cvss"]["metrics"]["AV"] == "N"
    assert review["cvss"].get("severity") == "Critical"
