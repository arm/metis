# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from unittest.mock import Mock

import pytest

from metis.engine import MetisEngine
from metis.cvss import populate_cvss_data


@pytest.fixture
def engine_all_in_one(dummy_backend, dummy_llm):
    return MetisEngine(
        codebase_path="./tests/data",
        vector_backend=dummy_backend,
        language_plugin="c",
        llm_provider=dummy_llm,
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        response_mode="compact",
        cvss_all_in_one=True,
    )


def test_populate_cvss_from_issue(engine_all_in_one):
    issue = {
        "issue": "Example",
        "cvss_metrics": {
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
        },
        "cvss_rating": "critical",
    }

    populate_cvss_data(issue)

    assert "cvss" in issue
    cvss = issue["cvss"]
    assert cvss["vector"].startswith("CVSS:4.0/")
    assert cvss["score"] == pytest.approx(10.0)
    assert cvss["severity"] == "Critical"


def test_populate_cvss_with_rating_only():
    issue = {
        "issue": "Example",
        "cvss_rating": "high",
    }

    populate_cvss_data(issue)

    assert "cvss" in issue
    cvss = issue["cvss"]
    assert cvss.get("severity") == "High"
    assert "vector" not in cvss
