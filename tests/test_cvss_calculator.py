# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import pytest

from metis.cvss.calculator import (
    calculate_cvss_score,
    compute_cvss_severity,
    format_cvss_vector,
    normalize_metric_values,
    normalize_cvss_rating,
    populate_cvss_data,
)


@pytest.fixture
def all_metrics():
    return {
        "AV": "n",
        "AC": "l",
        "AT": "n",
        "PR": "n",
        "UI": "n",
        "VC": "h",
        "VI": "h",
        "VA": "h",
        "SC": "h",
        "SI": "h",
        "SA": "h",
    }


def test_calculate_cvss_score(all_metrics):
    score = calculate_cvss_score(all_metrics)
    assert score == pytest.approx(10.0)


def test_format_vector(all_metrics):
    vector = format_cvss_vector(all_metrics)
    assert (
        vector
        == "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
    )


def test_compute_severity():
    severity = compute_cvss_severity(
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
    )
    assert severity == "Critical"


def test_normalize_metric_values():
    normalized = normalize_metric_values({"av": "n", "UI": "p"})
    assert normalized["AV"] == "N"
    assert normalized["UI"] == "P"


def test_normalize_rating():
    assert normalize_cvss_rating("med") == "Medium"
    assert normalize_cvss_rating("CRITICAL") == "Critical"


def test_populate_issue_with_metrics():
    issue = {
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
        }
    }
    populate_cvss_data(issue)
    cvss = issue["cvss"]
    assert cvss["vector"].startswith("CVSS:4.0/")
    assert cvss["severity"] == "Critical"


def test_populate_issue_with_rating():
    issue = {"cvss_rating": "high"}
    populate_cvss_data(issue)
    assert issue["cvss"]["severity"] == "High"
