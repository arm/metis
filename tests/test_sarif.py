# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import hashlib

from metis.sarif.writer import generate_sarif
from metis.sarif.utils import read_file_lines, create_fingerprint


def test_read_file_lines(tmp_path):
    """Verify that read_file_lines returns all lines including newlines."""
    content = "first line\nsecond line\nthird line"
    file_path = tmp_path / "sample.txt"
    file_path.write_text(content)

    lines = read_file_lines(str(file_path))

    assert lines == ["first line\n", "second line\n", "third line"]


def test_create_fingerprint_deterministic_and_unique():
    """Ensure create_fingerprint is consistent for same inputs and different for different inputs."""
    fp1 = create_fingerprint("/path/to/file.py", 10, "RULEX")
    fp2 = create_fingerprint("/path/to/file.py", 10, "RULEX")
    fp3 = create_fingerprint("/path/to/file.py", 11, "RULEX")
    fp4 = create_fingerprint("/path/to/other.py", 10, "RULEX")

    # Deterministic for same inputs
    assert fp1 == fp2
    # Different line yields different fingerprint
    assert fp1 != fp3
    # Different file yields different fingerprint
    assert fp1 != fp4
    # Fingerprint format is hex string of expected length
    assert isinstance(fp1, str)
    assert len(fp1) == len(hashlib.sha1().hexdigest())


def test_generate_sarif_single_issue(tmp_path):
    """Test SARIF report generation for a single issue in context."""
    # Prepare a temporary file with known contents
    lines = ["alpha\n", "beta\n", "gamma\n", "delta\n"]
    temp_file = tmp_path / "code.py"
    temp_file.write_text("".join(lines))

    # Input structure for generate_sarif
    results = {
        "reviews": [
            {
                "file_path": str(temp_file),
                "file": "code.py",
                "reviews": [{"issue": "Example issue", "line_number": 2}],
            }
        ]
    }

    sarif = generate_sarif(
        results, tool_name="Metis", automation_id="auto-123", context_lines=1
    )

    # Basic SARIF structure assertions
    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    runs = sarif.get("runs", [])
    assert len(runs) == 1

    run = runs[0]
    results_array = run.get("results", [])
    assert len(results_array) == 1

    issue_entry = results_array[0]
    # Verify rule and message
    assert issue_entry["ruleId"] == "AI001"
    assert issue_entry["message"]["text"] == "Example issue"

    # Verify location URIs and context/window
    loc = issue_entry["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "code.py"

    # Region snippet corresponds to line 2 with one line of context above
    region = loc["region"]
    assert region["startLine"] == 1
    assert region["snippet"]["text"] == lines[1].strip()

    # ContextRegion covers lines 1-3
    context_region = loc["contextRegion"]
    assert context_region["startLine"] == 1
    assert context_region["endLine"] == 3
    # Combined snippet contains all three lines
    combined = context_region["snippet"]["text"]
    assert "alpha" in combined and "beta" in combined and "gamma" in combined

    # Fingerprint matches utility
    fp_expected = create_fingerprint(str(temp_file), 2, "AI001")
    assert issue_entry["partialFingerprints"]["primaryLocationLineHash"] == fp_expected
