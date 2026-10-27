# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import json
from dataclasses import replace
from pathlib import Path

import pytest

from metis.engine.nodes.simple_llm_review.graph import ReviewGraph
from metis.engine.stages.output import StreamingOutput
from metis.engine.stages.service import ExecutionGraphService
from metis.execution_nodes import SarifFinding
from metis.sarif.triage import extract_findings
from metis.sarif.writer import generate_sarif
from test_openai_flows import openai_cli as openai_cli
from test_openai_flows import assert_reports
from test_openai_flows import review_response
from test_openai_flows import triage_response


@pytest.mark.parametrize("interactive", [False, True])
def test_cli_review_and_triage_stream_sarif(openai_cli, monkeypatch, interactive):
    root, source, config, run = openai_cli
    graph = config["metis_engine"]["execution"]
    graph["stages"].pop("initialize")
    graph["stages"]["review"].pop("inputs")
    graph["stages"]["review"]["nodes"]["simple_llm_review"] = {}
    graph["stages"]["triage"]["inputs"] = {"sarif": "review.sarif"}
    execute = ExecutionGraphService._execute_stages

    def inspect(service, *args, **kwargs):
        assert kwargs.get("plans") is None
        assert isinstance(kwargs["output"], StreamingOutput)
        result = execute(service, *args, **kwargs)
        if "review" in result.outputs:
            assert result.outputs["review"]["findings"].reviews == []
        if "triage" in result.outputs:
            assert result.outputs["triage"]["sarif"].runs == ()
        return result

    def no_materialization(*_args, **_kwargs):
        raise AssertionError("Engine loaded an entire streamed report")

    monkeypatch.setattr(ExecutionGraphService, "_execute_stages", inspect)
    monkeypatch.setattr(
        "metis.engine.stages.output.load_json_object_file", no_materialization
    )
    commands = iter(
        (
            "review_code --output-file report.html --output-file report.csv --output-file report.sarif",
            "exit",
        )
    )
    monkeypatch.setattr(
        "metis.cli.entry.prompt", lambda *_args, **_kwargs: next(commands)
    )
    run(
        [
            ("ReviewResponseModel", review_response(source)),
            ("DeduplicationDecision", {"groups": []}),
            triage_response(source, 1),
            triage_response(source, 2),
        ],
        arguments=("--quiet", "--interactive", "--triage")
        if interactive
        else ("--quiet",),
    )
    if interactive:
        assert not (root / "report.json").exists()
        findings = json.loads((root / "report.sarif").read_text())["runs"][0]["results"]
        assert len(findings) == 2 and all(
            item["properties"]["metisTriaged"] for item in findings
        )
        for suffix in ("html", "csv"):
            assert "Unchecked access" in (root / f"report.{suffix}").read_text()
    else:
        assert_reports(root, source, triaged=True)


def test_file_triage_preserves_public_findings(engine, tmp_path, monkeypatch):
    groups = [
        {"file": path, "reviews": [{"id": name, "issue": name} for name in names]}
        for path, names in (
            ("source.c", ("prior", "first")),
            ("empty.c", ()),
            ("source.c", ("second",)),
        )
    ]
    groups[0]["reviews"][0].update(metisTriaged=True, metisTriageStatus="valid")
    review = {"reviews": groups}
    source = tmp_path / "input.json"
    source.write_text(json.dumps(review))
    expected = extract_findings(generate_sarif(review, read_source=False))

    def check_finding(finding):
        assert type(finding) is SarifFinding and replace(finding) in expected
        assert (finding.run_index, finding.result_index) in ((0, 1), (0, 2))

    def classify(finding, *_args, **_kwargs):
        check_finding(finding)
        return {"status": "valid", "reason": "Checked"}

    def progress(event):
        if "finding" in event:
            check_finding(event["finding"])

    monkeypatch.setattr(engine._triage_classifier, "classify", classify)
    for suffix in ("json", "sarif"):
        target = tmp_path / f"triaged.{suffix}"
        result = engine.execute_triage_file(source, target, progress_callback=progress)
        assert result["processed"] == result["total"] == 2
        document = json.loads(target.read_text())
        if suffix == "json":
            assert document["reviews"][1]["reviews"] == []
            document = generate_sarif(document, read_source=False)
        findings = document["runs"][0]["results"]
        assert [item["properties"]["metisFindingId"] for item in findings] == [
            "prior",
            "first",
            "second",
        ]
        assert all(item["properties"]["metisTriaged"] for item in findings)


def test_streaming_patch_preserves_repeated_entries(engine, monkeypatch):
    root = Path(engine.codebase_path)
    (root / "source.c").write_text("int example() {\n    return 0;\n}\n")
    patch = root / "changes.diff"
    patch.write_text(
        "".join(
            "diff --git a/source.c b/source.c\n--- a/source.c\n+++ b/source.c\n"
            f"@@ -1,2 +1,2 @@\n int example() {{\n-    return {before};\n+    return {after};\n"
            for before, after in ((0, 10000), (10000, 20000), (20000, 30000))
        )
    )

    def review(_graph, request, *, emit=None, **_kwargs):
        findings = (
            []
            if "+    return 20000;" in request["snippet"]
            else [{"issue": "Finding"}] * 2
        )
        result = {
            "file": request["relative_file"],
            "file_path": request["file_path"],
            "reviews": findings,
        }
        if emit is not None:
            emit(result)
            result = {**result, "reviews": []}
        return result

    monkeypatch.setattr(ReviewGraph, "review", review)
    monkeypatch.setattr(
        "metis.engine.nodes.simple_llm_review.service.summarize_changes",
        lambda _provider, _path, issues, *_args, **_kwargs: issues,
    )
    expected = engine.execute_review("patch", target=str(patch))["findings"]
    output = root / "streamed.json"
    engine.execute_review("patch", target=str(patch), output_path=output)
    streamed = json.loads(output.read_text())
    assert [len(group["reviews"]) for group in streamed["reviews"]] == [2, 0, 2]
    for report in (expected, streamed):
        for group in report["reviews"]:
            for finding in group["reviews"]:
                finding.pop("id")
    assert streamed == expected
