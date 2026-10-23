# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import csv
import json
import sqlite3
import subprocess
import sys
from urllib.parse import unquote

import httpx
import pytest
import yaml
from langchain_openai import ChatOpenAI

from metis.cli.entry import main
from metis.configuration import load_metis_config
from metis.sarif.triage import extract_findings


@pytest.fixture
def openai_cli(tmp_path, monkeypatch):
    root = tmp_path / "repository [literal] # ü"
    root.mkdir()
    source = root / "literal # %2F ü.c"
    source.write_text(
        "int first(int *data) { return data[4]; }\n"
        "int second(int *data) { return data[8]; }\n",
        encoding="utf-8",
    )
    config = load_metis_config()
    config["query"].pop("temperature")
    config["llm_provider"] = {
        "name": "openai",
        "model": "gpt-6-astra",
        "api_key": "offline-test-only",
        "base_url": "https://offline.invalid/v1",
    }
    config["metis_engine"].update(
        max_workers=1,
        llm_max_retries=2,
        triage_checkpoint_every=1,
        review_checkpoints=False,
    )
    config["metis_engine"]["execution"]["inputs"]["review_request"] = {
        "mode": "file",
        "target": f"./{source.name}",
    }
    monkeypatch.chdir(root)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("LANGSMITH_TRACING", "false")
    monkeypatch.setenv("LANGCHAIN_TRACING_V2", "false")
    monkeypatch.setattr(
        "metis.providers.openai_compatible.tiktoken_token_count",
        lambda text, model=None: len(text),
    )

    def run(responses, *, exit_code=0):
        requests = []
        pending = list(responses)

        def respond(request):
            assert str(request.url) == "https://offline.invalid/v1/responses"
            body = json.loads(request.content)
            requests.append(body)
            if not pending:
                return httpx.Response(
                    400, json={"error": {"message": "Unexpected request"}}
                )
            response = pending.pop(0)
            if isinstance(response, httpx.Response):
                return response
            name, arguments = response
            if name:
                assert name in {tool["name"] for tool in body["tools"]}
                output = {
                    "type": "function_call",
                    "id": "fc_offline",
                    "call_id": "call_offline",
                    "name": name,
                    "arguments": json.dumps(arguments),
                    "status": "completed",
                }
            else:
                output = {
                    "type": "message",
                    "id": "msg_offline",
                    "role": "assistant",
                    "content": [
                        {
                            "type": "output_text",
                            "text": json.dumps(arguments),
                            "annotations": [],
                        }
                    ],
                    "status": "completed",
                }
            return httpx.Response(
                200,
                json={
                    "id": "resp_offline",
                    "object": "response",
                    "created_at": 1,
                    "model": body["model"],
                    "status": "completed",
                    "error": None,
                    "incomplete_details": None,
                    "parallel_tool_calls": False,
                    "output": [output],
                },
            )

        config_path = tmp_path / "input.yaml"
        config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
        with httpx.Client(transport=httpx.MockTransport(respond)) as client:
            monkeypatch.setattr(
                "metis.providers.openai_compatible.ChatOpenAI",
                lambda **kwargs: ChatOpenAI(http_client=client, **kwargs),
            )
            monkeypatch.setattr(
                sys,
                "argv",
                [
                    "metis",
                    "--config",
                    str(config_path),
                    "--codebase-path",
                    str(root),
                    "--output-files",
                    "report.json",
                    "report.sarif",
                    "report.html",
                    "report.csv",
                ],
            )
            actual_exit = 0
            try:
                main()
            except SystemExit as error:
                actual_exit = error.code
        assert actual_exit == exit_code, requests
        for request in requests:
            temperature = config["query"].get("temperature")
            if temperature is None:
                assert "temperature" not in request
            else:
                assert request["temperature"] == temperature
        assert len(requests) == len(responses) and not pending, requests
        assert not (root / "chromadb").exists()
        assert not list(root.rglob("*.tmp"))
        return requests

    return root, source, config, run


def review_response(source):
    return {
        "reviews": [
            {
                "issue": f"Unchecked access {line}",
                "start_line": line,
                "code_snippet": snippet,
                "reasoning": "The supplied buffer may be too short.",
                "mitigation": "Validate the buffer length.",
                "confidence": 0.99,
                "cwe": "CWE-125",
                "severity": "HIGH",
            }
            for line, snippet in enumerate(source.read_text().splitlines(), 1)
        ]
    }


def triage_response(source, line):
    return None, {
        "status": "valid",
        "reason": "The inspected access has no length guard.",
        "evidence": [f"{source.name}:{line}-{line}"],
        "resolution_chain": [
            f"caller-provided data -> {source.name}:{line} unchecked access"
        ],
        "unresolved_hops": [],
    }


def memory_rows(root):
    with sqlite3.connect(root / ".metis/memory/metis_memory.sqlite3") as connection:
        return connection.execute(
            "SELECT * FROM memory_records ORDER BY namespace, key"
        ).fetchall()


def assert_reports(root, source, *, triaged):
    report = json.loads((root / "report.json").read_text())
    sarif = json.loads((root / "report.sarif").read_text())
    findings = report["reviews"][0]["reviews"]
    results = sarif["runs"][0]["results"]
    assert len(findings) == len(results) == 2
    assert len({finding["id"] for finding in findings}) == 2
    assert report["reviews"][0]["file"] == source.name
    with (root / "report.csv").open(newline="") as handle:
        rows = list(csv.DictReader(handle))
    html = (root / "report.html").read_text()
    html_issues = json.loads(
        html.split('<script id="report-data" type="application/json">', 1)[1].split(
            "</script>", 1
        )[0]
    )["issues"]
    assert len(rows) == 2
    for line, (finding, result, row) in enumerate(
        zip(findings, results, rows, strict=True), 1
    ):
        properties = result["properties"]
        location = result["locations"][0]["physicalLocation"]
        assert finding["id"] == properties["metisFindingId"]
        assert unquote(location["artifactLocation"]["uri"]) == source.name
        assert location["region"]["startLine"] == line
        assert (
            location["region"]["snippet"]["text"]
            == source.read_text().splitlines()[line - 1]
        )
        assert finding["issue"] == result["message"]["text"] == row["Issue"]
        assert row["File"] == source.name and row["Line"] == str(line)
        assert (
            row["Severity"].upper()
            == properties["severity"].upper()
            == finding["severity"].upper()
            == "HIGH"
        )
        assert row["CWE"] == properties["cwe"] == finding["cwe"] == "CWE-125"
        assert row["Reasoning"] == properties["reasoning"] == finding["reasoning"]
        assert row["Mitigation"] == properties["mitigation"] == finding["mitigation"]
        for field in (
            "file",
            "line",
            "severity",
            "cwe",
            "issue",
            "reasoning",
            "mitigation",
        ):
            assert (
                html_issues[line - 1][field]
                == row[field.capitalize() if field != "cwe" else "CWE"]
            )
        if triaged:
            for value in (finding, properties):
                assert value["metisTriaged"] is True
                assert value["metisTriageStatus"] == "valid"
                assert value["metisTriageDecisionSource"] == "model"
                assert value["metisTriageEvidence"] == [f"{source.name}:{line}"]
    return sarif


@pytest.mark.parametrize("document_present", [True, False], ids=["document", "missing"])
@pytest.mark.parametrize(
    ("model", "query"),
    [
        ("gpt-6-astra", {}),
        ("gpt-4.1", {}),
        ("gpt-4.1", {"temperature": None}),
        ("gpt-4.1", {"temperature": 0.0}),
        ("gpt-4.1", {"temperature": 0.7}),
    ],
    ids=["reasoning", "omitted", "null", "zero", "configured"],
)
def test_combined_cli_refreshes_and_reuses_repository_context(
    openai_cli, document_present, model, query
):
    root, source, config, run = openai_cli
    config["llm_provider"]["model"] = model
    config["query"].update(query)
    threat = config["metis_engine"]["threat_model"]
    threat["source_patterns"] = ["SECURITY.md"]
    assert threat["history"]["enabled"] is False
    claim = {
        "claim_type": "scope_rule",
        "statement": "Buffer capacity is a caller responsibility.",
        "applies_to": ["repository"],
        "disposition": "advisory",
    }
    setup = []
    if document_present:
        (root / "SECURITY.md").write_text(claim["statement"])
        setup = [
            (
                "_ThreatSourceClaimResponseModel",
                {"records": [claim]},
            ),
            (
                "_ThreatSourceClaimReductionResponseModel",
                {"records": [{**claim, "source_claim_indexes": [0]}]},
            ),
        ]
    else:
        for arguments in (
            ["init"],
            ["add", "--", source.name],
            [
                "-c",
                "user.name=Offline Test",
                "-c",
                "user.email=offline@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-m",
                "Require buffer bounds checks",
            ],
        ):
            subprocess.run(
                ["git", "-c", "core.hooksPath=/dev/null", *arguments],
                cwd=root,
                check=True,
                capture_output=True,
                timeout=30,
            )
    reviews = review_response(source)
    for finding in reviews["reviews"]:
        finding["id"] = " duplicate "
    decisions = [
        (None, reviews),
        ("DeduplicationDecision", {"groups": []}),
        triage_response(source, 1),
        triage_response(source, 2),
    ]
    requests = run([*setup, *decisions])
    expected_claim = claim["statement"] if document_present else None
    request_batches = [(requests[len(setup) :], expected_claim)]
    sarif = assert_reports(root, source, triaged=True)
    assert json.loads((root / "report.checkpoint.sarif").read_text()) == sarif
    rows = memory_rows(root)
    assert rows
    records = [json.loads(row[2]) for row in rows]
    if document_present:
        source_prompt = json.dumps(requests[0]["input"])
        assert "Source path: SECURITY.md" in source_prompt
        assert claim["statement"] in source_prompt and "int first" not in source_prompt
        assert any(record["authority"] == "authoritative" for record in records)
    else:
        assert [record["artifact_type"] for record in records] == [
            "threat_model_snapshot"
        ]
        assert "threat_model_snapshot" not in json.dumps(requests[-1])
    with sqlite3.connect(root / ".metis/codegraph.sqlite3") as connection:
        graphs = connection.execute("SELECT * FROM canonical_codegraph").fetchall()
        assert len(graphs) == 1
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM codegraph_records WHERE kind = 'node'"
            ).fetchone()[0]
            == 2
        )
    request_batches.append((run(decisions), expected_claim))
    assert memory_rows(root) == rows
    with sqlite3.connect(root / ".metis/codegraph.sqlite3") as connection:
        assert (
            connection.execute("SELECT * FROM canonical_codegraph").fetchall() == graphs
        )
    rerun = assert_reports(root, source, triaged=True)
    assert [
        result["partialFingerprints"] for result in rerun["runs"][0]["results"]
    ] == [result["partialFingerprints"] for result in sarif["runs"][0]["results"]]
    if document_present:
        claim["statement"] = "Buffer capacity must be checked before every access."
        (root / "SECURITY.md").write_text(claim["statement"])
        setup[1][1]["records"][0]["statement"] = claim["statement"]
        requests = run([*setup, *decisions])
        request_batches.append((requests[len(setup) :], claim["statement"]))
        assert memory_rows(root) != rows
        assert claim["statement"] in json.dumps(memory_rows(root))
        assert_reports(root, source, triaged=True)
    else:
        threat["history"]["enabled"] = True
        lesson = {
            "statement": "Buffer accesses have required bounds hardening.",
            "applies_to": ["repository"],
            "source_commit_indexes": [0],
        }
        requests = run(
            [
                ("_HistoryLessonResponseModel", {"records": [lesson]}),
                *decisions,
            ]
        )
        assert "Require buffer bounds checks" in json.dumps(requests[0]["input"])
        assert "int first" not in json.dumps(requests[0]["input"])
        request_batches.append(
            (requests[1:], f"[history_derived, advisory] {lesson['statement']}")
        )
        records = [json.loads(row[2]) for row in memory_rows(root)]
        assert [record["artifact_type"] for record in records] == [
            "threat_model_history_lesson"
        ]
        assert records[0]["body_json"]["source_commits"][0]["message"] == (
            "Require buffer bounds checks"
        )
        assert_reports(root, source, triaged=True)
    rows = memory_rows(root)
    request_batches.append((run(decisions), request_batches[-1][1]))
    assert memory_rows(root) == rows
    assert_reports(root, source, triaged=True)
    if not document_present:
        threat["history"]["enabled"] = False
        request_batches.append((run(decisions), None))
        assert [json.loads(row[2])["artifact_type"] for row in memory_rows(root)] == [
            "threat_model_snapshot"
        ]

    for requests, expected_claim in request_batches:
        prompts = [
            next(
                message["content"]
                for message in request["input"]
                if message["role"] == "user"
            )
            for request in (requests[0], *requests[-2:])
        ]
        if expected_claim is not None:
            for prompt in prompts:
                assert expected_claim in prompt
        else:
            assert "THREAT_MODEL_CONTEXT:" not in prompts[0]
            assert all("Threat-Model Context:" not in prompt for prompt in prompts[1:])
        for line, (function, prompt) in enumerate(
            zip(("first", "second"), prompts[1:], strict=True), 1
        ):
            assert (
                f"[CODEGRAPH_CONTEXT]\ntarget: {source.name}::{function} at {source.name}:{line}"
                in prompt
            )


@pytest.mark.parametrize("max_rounds", [1, 3])
def test_checkpoint_limit_does_not_override_yaml_tool_rounds(
    openai_cli, monkeypatch, max_rounds
):
    root, source, config, run = openai_cli
    config["metis_engine"]["review_checkpoints"] = True
    config["metis_engine"]["model_tools"]["max_rounds"] = max_rounds
    graph = config["metis_engine"]["execution"]
    graph["stages"].pop("initialize")
    graph["stages"].pop("triage")
    graph["stages"]["review"].pop("inputs")
    monkeypatch.setattr(
        "metis.engine.nodes.simple_llm_review.graph._MAX_CHECKPOINT_TOOL_OBSERVATIONS",
        1,
    )
    dedup = ("DeduplicationDecision", {"groups": []})
    responses = [
        *[("cat", {"path": source.name})] * max_rounds,
        (None, review_response(source)),
        dedup,
    ]
    requests = run(responses)
    assert len(requests) == max_rounds + 2
    assert requests[max_rounds]["tool_choice"] == "none"
    assert_reports(root, source, triaged=False)
    resumed = run([dedup] if max_rounds == 1 else responses)
    assert len(resumed) == (1 if max_rounds == 1 else len(requests))


def test_review_only_then_external_triage_replays_checkpoint(openai_cli):
    root, source, config, run = openai_cli
    graph = config["metis_engine"]["execution"]
    source = source.rename(root / f"~{source.name}")
    graph["inputs"]["review_request"]["target"] = f"./{source.name}"
    triage = graph["stages"].pop("triage")
    graph["stages"].pop("initialize")
    review = graph["stages"]["review"]
    review.pop("inputs")
    review["nodes"]["simple_llm_review"] = {}
    run(
        [
            ("ReviewResponseModel", review_response(source)),
            ("DeduplicationDecision", {"groups": []}),
        ]
    )
    original = assert_reports(root, source, triaged=False)
    original_run = original["runs"][0]
    original_run["tool"] = {"driver": {"name": "External Analyzer"}}
    original_run["properties"] = {"externalMetadata": "preserved"}
    for result, severity in zip(original_run["results"], ("", "Low"), strict=True):
        result["level"] = "error"
        result["properties"] = {"severity": severity, "externalFinding": "preserved"}
    triage["inputs"] = {"sarif": "$inputs.sarif"}
    graph.update(inputs={"sarif": original}, stages={"triage": triage})
    requests = run([triage_response(source, 1), triage_response(source, 2)])
    assert all(
        "[CODEGRAPH_CONTEXT]" not in json.dumps(request["input"])
        for request in requests
    )
    saved = json.loads((root / "report.sarif").read_text())
    assert json.loads((root / "report.json").read_text()) == saved
    saved_run = saved["runs"][0]
    assert saved_run["tool"] == original_run["tool"]
    assert saved_run["properties"] == original_run["properties"]
    for before, after in zip(
        original_run["results"], saved_run["results"], strict=True
    ):
        for key in ("locations", "level", "message"):
            assert after[key] == before[key]
        for key, value in before["properties"].items():
            assert after["properties"][key] == value
        assert after["properties"]["metisTriageDecisionSource"] == "model"
    with (root / "report.csv").open(newline="") as handle:
        assert [row["Severity"] for row in csv.DictReader(handle)] == ["Unknown", "Low"]
    html = (root / "report.html").read_text()
    html_data = json.loads(
        html.split('<script id="report-data" type="application/json">', 1)[1].split(
            "</script>", 1
        )[0]
    )
    assert [issue["severity"] for issue in html_data["issues"]] == ["Unknown", "Low"]
    assert html_data["severityCounts"] == {"Unknown": 1, "Low": 1}
    assert (
        html_data["fileStats"][source.name]["severityCounts"]
        == html_data["severityCounts"]
    )
    assert not extract_findings(saved)
    assert len(extract_findings(original)) == 2
    assert not (root / ".metis/codegraph.sqlite3").exists()
    checkpoint = json.loads((root / "report.checkpoint.sarif").read_text())
    assert checkpoint == saved
    graph["inputs"]["sarif"] = checkpoint
    run([])
    assert json.loads((root / "report.json").read_text()) == checkpoint


@pytest.mark.parametrize(
    "failure", ["review", "dedup", "authentication", "triage", "distillation"]
)
def test_cli_failures_preserve_outputs_and_recover_from_checkpoint(openai_cli, failure):
    root, source, config, run = openai_cli
    graph = config["metis_engine"]["execution"]
    initialize = graph["stages"].pop("initialize")
    triage = graph["stages"].pop("triage")
    review = graph["stages"]["review"]
    review.pop("inputs")
    review["nodes"]["simple_llm_review"] = {}
    valid = [
        ("ReviewResponseModel", review_response(source)),
        ("DeduplicationDecision", {"groups": []}),
    ]
    unauthorized = httpx.Response(
        401,
        json={
            "error": {
                "message": "Offline authentication failure",
                "type": "authentication_error",
            }
        },
    )
    previous = {}
    for suffix in ("json", "sarif", "html", "csv", "checkpoint.sarif"):
        path = root / f"report.{suffix}"
        path.write_text('{"prior":"readable"}')
        previous[path] = path.read_bytes()
    if failure == "distillation":
        graph["stages"]["initialize"] = initialize
        review["inputs"] = {"codegraph": "initialize.codegraph"}
        config["metis_engine"]["threat_model"]["source_patterns"] = ["SECURITY.md"]
        claim = {
            "claim_type": "asset",
            "statement": "Caller buffers are protected assets.",
            "applies_to": ["repository"],
            "disposition": "advisory",
        }
        document = root / "SECURITY.md"
        document.write_text(claim["statement"])
        run(
            [
                ("_ThreatSourceClaimResponseModel", {"records": [claim]}),
                (
                    "_ThreatSourceClaimReductionResponseModel",
                    {"records": [{**claim, "source_claim_indexes": [0]}]},
                ),
                *valid,
            ]
        )
        previous = {path: path.read_bytes() for path in previous}
        rows = memory_rows(root)
        document.write_text("Validate buffer capacity before every access.")
        requests = run([unauthorized], exit_code=1)
        assert "Source path: SECURITY.md" in json.dumps(requests[0]["input"])
        assert memory_rows(root) == rows
        assert all(path.read_bytes() == contents for path, contents in previous.items())
        document.write_text(claim["statement"])
        run(valid)
        assert memory_rows(root) == rows
        assert_reports(root, source, triaged=False)
        return
    elif failure == "triage":
        run(valid)
        original = json.loads((root / "report.sarif").read_text())
        triage["inputs"] = {"sarif": "$inputs.sarif"}
        graph.update(inputs={"sarif": original}, stages={"triage": triage})
        run([triage_response(source, 1), unauthorized], exit_code=1)
        partial = json.loads((root / "report.checkpoint.sarif").read_text())
        assert partial == json.loads((root / "report.sarif").read_text())
        assert partial == json.loads((root / "report.json").read_text())
        completed, failed = partial["runs"][0]["results"]
        assert completed["properties"]["metisTriaged"] is True
        assert completed["properties"]["metisTriageDecisionSource"] == "model"
        assert failed["properties"]["metisTriaged"] is False
        assert failed["properties"]["metisTriageDecisionSource"] == "execution_failure"
        assert len(extract_findings(partial)) == 1
        graph["inputs"]["sarif"] = partial
        run([triage_response(source, 2)])
        recovered = json.loads((root / "report.sarif").read_text())
        assert recovered["runs"][0]["results"][0] == completed
        assert not extract_findings(recovered)
        return
    elif failure == "dedup":
        run(
            [valid[0], ("DeduplicationDecision", {}), ("DeduplicationDecision", {})],
            exit_code=1,
        )
        assert_reports(root, source, triaged=False)
        return
    else:
        responses = (
            [unauthorized]
            if failure == "authentication"
            else [("ReviewResponseModel", {})] * 2
        )
        run(responses, exit_code=1)
    assert all(path.read_bytes() == contents for path, contents in previous.items())
