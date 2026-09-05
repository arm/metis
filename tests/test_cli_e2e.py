# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Run the actual CLI against an offline extension and inspect published artifacts."""

import csv
import json
import stat
import subprocess
import sys

import pytest
import yaml

from test_execution_e2e import extension_environment
from test_execution_e2e import extension_graph
from test_execution_e2e import (
    installed_execution_extension as installed_execution_extension,
)
from test_execution_e2e import write_execution_config


def run_cli(
    installation, directory, *arguments, input_text=None, config_file="metis.yaml"
):
    return subprocess.run(
        [sys.executable, "-m", "metis", "--config", config_file, *arguments],
        cwd=directory,
        env=extension_environment(
            installation, METIS_E2E_EVENTS=directory / "events.jsonl"
        ),
        capture_output=True,
        text=True,
        input=input_text,
        timeout=30,
    )


@pytest.mark.parametrize(
    ("status", "verbose", "explicit"),
    [
        ("ok", False, True),
        ("ok", True, False),
        ("inconclusive", False, False),
        ("inconclusive", True, True),
    ],
)
def test_cli_executes_installed_extension_and_publishes_reports(
    installed_execution_extension, tmp_path, status, verbose, explicit
):
    graph = extension_graph()
    graph["node_configuration"]["review"] = {"e2e_result": {"status": status}}
    config_file = "custom-config.yml" if explicit else "metis.yaml"
    write_execution_config(tmp_path / config_file, graph)
    arguments = ["--log-workflow-debug", "--log-workflow-debug-path", "trace.ndjson"]
    if verbose:
        arguments.append("--verbose")
    if explicit:
        for suffix in ("json", "sarif", "html", "csv"):
            target = tmp_path / f"report.{suffix}"
            target.write_text("previous report", encoding="utf-8")
            target.chmod(0o640)
            arguments.extend(["--output-file", target.name])
    completed = run_cli(
        installed_execution_extension, tmp_path, *arguments, config_file=config_file
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert (
        "inconclusive results" if status == "inconclusive" else "graph complete"
    ) in completed.stdout
    assert ("Inert extension warning" in completed.stdout) == (status == "inconclusive")
    json_path = (
        tmp_path / "report.json"
        if explicit
        else next((tmp_path / "results").glob("*.json"))
    )
    report = json.loads(json_path.read_text())
    assert report["reviews"][0]["reviews"][0]["id"] == "e2e-1"
    sarif = json.loads(json_path.with_suffix(".sarif").read_text())
    assert (
        sarif["runs"][0]["results"][0]["message"]["text"] == "Inert extension fixture"
    )
    assert stat.S_IMODE(json_path.stat().st_mode) == 0o600
    if explicit:
        assert "Inert extension fixture" in (tmp_path / "report.html").read_text()
        with (tmp_path / "report.csv").open(newline="", encoding="utf-8") as handle:
            assert list(csv.DictReader(handle))[0]["Issue"] == "Inert extension fixture"
        for suffix in ("html", "csv"):
            assert stat.S_IMODE((tmp_path / f"report.{suffix}").stat().st_mode) == 0o640
    trace = [
        json.loads(line)
        for line in (tmp_path / "trace.ndjson").read_text().splitlines()
    ]
    assert trace[0]["kind"] == trace[-1]["kind"] == "run"
    if status == "ok":
        assert trace[-1]["status"] == "ok"
    assert any(
        item["record"] == "span.start"
        and item.get("kind") == "command"
        and item["name"] == "execution_graph"
        for item in trace
    )
    assert any(item.get("status") == status for item in trace)
    events = [
        json.loads(line)["event"]
        for line in (tmp_path / "events.jsonl").read_text().splitlines()
    ]
    assert events.index("seed") < events.index("join") < events.index("review")
    assert not list(tmp_path.rglob("*.tmp"))


def test_cli_uses_filename_from_external_result_node(
    installed_execution_extension, tmp_path
):
    graph = extension_graph()
    graph["stages"]["review"]["nodes"]["e2e_result"] = {
        "filename": "custom-result",
        "formats": ["json", "sarif"],
    }
    graph["stages"]["review"]["outputs"]["filename"] = "e2e_result.filename"
    write_execution_config(tmp_path / "metis.yaml", graph)

    completed = run_cli(installed_execution_extension, tmp_path)

    assert completed.returncode == 0, completed.stdout + completed.stderr
    report = json.loads((tmp_path / "custom-result.json").read_text())
    assert report["reviews"][0]["reviews"][0]["id"] == "e2e-1"
    sarif = json.loads((tmp_path / "custom-result.sarif").read_text())
    assert (
        sarif["runs"][0]["results"][0]["message"]["text"] == "Inert extension fixture"
    )


@pytest.mark.parametrize("explicit", [False, True], ids=["configured", "explicit"])
def test_cli_preserves_valid_findings_when_sarif_producer_fails(
    installed_execution_extension, tmp_path, explicit
):
    write_execution_config(tmp_path / "metis.yaml", extension_graph(fail=True))
    old_sarif = tmp_path / "report.sarif"
    old_sarif.write_text("previous complete report", encoding="utf-8")
    arguments = ["--output-files", "report.json", "report.sarif"] if explicit else []
    completed = run_cli(installed_execution_extension, tmp_path, *arguments)
    assert completed.returncode == 1, completed.stdout + completed.stderr
    assert "Deliberate fixture failure" in completed.stdout
    assert "Unable to save partial outputs" not in completed.stdout
    report_path = (
        tmp_path / "report.json"
        if explicit
        else next((tmp_path / "results").glob("*.json"))
    )
    assert (
        json.loads(report_path.read_text())["reviews"][0]["reviews"][0]["id"] == "e2e-1"
    )
    assert old_sarif.read_text() == "previous complete report"
    assert list(tmp_path.rglob("*.sarif")) == [old_sarif]
    assert not list(tmp_path.rglob("*.tmp"))


def test_cli_checkpoint_round_trip_across_processes(
    installed_execution_extension, tmp_path
):
    config_path = write_execution_config(tmp_path / "metis.yaml", extension_graph())
    configuration = yaml.safe_load(config_path.read_text())
    configuration["metis_engine"]["review_checkpoints"] = True
    config_path.write_text(yaml.safe_dump(configuration), encoding="utf-8")
    for _ in range(2):
        completed = run_cli(
            installed_execution_extension, tmp_path, "--output-file", "report.json"
        )
        assert completed.returncode == 0, completed.stdout + completed.stderr
    resumes = [
        item["records"]
        for line in (tmp_path / "events.jsonl").read_text().splitlines()
        if (item := json.loads(line))["event"] == "resume"
    ]
    assert resumes == [None, {"fixture": {"completed": True}}]
    assert (tmp_path / ".metis" / "checkpoints" / "review.e2e_result.sqlite3").is_file()
    assert not list(tmp_path.glob("*.sqlite3"))


def test_interactive_cli_rejects_bad_arguments_and_recovers_without_outputs(
    installed_execution_extension, tmp_path
):
    write_execution_config(tmp_path / "metis.yaml", extension_graph())
    completed = run_cli(
        installed_execution_extension,
        tmp_path,
        "--interactive",
        input_text="\n".join(
            [
                "review_file one.txt two.txt",
                "index ignored",
                "ask",
                "help ignored",
                "exit ignored",
                "review_file one.txt --output-file",
                "version",
                "exit",
                "",
            ]
        ),
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "requires exactly one file path" in completed.stdout
    assert "requires a question" in completed.stdout
    assert completed.stdout.count("does not accept positional arguments") >= 3
    assert "--output-file requires a filename" in completed.stdout
    assert "Goodbye" in completed.stdout
    assert not (tmp_path / "results").exists()
    assert not list(tmp_path.glob("*.json"))


@pytest.mark.parametrize("config_kind", ["missing", "directory"])
def test_cli_reports_config_path_errors_without_traceback(
    installed_execution_extension, tmp_path, config_kind
):
    if config_kind == "directory":
        (tmp_path / "metis.yaml").mkdir()
    completed = run_cli(installed_execution_extension, tmp_path)
    assert completed.returncode == 1
    assert "Error:" in completed.stdout
    assert "Traceback" not in completed.stderr
    assert not (tmp_path / "events.jsonl").exists()
    assert not (tmp_path / "results").exists()


@pytest.mark.parametrize(
    "configuration", ["metis_engine: [", "metis_engine:\n  max_workers: 0\n"]
)
def test_cli_reports_invalid_yaml_before_engine_setup(
    installed_execution_extension, tmp_path, configuration
):
    (tmp_path / "metis.yaml").write_text(configuration, encoding="utf-8")
    completed = run_cli(installed_execution_extension, tmp_path)
    assert completed.returncode == 1
    assert "Error:" in completed.stdout
    assert "Traceback" not in completed.stderr
    assert not (tmp_path / "events.jsonl").exists()
    assert not (tmp_path / "results").exists()
