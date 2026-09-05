# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import json
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from metis.cli import entry, utils
from metis.engine.external_stages import service as external_service
from metis.usage import runtime as usage_runtime


class FixedClock(datetime):
    @classmethod
    def now(cls, tz=None):
        return cls(2026, 9, 4, 12, 0, 0, tzinfo=tz)


@pytest.mark.parametrize("kind", ["command", "graph", "graph_fallback"])
def test_generated_cli_paths_preserve_successive_outputs(monkeypatch, tmp_path, kind):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(entry, "datetime", FixedClock)
    monkeypatch.setattr(utils, "datetime", FixedClock)
    saved = []
    for iteration in range(2):
        if kind == "command":
            args = SimpleNamespace(output_file=None)
            entry.determine_output_file("ask", args, [])
            paths = args.output_file
        else:
            paths = utils.output_files_for_formats(
                ["configured.json"] if kind == "graph_fallback" else None,
                ("json", "csv"),
                command="graph_review",
                generated_output=True,
                reserved_paths={Path("configured.json"), Path("configured.csv")},
            )
            assert Path(paths[0]).with_suffix(".csv") == Path(paths[1])
        utils.save_output(paths, {"iteration": iteration, "reviews": []}, quiet=True)
        saved.append(Path(paths[0]))
    assert [json.loads(path.read_text())["iteration"] for path in saved] == [0, 1]


def test_generated_usage_paths_preserve_successive_sessions(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(usage_runtime, "datetime", FixedClock)
    paths = [
        usage_runtime.UsageRuntime(tmp_path / label).save_run_summary()
        for label in ("first", "second")
    ]
    assert [json.loads(Path(path).read_text())["project_name"] for path in paths] == [
        "first",
        "second",
    ]


def test_generated_external_run_directories_are_independent(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(external_service, "datetime", FixedClock)
    first = external_service._resolve_run_dir(None)
    second = external_service._resolve_run_dir(None)
    assert first != second
    assert first.parent == second.parent == tmp_path / "results" / "external_stages"
    assert external_service._resolve_run_dir(first) == first


def test_explicit_output_paths_retain_replacement_behavior(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    for iteration in range(2):
        args = SimpleNamespace(output_file=["explicit.json"])
        entry.determine_output_file("ask", args, [])
        assert args.output_file == ["explicit.json"]
        paths = utils.output_files_for_formats(
            args.output_file, ("json",), command="review"
        )
        assert paths == ["explicit.json"]
        utils.save_output(paths, {"iteration": iteration}, quiet=True)
        usage_runtime.UsageRuntime(tmp_path / str(iteration)).save_run_summary(
            "usage.json"
        )
    assert json.loads(Path("explicit.json").read_text()) == {"iteration": 1}
    assert json.loads(Path("usage.json").read_text())["project_name"] == "1"
    assert external_service._resolve_run_dir("explicit") == tmp_path / "explicit"
