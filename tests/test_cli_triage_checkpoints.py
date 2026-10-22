# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path

import pytest

from metis.cli.triage_checkpoints import triage_checkpoint_callbacks
from metis.cli import output as cli_output
from metis.cli.output import save_graph_outputs
from metis.generated_artifacts import generated_artifact_paths
from metis.sarif.triage import load_sarif_file


def _execution(filename=None):
    node = {"formats": ["sarif"]}
    if filename is not None:
        node["filename"] = str(filename)
    return {"stages": {"triage": {"nodes": {"result": node}}}}


@pytest.mark.parametrize(
    "explicit,configured,generated,expected",
    [
        ("report.v1.SARIF", "configured", False, "report.v1.checkpoint.sarif"),
        ("generated.json", "configured", True, "configured.checkpoint.sarif"),
        ("report.json", "configured", False, "report.checkpoint.sarif"),
        ("report.v1.json", None, False, "report.v1.checkpoint.sarif"),
        ("report.sarif", "report.checkpoint", False, "report.checkpoint.sarif"),
    ],
)
def test_checkpoint_selection_and_atomic_cadence(
    tmp_path, monkeypatch, explicit, configured, generated, expected, caplog
):
    readonly = tmp_path / "readonly"
    readonly.mkdir()
    monkeypatch.chdir(readonly)
    temporary_file = cli_output.NamedTemporaryFile

    def writable_destination_only(*args, **kwargs):
        if Path(kwargs["dir"]) == readonly:
            raise PermissionError("Working directory is read-only")
        return temporary_file(*args, **kwargs)

    monkeypatch.setattr(cli_output, "NamedTemporaryFile", writable_destination_only)
    output = tmp_path / explicit
    output.write_text("previous output", encoding="utf-8")
    callbacks = triage_checkpoint_callbacks(
        output_files=[str(output)],
        generated_output=generated,
        execution=_execution(tmp_path / configured if configured else None),
        checkpoint_every=2,
        quiet=True,
        generated_bases={},
        codebase_path=str(tmp_path),
    )
    checkpoint = tmp_path / expected
    callback = callbacks["checkpoint_callback"]
    payload = {"version": "2.1.0", "runs": []}

    callback(payload, 1, 3)
    assert not checkpoint.exists()
    callback(payload, 2, 3)

    assert load_sarif_file(checkpoint) == payload
    assert generated_artifact_paths(tmp_path) == {checkpoint.resolve()}
    assert output.read_text(encoding="utf-8") == "previous output"
    callback({**payload, "invalid": float("nan")}, 2, 3)
    assert "Unable to save triage checkpoint" in caplog.text
    assert load_sarif_file(checkpoint) == payload


def test_checkpoint_uses_mapped_external_result_filename(tmp_path):
    execution = _execution()
    execution["stages"]["triage"] = {
        "outputs": {"filename": "external.filename", "formats": "external.formats"},
        "nodes": {
            "external": {"filename": str(tmp_path / "external"), "formats": ["json"]}
        },
    }
    callbacks = triage_checkpoint_callbacks(
        output_files=[str(tmp_path / "generated.json")],
        generated_output=True,
        execution=execution,
        checkpoint_every=1,
        quiet=True,
    )

    callbacks["checkpoint_callback"]({"version": "2.1.0", "runs": []}, 1, 2)

    assert (tmp_path / "external.checkpoint.sarif").is_file()


@pytest.mark.parametrize("collision", ["explicit", "configured"])
def test_checkpoint_collision_fails_before_writing(tmp_path, collision):
    checkpoint = tmp_path / "report.checkpoint.sarif"
    checkpoint.write_text("previous report", encoding="utf-8")
    outputs = [str(tmp_path / "report.sarif")]
    execution = _execution()
    if collision == "configured":
        execution = _execution(tmp_path / "report")
        (tmp_path / "review.sarif").symlink_to(checkpoint)
        execution["stages"]["review"] = {
            "nodes": {
                "result": {
                    "filename": str(tmp_path / "review"),
                    "formats": ["sarif"],
                }
            }
        }
    else:
        outputs.append(str(checkpoint))

    with pytest.raises(ValueError, match="distinct"):
        triage_checkpoint_callbacks(
            output_files=outputs,
            generated_output=collision == "configured",
            execution=execution,
            checkpoint_every=1,
            quiet=True,
        )

    assert checkpoint.read_text(encoding="utf-8") == "previous report"


def test_checkpoint_does_not_reserve_unused_companion_paths(tmp_path):
    outputs = [str(tmp_path / "report.checkpoint.json"), str(tmp_path / "report.sarif")]
    for path in outputs:
        Path(path).write_text("previous output")
    execution = _execution()
    execution["stages"]["triage"]["nodes"]["result"]["formats"] = ["json", "sarif"]
    callbacks = triage_checkpoint_callbacks(
        output_files=outputs,
        generated_output=False,
        execution=execution,
        checkpoint_every=1,
        quiet=True,
    )
    payload = {"version": "2.1.0", "runs": []}
    callbacks["checkpoint_callback"](payload, 1, 1)
    assert all(Path(path).read_text() == "previous output" for path in outputs)
    save_graph_outputs(
        outputs,
        {"triage": {"formats": ("json", "sarif"), "sarif": payload}},
        True,
    )
    assert {path.name for path in tmp_path.iterdir()} == {
        "report.checkpoint.json",
        "report.sarif",
        "report.checkpoint.sarif",
    }


def test_checkpoint_shares_generated_fallback_when_explicit_path_belongs_to_review(
    tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    output_files = [str(tmp_path / "review.json")]
    execution = _execution()
    execution["stages"]["review"] = {"nodes": {"result": {"formats": ["json"]}}}
    generated_bases = {}
    callbacks = triage_checkpoint_callbacks(
        output_files=output_files,
        generated_output=False,
        execution=execution,
        checkpoint_every=1,
        quiet=True,
        generated_bases=generated_bases,
    )
    payload = {"version": "2.1.0", "runs": []}
    callbacks["checkpoint_callback"](payload, 1, 1)
    save_graph_outputs(
        output_files,
        {
            "review": {"formats": ("json",), "findings": {"reviews": []}},
            "triage": {"formats": ("sarif",), "sarif": payload},
        },
        True,
        generated_bases=generated_bases,
    )
    checkpoint = next((tmp_path / "results").glob("*.checkpoint.sarif"))
    report = checkpoint.with_name(
        checkpoint.name.replace(".checkpoint.sarif", ".sarif")
    )
    assert load_sarif_file(checkpoint) == load_sarif_file(report) == payload
    assert (tmp_path / "review.json").is_file()
