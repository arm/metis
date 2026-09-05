# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from contextlib import nullcontext
import json
from types import SimpleNamespace
from typing import Annotated

import pytest

from metis.cli import commands
from metis.cli.command_runtime import CommandRuntime
from metis.engine.stages.configuration import BUILTIN_STAGE_CONTRACTS
from metis.engine.stages.configuration import ExecutionConfiguration
from metis.execution_nodes import EmptyNodeConfiguration
from metis.execution_nodes import NodeRegistration
from metis.execution_nodes import NodeResult
from test_execution_graph import _service


type NullableFilename = str | None
type InvalidNullableFilename = str | int | None


@pytest.mark.parametrize(
    ("output_files", "generated", "expected_base"),
    (
        (["generated.json"], True, "configured"),
        (None, False, "configured"),
        ([], False, "configured"),
        (["explicit.sarif"], False, "explicit"),
    ),
)
def test_review_command_uses_result_filename_unless_cli_path_is_explicit(
    monkeypatch, output_files, generated, expected_base
):
    outputs = {
        "filename": "configured",
        "formats": ("sarif", "json"),
        "findings": {"reviews": []},
        "sarif": {"version": "2.1.0", "runs": []},
    }
    args = SimpleNamespace(
        quiet=True,
        triage=False,
        output_file=output_files,
        _metis_generated_output=generated,
    )
    monkeypatch.setattr(commands, "_execute_review", lambda *_args: outputs)
    monkeypatch.setattr(
        commands, "_finalize_review_output", lambda *_args, **_kwargs: None
    )

    commands.run_review_code(
        object(), args, CommandRuntime(command="review_code", command_args=[])
    )

    assert args.output_file == [f"{expected_base}.sarif", f"{expected_base}.json"]


@pytest.mark.parametrize("suffix", (".sarif", ".json"))
@pytest.mark.parametrize("output_files", (None, [], ["explicit.sarif"]))
def test_triage_command_uses_result_filename_unless_cli_path_is_explicit(
    monkeypatch, tmp_path, suffix, output_files
):
    sarif = {"version": "2.1.0", "runs": []}
    source = tmp_path / f"input{suffix}"
    source.write_text(json.dumps(sarif if suffix == ".sarif" else {"reviews": []}))
    args = SimpleNamespace(quiet=True, output_file=output_files)
    saved = []
    monkeypatch.setattr(
        commands,
        "run_triage_action",
        lambda *_args, **_kwargs: {
            "filename": "configured",
            "formats": ("sarif", "json"),
            "sarif": sarif,
        },
    )
    monkeypatch.setattr(
        commands, "save_output", lambda paths, *_args, **_kwargs: saved.extend(paths)
    )

    commands.run_triage(
        object(), str(source), args, CommandRuntime(command="triage", command_args=[])
    )

    base = "explicit" if output_files else "configured"
    assert saved == [f"{base}.sarif", f"{base}.json"]


@pytest.mark.parametrize("stage_name", ("review", "triage", "initialize"))
@pytest.mark.parametrize(
    ("annotation", "valid"),
    (
        (str, True),
        (NullableFilename, True),
        (Annotated[NullableFilename, "filename"], True),
        (int, False),
        (int | None, False),
        (InvalidNullableFilename, False),
    ),
)
def test_optional_aliased_filename_declaration_matches_builtin_output_contract(
    stage_name, annotation, valid
):
    annotations = dict(BUILTIN_STAGE_CONTRACTS[stage_name].required_outputs)
    registration = NodeRegistration(
        "private_result",
        stage_name,
        EmptyNodeConfiguration,
        {},
        {**annotations, "destination": annotation},
        lambda _invocation: NodeResult({}),
    )
    configuration = ExecutionConfiguration.model_validate(
        {
            "inputs": {
                "review_request": {"mode": "code"},
                "sarif": {"version": "2.1.0", "runs": []},
            },
            "stages": {
                stage_name: {
                    "inputs": {"sarif": "$inputs.sarif"}
                    if stage_name == "triage"
                    else {},
                    "outputs": {
                        **{name: f"private_result.{name}" for name in annotations},
                        "filename": "private_result.destination",
                    },
                    "nodes": {"private_result": {}},
                }
            },
        }
    )
    expectation = (
        nullcontext()
        if valid or stage_name == "initialize"
        else pytest.raises(
            ValueError, match="output 'filename' has an incompatible type"
        )
    )
    with expectation:
        service, _ = _service(configuration, extra_registrations=(registration,))
        service.close()
