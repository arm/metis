# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from threading import Event
from typing import ForwardRef
from typing import TypeVar

import pytest
from pydantic import BaseModel

import metis.execution_stages as execution_stages
from metis.engine.stages.catalog import StageCatalog
from metis.engine.stages.configuration import ExecutionConfiguration


class _BuiltinCollisionEntryPoint:
    name = "review"


def test_execution_stage_public_api_is_explicit() -> None:
    assert set(execution_stages.__all__) == {
        "StageContract",
        "StageRegistration",
    }


def test_execution_stage_contract_rejects_invalid_ports() -> None:
    with pytest.raises(ValueError, match="invalid port 'bad-port'"):
        execution_stages.StageContract({"bad-port": str})


def test_installed_execution_stage_cannot_shadow_a_builtin() -> None:
    with pytest.raises(ValueError, match="conflicts with a built-in stage"):
        StageCatalog(("review",), (_BuiltinCollisionEntryPoint(),))


@pytest.mark.parametrize(
    ("node_name", "outputs"),
    (
        ("result", ()),
        ("result", {"filename": "result.filename"}),
        ("private_result", {"filename": "private_result.filename"}),
        ("private_result", {"filename": "private_result.destination"}),
        ("private_result", {"filename": "private_result"}),
        ("filename", ("filename",)),
    ),
)
def test_filename_follows_the_stage_output_producer(node_name, outputs):
    configuration = ExecutionConfiguration.model_validate(
        {
            "inputs": {"review_request": {"mode": "code"}},
            "stages": {
                "review": {
                    "outputs": outputs,
                    "nodes": {
                        node_name: {"formats": ["json"], "filename": "results/review"}
                    },
                }
            },
        }
    )

    assert configuration.stages.review.nodes[node_name].filename == "results/review"


@pytest.mark.parametrize(
    ("node_name", "outputs"),
    (
        ("private_result", ()),
        ("private_result", {"filename": "other.filename"}),
        ("result", {"filename": "private_result.filename"}),
        ("private_result", {"formats": "private_result.formats"}),
        ("private_result", ("private_result",)),
    ),
)
def test_filename_rejects_an_unpublished_or_different_producer(node_name, outputs):
    with pytest.raises(ValueError, match="producer of its filename output"):
        ExecutionConfiguration.model_validate(
            {
                "inputs": {"review_request": {"mode": "code"}},
                "stages": {
                    "review": {
                        "outputs": outputs,
                        "nodes": {
                            node_name: {
                                "formats": ["json"],
                                "filename": "results/review",
                            }
                        },
                    }
                },
            }
        )


def test_filename_rejects_multiple_configured_producers():
    with pytest.raises(ValueError, match="configures multiple filenames"):
        ExecutionConfiguration.model_validate(
            {
                "inputs": {"review_request": {"mode": "code"}},
                "stages": {
                    "review": {
                        "outputs": {"filename": "private_result.filename"},
                        "nodes": {
                            "private_result": {
                                "formats": ["json"],
                                "filename": "results/private",
                            },
                            "result": {
                                "formats": ["json"],
                                "filename": "results/review",
                            },
                        },
                    }
                },
            }
        )


@pytest.mark.parametrize(
    "factory",
    (
        lambda: execution_stages.StageContract({1: str}),
        lambda: execution_stages.StageContract({}, {None: str}),
        lambda: execution_stages.StageRegistration(
            1, execution_stages.StageContract({})
        ),
        lambda: execution_stages.StageRegistration(
            None, execution_stages.StageContract({})
        ),
    ),
)
def test_execution_stage_names_reject_non_strings(factory):
    with pytest.raises(ValueError, match="[Ii]nvalid"):
        factory()


type _OptionalStagePort[T] = T | None


class _StagePayload[T](BaseModel):
    value: T


@pytest.mark.parametrize("direction", ("inputs", "required_outputs"))
@pytest.mark.parametrize(
    "annotation",
    (
        TypeVar("Unbound") | None,
        ForwardRef("UnknownPort") | None,
        _OptionalStagePort,
        123,
    ),
)
def test_stage_contract_rejects_unsupported_annotations_at_construction(
    direction, annotation
):
    with pytest.raises(TypeError, match="port 'value'.*unsupported annotation"):
        execution_stages.StageContract(
            **({"inputs": {}} | {direction: {"value": annotation}})
        )


@pytest.mark.parametrize(
    "annotation",
    (
        int | None,
        _OptionalStagePort[_StagePayload[int]],
        _StagePayload[list[str]],
        Event,
    ),
)
def test_stage_contract_preserves_supported_concrete_annotations(annotation):
    contract = execution_stages.StageContract(
        {"value": annotation}, {"result": annotation}
    )
    assert contract.inputs["value"] is annotation
    assert contract.required_outputs["result"] is annotation
