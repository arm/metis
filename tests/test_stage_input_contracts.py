# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from typing import Annotated
from unittest.mock import Mock

import pytest
from pydantic import AfterValidator

from metis.engine.stages.catalog import StageCatalog
from metis.engine.stages.configuration import ExecutionConfiguration
from metis.execution_nodes import EmptyNodeConfiguration
from metis.execution_nodes import ExecutionStatus
from metis.execution_nodes import ExecutionDiagnostic
from metis.execution_nodes import NodeRegistration
from metis.execution_nodes import NodeResult
from metis.execution_nodes import ReviewCommand
from metis.execution_stages import StageContract
from metis.execution_stages import StageRegistration
from test_execution_graph import _service


type _OptionalPort[T] = T | None


def _input_service(monkeypatch, annotation, source, value, handler):
    registration = StageRegistration("external", StageContract({"value": annotation}))
    monkeypatch.setattr(StageCatalog, "resolve", lambda self, name: registration)
    stage = {"outputs": {"seen": "observe.seen"}, "nodes": {"observe": {}}}
    stages = {"external": stage}
    if source == "root":
        stage["inputs"] = {"value": "$inputs.review_request"}
    elif source == "stage":
        stage["inputs"] = {"value": "initialize.value"}
        stages["initialize"] = {
            "outputs": {"value": "produce.value"},
            "nodes": {"produce": {}},
        }
    configuration = ExecutionConfiguration.model_validate(
        {"inputs": {"review_request": value}, "stages": stages}
    )
    return _service(
        configuration,
        extra_registrations=(
            NodeRegistration(
                "observe",
                "external",
                EmptyNodeConfiguration,
                {"value": ReviewCommand | None},
                {"seen": bool},
                handler,
            ),
            NodeRegistration(
                "produce",
                "initialize",
                EmptyNodeConfiguration,
                {},
                {"value": ReviewCommand},
                lambda invocation: NodeResult({"value": value}),
            ),
        ),
    )[0]


@pytest.mark.parametrize(
    "source,valid",
    (
        ("root", False),
        ("root", True),
        ("stage", False),
        ("stage", True),
        ("unset", False),
    ),
)
def test_stage_input_constraints_apply_before_node_execution(
    monkeypatch, source, valid
):
    def requires_target(command):
        if command is None or command.target != "expected":
            raise ValueError("stage requires target expected")
        return command

    annotation = Annotated[ReviewCommand | None, AfterValidator(requires_target)]
    value = (
        ReviewCommand(mode="file", target="expected")
        if valid
        else ReviewCommand(mode="code")
    )
    handler = Mock(return_value=NodeResult({"seen": True}))
    service = _input_service(monkeypatch, annotation, source, value, handler)
    try:
        result = service.execute_graph()
    finally:
        service.close()
    if valid:
        assert result.status is ExecutionStatus.OK
        assert handler.call_args.args[0].inputs["value"] == value
    else:
        assert result.status is ExecutionStatus.ERROR
        assert result.diagnostics[0].code == "execution.stage_input_invalid"
        assert "stage requires target expected" in result.diagnostics[0].message
        handler.assert_not_called()


@pytest.mark.parametrize(
    "source,present", (("unset", False), ("root", False), ("root", True))
)
def test_nullable_generic_stage_input_accepts_absent_null_and_present_values(
    monkeypatch, source, present
):
    value = ReviewCommand(mode="code") if present else None
    handler = Mock(return_value=NodeResult({"seen": True}))
    service = _input_service(
        monkeypatch, _OptionalPort[ReviewCommand], source, value, handler
    )
    try:
        result = service.execute_graph()
    finally:
        service.close()
    assert result.status is ExecutionStatus.OK
    assert handler.call_args.args[0].inputs["value"] == value


@pytest.mark.parametrize("value", (-1, 1))
@pytest.mark.parametrize(
    "node_status", (ExecutionStatus.OK, ExecutionStatus.INCONCLUSIVE)
)
def test_stage_output_constraints_preserve_valid_outputs_and_diagnostics(
    monkeypatch, value, node_status
):
    validated = []

    def positive(value):
        validated.append(value)
        if value <= 0:
            raise ValueError("stage output must be positive")
        return value

    annotation = Annotated[int, AfterValidator(positive)]
    registration = StageRegistration(
        "external", StageContract({}, {"total": annotation, "independent": annotation})
    )
    monkeypatch.setattr(StageCatalog, "resolve", lambda self, name: registration)
    outputs = {"total": value, "independent": 7, "extra": 3}
    configuration = ExecutionConfiguration.model_validate(
        {
            "stages": {
                "external": {
                    "outputs": {name: f"produce.{name}" for name in outputs},
                    "nodes": {"produce": {}},
                }
            }
        }
    )
    warning = ExecutionDiagnostic("fixture.note", "original diagnostic", "warning")
    node = NodeRegistration(
        "produce",
        "external",
        EmptyNodeConfiguration,
        {},
        {name: int for name in outputs},
        lambda invocation: NodeResult(outputs, node_status, (warning,)),
    )
    service, _ = _service(configuration, extra_registrations=(node,))
    try:
        result = service.execute_graph()
    finally:
        service.close()
    assert validated == [value, 7]
    assert result.diagnostics[0] == warning
    if value > 0:
        assert result.status is node_status
        assert result.outputs["external"] == outputs
        assert result.diagnostics == (warning,)
    else:
        assert result.status is ExecutionStatus.ERROR
        assert result.outputs["external"] == {"independent": 7, "extra": 3}
        assert result.diagnostics[1].code == "execution.stage_output_invalid"
        assert "stage output must be positive" in result.diagnostics[1].message


def test_close_during_stage_output_validation_cannot_publish_success(monkeypatch):
    from concurrent.futures import CancelledError, ThreadPoolExecutor
    from threading import Event

    entered = Event()
    release = Event()

    def wait_for_close(value):
        entered.set()
        assert release.wait(4)
        return value

    registration = StageRegistration(
        "external",
        StageContract({}, {"value": Annotated[int, AfterValidator(wait_for_close)]}),
    )
    monkeypatch.setattr(StageCatalog, "resolve", lambda self, name: registration)
    configuration = ExecutionConfiguration.model_validate(
        {
            "stages": {
                "external": {
                    "outputs": {"value": "produce.value"},
                    "nodes": {"produce": {}},
                }
            }
        }
    )
    node = NodeRegistration(
        "produce",
        "external",
        EmptyNodeConfiguration,
        {},
        {"value": int},
        lambda invocation: NodeResult({"value": 1}),
    )
    service, _ = _service(configuration, extra_registrations=(node,))
    try:
        with ThreadPoolExecutor(max_workers=2) as callers:
            result = callers.submit(service.execute_graph)
            try:
                assert entered.wait(2)
                closed = callers.submit(service.close)
                with service._condition:
                    assert service._condition.wait_for(lambda: service._closed, 2)
                release.set()
                with pytest.raises(CancelledError):
                    result.result(2)
                closed.result(2)
            finally:
                release.set()
    finally:
        service.close()
