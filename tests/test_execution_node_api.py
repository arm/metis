# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from collections.abc import Callable
from typing import Protocol
from typing import ForwardRef

import pytest

import metis.execution_nodes as execution_nodes
from metis.engine.execution.compiler import _annotations_compatible


def test_execution_node_public_api_is_explicit() -> None:
    assert set(execution_nodes.__all__) == {
        "CapabilityRequirement",
        "CodeGraph",
        "CodeGraphProvider",
        "CodeGraphProviderContext",
        "CodeGraphReference",
        "CodeGraphResult",
        "EmptyNodeConfiguration",
        "ExecutionDiagnostic",
        "ExecutionStatus",
        "FinalReviewRun",
        "JsonPromptRequest",
        "NodeCallbacks",
        "NodeCodeGraphs",
        "NodeContext",
        "NodeInvocation",
        "NodeJobs",
        "NodeRegistration",
        "NodeResult",
        "NodeRuntime",
        "PatchReviewResult",
        "ReviewCommand",
        "ReviewResult",
        "ReviewRun",
        "ReviewStatus",
        "SarifFinding",
        "SarifPayload",
        "StandardReviewResult",
        "TriageAdjudicator",
        "TriageClassifier",
        "TriageDecision",
        "TriageRun",
    }


type _MalformedPortAlias[T] = dict[T, 123]
type _GenericPortAlias[T] = list[T]
type _RecursivePortAlias[T] = T | list[_RecursivePortAlias[T]]
type _CallablePortAlias[**P, R] = Callable[P, R]
type _VariadicCallablePortAlias[*Ts] = Callable[[*Ts], None]


@pytest.mark.parametrize(
    "annotation",
    (
        123,
        object(),
        list[123],
        dict[str, list[123]],
        list[...],
        dict[str, ...],
        tuple[...],
        list[[int]],
        dict[str, [int]],
        tuple[[int]],
        _MalformedPortAlias[str],
        _GenericPortAlias[[int]],
        _CallablePortAlias[[[int]], str],
        _VariadicCallablePortAlias[[int]],
        tuple[_GenericPortAlias.__type_params__[0], _GenericPortAlias[int]],
    ),
)
def test_execution_node_rejects_non_type_port_annotations(annotation):
    with pytest.raises(TypeError, match="unsupported annotation"):
        execution_nodes.NodeRegistration(
            "invalid",
            "stage",
            execution_nodes.EmptyNodeConfiguration,
            {},
            {"value": annotation},
            lambda _invocation: execution_nodes.NodeResult({}),
        )


@pytest.mark.parametrize(
    "annotation",
    (
        Callable[..., int],
        Callable[[int, str], str],
        tuple[int, ...],
        _GenericPortAlias[int],
        _RecursivePortAlias[int],
        _CallablePortAlias[[int, str], str],
        _CallablePortAlias[..., int],
        _VariadicCallablePortAlias[int, str],
    ),
)
def test_execution_node_accepts_concrete_generic_port_annotations(annotation):
    registration = execution_nodes.NodeRegistration(
        "valid",
        "stage",
        execution_nodes.EmptyNodeConfiguration,
        {},
        {"value": annotation},
        lambda _invocation: execution_nodes.NodeResult({}),
    )
    assert registration.outputs["value"] is annotation


def test_execution_node_preserves_one_shot_required_port_names():
    registration = execution_nodes.NodeRegistration(
        "valid",
        "stage",
        execution_nodes.EmptyNodeConfiguration,
        {"value": int | None},
        {},
        lambda _invocation: execution_nodes.NodeResult({}),
        required_when_bound=iter(["value"]),
    )
    assert registration.required_when_bound == frozenset({"value"})


def test_execution_node_rejects_protocol_without_runtime_checks():
    class UncheckedProtocol(Protocol):
        def value(self) -> int: ...

    with pytest.raises(TypeError, match="unsupported annotation"):
        execution_nodes.NodeRegistration(
            "invalid",
            "stage",
            execution_nodes.EmptyNodeConfiguration,
            {"value": UncheckedProtocol},
            {},
            lambda _invocation: execution_nodes.NodeResult({}),
        )


@pytest.mark.parametrize(
    "annotation", ("MissingPortType", list[ForwardRef("MissingPortType")])
)
def test_execution_node_rejects_unresolved_forward_types_before_execution(annotation):
    with pytest.raises(TypeError, match="unsupported annotation"):
        execution_nodes.NodeRegistration(
            "invalid",
            "stage",
            execution_nodes.EmptyNodeConfiguration,
            {"value": annotation},
            {},
            lambda _invocation: execution_nodes.NodeResult({}),
        )


@pytest.mark.parametrize(
    "changes,error_type",
    (
        ({"name": 1}, ValueError),
        ({"stage": None}, ValueError),
        ({"inputs": []}, TypeError),
        ({"outputs": None}, TypeError),
        ({"inputs": {1: str}}, ValueError),
        ({"capabilities": []}, TypeError),
        (
            {"capabilities": {1: execution_nodes.CapabilityRequirement.OPTIONAL}},
            ValueError,
        ),
        ({"required_when_bound": "value"}, TypeError),
    ),
)
def test_execution_node_rejects_malformed_registration_fields(changes, error_type):
    arguments = {
        "name": "valid",
        "stage": "stage",
        "configuration": execution_nodes.EmptyNodeConfiguration,
        "inputs": {},
        "outputs": {},
        "execute": lambda _invocation: execution_nodes.NodeResult({}),
    }
    with pytest.raises(error_type):
        execution_nodes.NodeRegistration(**(arguments | changes))


type _ReorderedPortAlias[T, U] = tuple[U, T]
type _UnusedPortAlias[T, U] = U | None
type _UnionRecursivePortAlias[T] = T | _UnionRecursivePortAlias[T] | None


@pytest.mark.parametrize(
    "alias,underlying",
    (
        (_GenericPortAlias[int], list[int]),
        (_RecursivePortAlias[int], int | list[_RecursivePortAlias[int]]),
        (_CallablePortAlias[[int, str], str], Callable[[int, str], str]),
        (_VariadicCallablePortAlias[int, str], Callable[[int, str], None]),
        (_ReorderedPortAlias[int, str], tuple[str, int]),
        (_UnusedPortAlias[int, str], str | None),
        (_UnionRecursivePortAlias[int], int | None),
    ),
)
def test_concrete_generic_alias_preserves_parameter_bindings(alias, underlying):
    assert _annotations_compatible(alias, underlying)
    assert _annotations_compatible(underlying, alias)
