# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from typing import Literal
from typing import NewType

import pytest

from metis.engine.execution.compiler import _annotations_compatible
from metis.engine.execution.graph import StageConfiguration
from metis.engine.execution.runner import run_stage
from metis.execution_nodes import EmptyNodeConfiguration
from metis.execution_nodes import ExecutionStatus
from metis.execution_nodes import NodeRegistration
from metis.execution_nodes import NodeResult
from test_execution_graph import _compile
from test_execution_graph import _node_context


type _NativeA = int | list[_NativeA]
type _NativeB = int | list[_NativeB]
type _NativeWrong = str | list[_NativeWrong]
type _GenericA[T] = list[_GenericA[T]] | T
type _GenericB[T] = list[_GenericB[T]] | T
type _MutualA = int | dict[str, _MutualAItems]
type _MutualAItems = list[_MutualA]
type _MutualB = int | dict[str, _MutualBItems]
type _MutualBItems = list[_MutualB]
type _PairA = tuple[_PairA, int] | None
type _PairB = tuple[_PairB, str] | None
type _TupleTree = int | tuple[_TupleTree, ...]
type _SequenceTree = int | Sequence[_SequenceTree]
type _LiteralTree = Literal[1] | list[_LiteralTree]
type _SelfUnion = _SelfUnion | int
_UserId = NewType("_UserId", int)
type _IdTree = _UserId | list[_IdTree]


@pytest.mark.parametrize(
    "source,target,expected",
    (
        (_NativeA, _NativeB, True),
        (_NativeA, _NativeWrong, False),
        (_GenericA[int], _GenericB[int], True),
        (_GenericA[int], _GenericB[str], False),
        (_NativeA, _GenericB[int], True),
        (_MutualA, _MutualB, True),
        (_PairA, _PairB, False),
        (_TupleTree, _SequenceTree, True),
        (_SequenceTree, _TupleTree, False),
        (_LiteralTree, _NativeB, True),
        (_NativeA, _LiteralTree, False),
        (_IdTree, _NativeB, True),
        (_NativeA, _IdTree, False),
        (_GenericA[int], _GenericB[int] | None, True),
        (_GenericA[int] | None, _GenericB[int], False),
        (_SelfUnion, int, True),
        (int, _SelfUnion, True),
    ),
)
def test_recursive_annotation_compatibility(source, target, expected):
    assert _annotations_compatible(source, target) is expected


def test_recursive_ports_compile_independently():
    barrier = Barrier(4)
    value = [1, [2]]
    cases = (
        (_NativeA, _NativeB, True),
        (_NativeA, _NativeWrong, False),
        (_GenericA[int], _GenericB[int], True),
        (_GenericA[int], _GenericB[str], False),
    )

    def compile_case(case):
        source, target, compatible = case
        registrations = (
            NodeRegistration(
                "source",
                "initialize",
                EmptyNodeConfiguration,
                {},
                {"value": source},
                lambda _: NodeResult({"value": value}),
            ),
            NodeRegistration(
                "consumer",
                "initialize",
                EmptyNodeConfiguration,
                {"value": target},
                {"value": target},
                lambda invocation: NodeResult(dict(invocation.inputs)),
            ),
        )
        stage = StageConfiguration.model_validate(
            {
                "nodes": {
                    "source": {},
                    "consumer": {"inputs": {"value": "source.value"}},
                },
                "outputs": {"value": "consumer.value"},
            }
        )
        barrier.wait(timeout=5)
        if compatible:
            result = run_stage(
                "initialize", _compile(registrations, stage), _node_context(), {}
            )
            assert result.status is ExecutionStatus.OK
            assert result.outputs["value"] == value
        else:
            with pytest.raises(ValueError, match="not compatible"):
                _compile(registrations, stage)

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(compile_case, case) for case in cases]
        for future in futures:
            future.result(timeout=10)
