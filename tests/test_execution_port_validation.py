# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from copy import deepcopy
from typing import Annotated
from typing import Literal
from typing import NewType
from typing import ParamSpec
from typing import TypedDict
from typing import Unpack
from unittest.mock import Mock

import pytest
from pydantic import AfterValidator
from pydantic import BaseModel
from pydantic import BeforeValidator
from pydantic import TypeAdapter
from pydantic import ValidationError
from pydantic import model_validator

from metis.engine.execution.catalog import NodeCatalog
from metis.engine.execution.compiler import compile_stage
from metis.engine.execution.contracts import annotation_adapter
from metis.engine.execution.graph import StageConfiguration
from metis.engine.execution.runner import _validate_value
from metis.engine.execution.runner import run_stage
from metis.execution_nodes import EmptyNodeConfiguration
from metis.execution_nodes import ExecutionStatus
from metis.execution_nodes import NodeRegistration
from metis.execution_nodes import NodeResult
from test_execution_graph import _node_context


class Payload(BaseModel):
    value: int


class GenericPayload[T](BaseModel):
    value: T


class PayloadFields(TypedDict):
    metadata: Payload
    type: Payload


class RecursivePayload(BaseModel):
    child: "RecursivePayload | None" = None

    @model_validator(mode="after")
    def unchanged(self):
        return self


type OptionalPort[T] = T | None
type RecursivePort[T] = T | list[RecursivePort[T]]

FloatPort = NewType("FloatPort", float)
Parameters = ParamSpec("Parameters")


@pytest.mark.parametrize("direction", ("input", "output"))
@pytest.mark.parametrize(
    "annotation,value",
    (
        (float, 9007199254740993),
        (Annotated[float | None, "nullable"], 1),
        (FloatPort, 1),
        (Literal[True], 1),
        (Literal[1] | None, True),
        (Literal[1], 1.0),
        (Payload | None, {"value": 1}),
        (Payload | int, {"value": 1}),
        (Annotated[Payload, "model"], {"value": 1}),
        (OptionalPort[Payload], {"value": 1}),
        (GenericPayload[int] | None, {"value": 1}),
        (list[Payload], [{"value": 1}]),
        (PayloadFields, {"metadata": {"value": 1}, "type": {"value": 1}}),
    ),
)
def test_node_ports_reject_implicit_scalar_and_model_conversion(
    annotation, value, direction
):
    handler = Mock(
        return_value=NodeResult({"value": value} if direction == "output" else {})
    )
    registration = NodeRegistration(
        "port",
        "initialize",
        EmptyNodeConfiguration,
        {"value": annotation} if direction == "input" else {},
        {"value": annotation} if direction == "output" else {},
        handler,
    )
    stage = StageConfiguration.model_validate({"nodes": {"port": {}}})
    plan = compile_stage(
        NodeCatalog((registration,), ()),
        "initialize",
        stage,
        {},
        {"value": annotation} if direction == "input" else {},
    )
    result = run_stage("initialize", plan, _node_context(), {"value": value})
    assert result.status is ExecutionStatus.ERROR
    assert result.diagnostics[0].code == "execution.node_failed"
    if direction == "input":
        handler.assert_not_called()


@pytest.mark.parametrize(
    "annotation,value",
    (
        (float, 1.5),
        (float | int, 1),
        (int | float, 1.5),
        (Literal[True] | int, 1),
        (Literal[1] | bool, True),
        (Literal[True, 1], 1),
        (Literal[True, 1], True),
        (Payload | None, None),
        (Payload | None, Payload(value=1)),
        (GenericPayload[int] | None, GenericPayload[int](value=1)),
        (Payload | dict[str, int], {"value": 1}),
        (list[Payload], [Payload(value=1)]),
        (PayloadFields, {"metadata": Payload(value=1), "type": Payload(value=1)}),
        (RecursivePort[float], [1.0, [2.0]]),
    ),
)
def test_valid_port_values_and_union_branches_keep_their_types(annotation, value):
    actual = _validate_value(annotation, value)
    assert type(actual) is type(value)
    assert actual == value
    if isinstance(value, BaseModel):
        assert actual is value


def test_model_guards_preserve_metadata_recursive_definitions_and_cached_schemas():
    before = deepcopy(RecursivePayload.__pydantic_core_schema__)
    checked = []

    def remember(value):
        checked.append(value)
        return value

    annotation = Annotated[
        list[Annotated[RecursivePayload | None, BeforeValidator(remember)]],
        AfterValidator(remember),
    ]
    value = RecursivePayload(child=RecursivePayload())
    assert _validate_value(annotation, [value, None]) == [value, None]
    assert checked == [value, None, [value, None]]
    with pytest.raises(ValidationError):
        _validate_value(annotation, [{}])
    with pytest.raises(ValidationError):
        _validate_value(RecursivePort[float], [1])
    assert RecursivePayload.__pydantic_core_schema__ == before
    # Normal Pydantic construction remains available outside the port boundary.
    assert (
        TypeAdapter(RecursivePayload | None).validate_python({}, strict=True)
        == RecursivePayload()
    )


@pytest.mark.parametrize(
    "annotation",
    (
        Parameters.args,
        Parameters.kwargs,
        list[Parameters.args],
        dict[str, Parameters.kwargs],
    ),
)
def test_unresolved_parameter_parts_are_not_concrete_port_annotations(annotation):
    with pytest.raises(TypeError, match="Expected a concrete port type"):
        annotation_adapter(annotation)


def test_model_metadata_validators_run_without_allowing_mapping_construction():
    checked = []

    class ValidatedPayload(BaseModel):
        value: int

        @model_validator(mode="wrap")
        @classmethod
        def remember(cls, value, handler):
            checked.append("model")
            return handler(value)

    def before(value):
        checked.append("before")
        return value

    def after(value):
        checked.append("after")
        return value

    value = ValidatedPayload(value=1)
    checked.clear()
    annotation = (
        Annotated[ValidatedPayload, BeforeValidator(before), AfterValidator(after)]
        | None
    )
    assert _validate_value(annotation, value) is value
    assert checked == ["before", "model", "after"]
    checked.clear()
    with pytest.raises(ValidationError):
        _validate_value(annotation, {"value": 1})
    assert checked == []


type PackedPort[*Items] = tuple[*Items]
type HeadPackedPort[Head, *Tail] = tuple[Head, *Tail]
type TailPackedPort[*Prefix, Last] = tuple[*Prefix, Last]
type NestedPackedPort[T] = list[PackedPort[T, str]]


@pytest.mark.parametrize(
    "annotation,valid,invalid",
    (
        (PackedPort[int, str], (1, "ok"), ((object(),), (1,), (1, "ok", 2), (1, 2))),
        (
            HeadPackedPort[int, str, bytes],
            (1, "ok", b"ok"),
            ((1, object()), (1, "ok"), (1, "ok", "bytes")),
        ),
        (
            TailPackedPort[int, str, bytes],
            (1, "ok", b"ok"),
            ((1, "ok"), (1, "ok", "bytes")),
        ),
        (tuple[Unpack[tuple[int, str]]], (1, "ok"), ((object(),), (1, 2))),
        (tuple[*tuple[int, str]], (1, "ok"), (((1, "ok"),), (1, 2))),
        (tuple[int, *tuple[str, bytes]], (1, "ok", b"ok"), ((1, ("ok", b"ok")),)),
        (NestedPackedPort[int], [(1, "ok")], ([(1,)], [(1, 2)])),
        (dict[str, PackedPort[int, str]], {"x": (1, "ok")}, ({"x": (1,)},)),
        (PackedPort[()], (), ((1,), (object(),))),
        (tuple[Unpack[tuple[()]]], (), ((1,),)),
        (tuple[*tuple[()]], (), ((1,),)),
        (tuple[Unpack[tuple[int, ...]]], (), (("bad",),)),
        (
            PackedPort[float, Payload],
            (1.0, Payload(value=1)),
            ((1, Payload(value=1)), (1.0, {"value": 1})),
        ),
    ),
)
def test_concrete_tuple_unpacks_enforce_flat_lengths_and_item_types(
    annotation, valid, invalid
):
    registration = NodeRegistration(
        "packed",
        "custom",
        EmptyNodeConfiguration,
        {},
        {"value": annotation},
        lambda invocation: NodeResult({}),
    )
    assert registration.outputs["value"] is annotation
    assert _validate_value(annotation, valid) == valid
    for value in invalid:
        with pytest.raises(ValidationError):
            _validate_value(annotation, value)


def test_tuple_unpack_normalization_preserves_annotation_validators():
    seen = []

    def remember(value):
        seen.append(value)
        return value

    annotation = Annotated[PackedPort[int, str], AfterValidator(remember)] | None
    assert _validate_value(annotation, (1, "ok")) == (1, "ok")
    assert seen == [(1, "ok")]
    assert _validate_value(annotation, None) is None
    with pytest.raises(ValidationError):
        _validate_value(annotation, (1,))
    assert seen == [(1, "ok")]


type RecursivePackedPort[*Items] = (
    PackedPort[*Items] | list[RecursivePackedPort[*Items]]
)


@pytest.mark.parametrize(
    "annotation",
    (RecursivePackedPort[int, str], tuple[int, *tuple[str, ...]]),
)
def test_unsupported_tuple_unpack_shapes_fail_before_execution(annotation):
    with pytest.raises(TypeError, match="tuple unpack.*unsupported"):
        annotation_adapter(annotation)


@pytest.mark.parametrize(
    "annotation", (Unpack[tuple[int, str]], list[Unpack[tuple[int, str]]])
)
def test_tuple_unpack_cannot_be_used_as_a_standalone_item_type(annotation):
    with pytest.raises(TypeError, match="must appear inside a tuple"):
        annotation_adapter(annotation)
