# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Mapping
from collections.abc import Sequence
from dataclasses import dataclass
from copy import deepcopy
from types import MappingProxyType
from typing import Any
from typing import Literal
from typing import NewType
from typing import Tuple
from typing import get_args
from typing import get_origin

from pydantic import BaseModel

from .catalog import NodeCatalog
from .contracts import CapabilityRequirement
from .contracts import NodeRegistration
from .contracts import StageName
from .contracts import annotation_allows_none
from .contracts import annotation_adapter
from .contracts import annotation_members
from .contracts import collection_item_annotation
from .graph import ConfiguredNode
from .graph import InputBinding
from .graph import StageConfiguration
from .graph import _topological_order


@dataclass(frozen=True, slots=True)
class _PlannedNode:
    name: str
    definition: ConfiguredNode
    registration: NodeRegistration
    configuration: BaseModel
    configuration_values: Mapping[str, object]
    input_bindings: Mapping[str, InputBinding]
    dependencies: frozenset[str]
    required_dependencies: frozenset[str]
    capabilities: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class StagePlan:
    nodes: tuple[_PlannedNode, ...]
    output_bindings: Mapping[str, str]
    output_annotations: Mapping[str, Any]


def compile_stage(
    catalog: NodeCatalog,
    stage_name: StageName,
    stage: StageConfiguration,
    configuration: Mapping[str, Mapping[str, object]],
    initial_inputs: Mapping[str, Any],
    capabilities: Mapping[str, object] | None = None,
) -> StagePlan:
    for input_name, annotation in initial_inputs.items():
        try:
            annotation_adapter(annotation)
        except Exception as exc:
            raise TypeError(
                f"Execution stage {stage_name!r} input {input_name!r} has an "
                f"unsupported annotation: {annotation!r}"
            ) from exc
    available_capabilities = capabilities or MappingProxyType({})
    unknown_configuration = set(configuration) - set(stage.nodes)
    if unknown_configuration:
        names = ", ".join(sorted(unknown_configuration))
        raise ValueError(
            f"Configuration provided for unavailable {stage_name} nodes: {names}"
        )
    registrations = {name: catalog.resolve(stage_name, name) for name in stage.nodes}
    planned: dict[str, _PlannedNode] = {}
    predecessors: dict[str, set[str]] = {}
    for name, definition in stage.nodes.items():
        registration = registrations[name]
        configured_capabilities = set(definition.capabilities)
        declared_capabilities = set(registration.capabilities)
        unsupported_capabilities = configured_capabilities - declared_capabilities
        if unsupported_capabilities:
            names = ", ".join(sorted(unsupported_capabilities))
            raise ValueError(
                f"Execution node {stage_name}.{name} does not declare "
                f"capabilities: {names}"
            )
        missing_capabilities = {
            capability
            for capability, requirement in registration.capabilities.items()
            if requirement is CapabilityRequirement.REQUIRED
            and capability not in configured_capabilities
        }
        if missing_capabilities:
            names = ", ".join(sorted(missing_capabilities))
            raise ValueError(
                f"Execution node {stage_name}.{name} requires capabilities: {names}"
            )
        unavailable_capabilities = configured_capabilities - set(available_capabilities)
        if unavailable_capabilities:
            names = ", ".join(sorted(unavailable_capabilities))
            raise ValueError(
                f"Execution node {stage_name}.{name} requested unavailable "
                f"capabilities: {names}"
            )
        configuration_values = deepcopy(dict(configuration.get(name, {})))
        node_configuration = registration.configuration.model_validate(
            deepcopy(configuration_values)
        )
        unknown_inputs = set(definition.inputs) - set(registration.inputs)
        if unknown_inputs:
            ports = ", ".join(sorted(unknown_inputs))
            raise ValueError(
                f"Execution node {stage_name}.{name} has unknown inputs: {ports}"
            )
        input_bindings = _infer_input_bindings(
            stage_name,
            name,
            definition,
            registrations,
            initial_inputs,
        )
        missing_inputs = {
            input_name
            for input_name, annotation in registration.inputs.items()
            if input_name not in input_bindings
            and (
                input_name not in initial_inputs
                or initial_inputs[input_name] is type(None)
            )
            and not annotation_allows_none(annotation)
        }
        if missing_inputs:
            ports = ", ".join(sorted(missing_inputs))
            raise ValueError(
                f"Execution node {stage_name}.{name} has unbound inputs: {ports}"
            )
        for input_name in (set(registration.inputs) - set(input_bindings)) & set(
            initial_inputs
        ):
            _validate_input_annotation(
                stage_name,
                name,
                input_name,
                initial_inputs[input_name],
                registration.inputs[input_name],
            )
        dependencies = set(definition.depends_on)
        required_dependencies = set(definition.depends_on)
        for input_name, binding in input_bindings.items():
            collection = isinstance(binding, tuple)
            if (
                collection
                and collection_item_annotation(registration.inputs[input_name]) is None
            ):
                raise ValueError(
                    f"Execution node {stage_name}.{name} input {input_name!r} "
                    "does not accept multiple sources"
                )
            for source in _sources(binding):
                if source.startswith("$inputs."):
                    stage_input = source.removeprefix("$inputs.")
                    if stage_input not in initial_inputs:
                        raise ValueError(
                            f"Execution node {stage_name}.{name} references "
                            f"unknown stage input {stage_input!r}"
                        )
                    _validate_input_annotation(
                        stage_name,
                        name,
                        input_name,
                        initial_inputs[stage_input],
                        registration.inputs[input_name],
                        collection=collection,
                    )
                    continue
                producer_name, _, _output_name = source.partition(".")
                dependencies.add(producer_name)
                if input_name in registration.required_when_bound or (
                    not collection
                    and not annotation_allows_none(registration.inputs[input_name])
                ):
                    required_dependencies.add(producer_name)
        planned[name] = _PlannedNode(
            name,
            definition,
            registration,
            node_configuration,
            MappingProxyType(configuration_values),
            MappingProxyType(input_bindings),
            frozenset(dependencies),
            frozenset(required_dependencies),
            MappingProxyType(
                {
                    capability: available_capabilities[capability]
                    for capability in sorted(configured_capabilities)
                }
            ),
        )
        predecessors[name] = dependencies
    for name, dependencies in predecessors.items():
        missing = dependencies - set(stage.nodes)
        if missing:
            names = ", ".join(sorted(missing))
            raise ValueError(
                f"Execution node {stage_name}.{name} depends on unavailable "
                f"nodes: {names}"
            )
        for input_name, binding in planned[name].input_bindings.items():
            for source in _sources(binding):
                if source.startswith("$inputs."):
                    continue
                _validate_input_annotation(
                    stage_name,
                    name,
                    input_name,
                    _reference_annotation(stage_name, source, registrations),
                    registrations[name].inputs[input_name],
                    collection=isinstance(binding, tuple),
                    source_name=source,
                )
    output_bindings = (
        dict(stage.outputs)
        if isinstance(stage.outputs, dict)
        else {name: name for name in stage.outputs}
    )
    if not output_bindings and "result" in registrations:
        result_dependants = [
            name
            for name, dependencies in predecessors.items()
            if "result" in dependencies
        ]
        if result_dependants:
            names = ", ".join(result_dependants)
            raise ValueError(
                f"Execution stage {stage_name!r} terminal result has "
                f"dependants: {names}"
            )
        output_bindings = {
            name: f"result.{name}" for name in registrations["result"].outputs
        }
    output_annotations = {
        name: _reference_annotation(stage_name, source, registrations)
        for name, source in output_bindings.items()
    }
    order = _topological_order(predecessors, tuple(stage.nodes))
    return StagePlan(
        tuple(planned[name] for name in order),
        MappingProxyType(output_bindings),
        MappingProxyType(output_annotations),
    )


def _infer_input_bindings(
    stage_name: StageName,
    node_name: str,
    definition: ConfiguredNode,
    registrations: Mapping[str, NodeRegistration],
    initial_inputs: Mapping[str, Any],
) -> dict[str, InputBinding]:
    bindings = dict(definition.inputs)
    registration = registrations[node_name]
    for input_name, annotation in registration.inputs.items():
        if input_name in bindings or input_name in initial_inputs:
            continue
        item = collection_item_annotation(annotation)
        collection = item is not None
        target = item if collection else annotation
        compatible = tuple(
            f"{producer_name}.{output_name}"
            for producer_name, producer in registrations.items()
            if producer_name not in {node_name, "result"}
            for output_name, output_annotation in producer.outputs.items()
            if _annotations_compatible(output_annotation, target)
        )
        if collection and compatible:
            bindings[input_name] = compatible
        elif len(compatible) == 1:
            bindings[input_name] = compatible[0]
        elif len(compatible) > 1:
            sources = ", ".join(compatible)
            raise ValueError(
                f"Execution node {stage_name}.{node_name} input {input_name!r} "
                f"matches multiple outputs: {sources}"
            )
    return bindings


def _reference_annotation(
    stage_name: StageName,
    source: str,
    registrations: Mapping[str, NodeRegistration],
) -> Any:
    producer_name, separator, output_name = source.partition(".")
    producer = registrations.get(producer_name)
    if producer is None:
        raise ValueError(
            f"Execution stage {stage_name!r} references unavailable node "
            f"{producer_name!r}"
        )
    if separator:
        if output_name not in producer.outputs:
            raise ValueError(
                f"Execution stage {stage_name!r} references unknown output {source!r}"
            )
        return producer.outputs[output_name]
    if len(producer.outputs) != 1:
        raise ValueError(
            f"Execution stage {stage_name!r} must select one of "
            f"{producer_name!r}'s outputs"
        )
    return next(iter(producer.outputs.values()))


def _validate_input_annotation(
    stage_name: StageName,
    node_name: str,
    input_name: str,
    source: Any,
    target: Any,
    *,
    collection: bool = False,
    source_name: str | None = None,
) -> None:
    if collection:
        item = collection_item_annotation(target)
        if item is None:
            raise ValueError(
                f"Execution node {stage_name}.{node_name} input {input_name!r} "
                "does not accept multiple sources"
            )
        target = item
    if not _annotations_compatible(source, target):
        reason = (
            "is incompatible with the stage input"
            if source_name is None
            else f"is not compatible with {source_name!r}"
        )
        raise ValueError(
            f"Execution node {stage_name}.{node_name} input {input_name!r} {reason}"
        )


def _sources(binding: str | tuple[str, ...]) -> tuple[str, ...]:
    return binding if isinstance(binding, tuple) else (binding,)


def _annotations_compatible(
    source: Any,
    target: Any,
    _active_pairs: tuple[tuple[Any, Any], ...] = (),
) -> bool:
    pair = (source, target)
    if pair in _active_pairs:
        # Close this recursive branch; its other members still need checking.
        return True
    active_pairs = (*_active_pairs, pair)
    source_members = annotation_members(source)
    target_members = annotation_members(target)
    for member in source_members:
        if get_origin(member) is Literal:
            for value in get_args(member):
                if not any(
                    any(
                        type(value) is type(candidate) and value == candidate
                        for candidate in get_args(target)
                    )
                    if get_origin(target) is Literal
                    else _member_compatible(type(value), target, active_pairs)
                    for target in target_members
                ):
                    return False
        elif not any(
            _member_compatible(member, target, active_pairs)
            for target in target_members
        ):
            return False
    return True


def _member_compatible(
    source: Any, target: Any, active_pairs: tuple[tuple[Any, Any], ...]
) -> bool:
    source = tuple if source is Tuple else tuple[()] if source == Tuple[()] else source
    target = tuple if target is Tuple else tuple[()] if target == Tuple[()] else target
    if source == target or target is Any:
        return True
    if isinstance(source, NewType):
        return _annotations_compatible(source.__supertype__, target, active_pairs)
    if source is Any:
        return False
    source_origin = get_origin(source)
    target_origin = get_origin(target)
    source_args = get_args(source)
    target_args = get_args(target)
    if target_origin is Literal:
        return source is type(None) and None in target_args
    if source is bool and target in (int, float):
        return False
    source_type = source_origin or source
    target_type = target_origin or target
    if not isinstance(source_type, type) or not isinstance(target_type, type):
        return False
    try:
        if not issubclass(source_type, target_type):
            return False
    except TypeError:
        return False
    if target == tuple[()]:
        return source == tuple[()]
    if target_origin is None or not target_args:
        return True
    if source_origin is None:
        return False
    if source_origin is tuple and target_origin is Sequence:
        values = (
            source_args[:1]
            if len(source_args) == 2 and source_args[1] is Ellipsis
            else source_args
        )
        return (
            bool(source_args)
            and all(
                _annotations_compatible(item, target_args[0], active_pairs)
                for item in values
            )
            or source == tuple[()]
        )
    if source_origin is tuple and target_origin is tuple:
        source_collection = len(source_args) == 2 and source_args[1] is Ellipsis
        target_collection = len(target_args) == 2 and target_args[1] is Ellipsis
        if target_collection:
            values = source_args[:1] if source_collection else source_args
            return all(
                _annotations_compatible(item, target_args[0], active_pairs)
                for item in values
            )
        if source_collection:
            return False
    if len(source_args) != len(target_args):
        return False
    return all(
        _annotations_compatible(s, t, active_pairs)
        for s, t in zip(source_args, target_args)
    )
