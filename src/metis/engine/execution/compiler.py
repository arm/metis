# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from types import UnionType
from typing import Any
from typing import Union
from typing import get_args
from typing import get_origin

from pydantic import BaseModel

from .catalog import NodeCatalog
from .contracts import CapabilityRequirement
from .contracts import NodeRegistration
from .contracts import StageName
from .contracts import annotation_allows_none
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
        node_configuration = registration.configuration.model_validate(
            configuration.get(name, {})
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
            and input_name not in initial_inputs
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
                if not collection and not annotation_allows_none(
                    registration.inputs[input_name]
                ):
                    required_dependencies.add(producer_name)
        planned[name] = _PlannedNode(
            name,
            definition,
            registration,
            node_configuration,
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
                _validate_reference(
                    stage_name,
                    name,
                    input_name,
                    source,
                    registrations,
                    collection=isinstance(binding, tuple),
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
        collection = get_origin(annotation) is tuple
        target = get_args(annotation)[0] if collection else annotation
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


def _validate_reference(
    stage_name: StageName,
    node_name: str,
    input_name: str,
    source: str,
    registrations: Mapping[str, NodeRegistration],
    *,
    collection: bool = False,
) -> None:
    source_annotation = _reference_annotation(stage_name, source, registrations)
    target = registrations[node_name].inputs[input_name]
    if collection:
        if get_origin(target) is not tuple:
            raise ValueError(
                f"Execution node {stage_name}.{node_name} input {input_name!r} "
                "does not accept multiple sources"
            )
        target = get_args(target)[0]
    if not _annotations_compatible(source_annotation, target):
        raise ValueError(
            f"Execution node {stage_name}.{node_name} input {input_name!r} is not "
            f"compatible with {source!r}"
        )


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
) -> None:
    if collection:
        if get_origin(target) is not tuple:
            raise ValueError(
                f"Execution node {stage_name}.{node_name} input {input_name!r} "
                "does not accept multiple sources"
            )
        target = get_args(target)[0]
    if not _annotations_compatible(source, target):
        raise ValueError(
            f"Execution node {stage_name}.{node_name} input {input_name!r} "
            "is incompatible with the stage input"
        )


def _sources(binding: str | tuple[str, ...]) -> tuple[str, ...]:
    return binding if isinstance(binding, tuple) else (binding,)


def _annotations_compatible(source: Any, target: Any) -> bool:
    if target is Any:
        return True
    if source is Any:
        return False
    source_members = (
        get_args(source) if get_origin(source) in {Union, UnionType} else (source,)
    )
    target_members = (
        get_args(target) if get_origin(target) in {Union, UnionType} else (target,)
    )
    return all(
        any(_member_compatible(s, t) for t in target_members) for s in source_members
    )


def _member_compatible(source: Any, target: Any) -> bool:
    if source == target or target is Any:
        return True
    if source is Any:
        return False
    source_origin = get_origin(source)
    target_origin = get_origin(target)
    if source_origin is None and target_origin is None:
        return (
            isinstance(source, type)
            and isinstance(target, type)
            and issubclass(source, target)
        )
    if target_origin is None:
        return (
            isinstance(target, type)
            and isinstance(source_origin, type)
            and (issubclass(source_origin, target))
        )
    if source_origin is not target_origin:
        return False
    source_args = get_args(source)
    target_args = get_args(target)
    if len(source_args) != len(target_args):
        return False
    if source_origin is not tuple:
        return source_args == target_args
    return all(_annotations_compatible(s, t) for s, t in zip(source_args, target_args))
