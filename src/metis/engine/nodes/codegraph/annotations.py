# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import re
from collections.abc import Callable
from collections.abc import Mapping
from typing import Annotated

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import StringConstraints

from metis.engine.codegraph import CodeGraph
from metis.engine.codegraph import CodeGraphAnnotations
from metis.engine.codegraph import CodeGraphDiagnostic
from metis.engine.codegraph import CodeGraphNodeFacts
from metis.engine.codegraph import CodeGraphSemantics

from .progress import CONFIGURED_SECURITY_FUNCTIONS_DONE
from .progress import CONFIGURED_SOURCE_FUNCTIONS_DONE
from .semantics import CodeGraphSemanticsCatalog

NonEmptyString = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
GLOBAL_INITIALIZER_ENTRYPOINT_REASON = (
    "referenced by a global function table or initializer"
)


class CodeGraphSourceFunction(BaseModel):
    name: NonEmptyString
    reason: str | None = None

    model_config = ConfigDict(extra="forbid", frozen=True)


class CodeGraphSecurityFunction(BaseModel):
    name: NonEmptyString
    sink_type: str | None = None
    reason: str | None = None

    model_config = ConfigDict(extra="forbid", frozen=True)


class CodeGraphConfiguration(BaseModel):
    source_functions: tuple[CodeGraphSourceFunction, ...] = ()
    security_functions: tuple[CodeGraphSecurityFunction, ...] = ()

    model_config = ConfigDict(extra="forbid", frozen=True)


def annotate_graph(
    graph: CodeGraph,
    *,
    semantics_for_path: Mapping[str, str | None],
    semantics: CodeGraphSemanticsCatalog,
    annotation_settings: CodeGraphConfiguration,
    progress_callback: Callable[[dict[str, object]], None] | None = None,
) -> tuple[tuple[str, ...], tuple[CodeGraphDiagnostic, ...]]:
    for node in graph.nodes.values():
        node.is_source = False
        node.source_reason = ""
        node.is_sink = False
        node.sink_type = ""
        node.sink_reason = ""
    _annotate_automatic_sources(graph)
    failed_files, diagnostics = _annotate_language_semantics(
        graph,
        semantics_for_path,
        semantics,
    )
    configured_sources, configured_sinks = _annotate_configured_functions(
        graph,
        annotation_settings,
    )
    if progress_callback is not None and configured_sources:
        progress_callback(
            {
                "event": CONFIGURED_SOURCE_FUNCTIONS_DONE,
                "sources": configured_sources,
            }
        )
    if progress_callback is not None and configured_sinks:
        progress_callback(
            {
                "event": CONFIGURED_SECURITY_FUNCTIONS_DONE,
                "sinks": configured_sinks,
            }
        )
    return failed_files, diagnostics


def normalize_sink_type(value: object) -> str:
    value = str(value or "other")
    normalized = value.strip().lower().replace("-", "_").replace(" ", "_")
    normalized = re.sub(r"[^a-z0-9_]+", "_", normalized)
    return re.sub(r"_+", "_", normalized).strip("_") or "other"


def _annotate_automatic_sources(graph: CodeGraph) -> None:
    incoming: dict[str, set[str]] = {name: set() for name in graph.nodes}
    for caller in graph.nodes.values():
        for callee in caller.resolved_calls:
            if callee in incoming and callee != caller.unique_name:
                incoming[callee].add(caller.unique_name)
    global_entries = {
        (construct.file_path, reference)
        for construct in graph.globals.values()
        for reference in construct.referenced_functions
    }
    for name, node in graph.nodes.items():
        global_entry = (node.file_path, node.name) in global_entries or (
            node.language == "c"
            and node.entrypoint_reason == GLOBAL_INITIALIZER_ENTRYPOINT_REASON
        )
        if node.is_source or (incoming[name] and not global_entry):
            continue
        node.is_source = True
        if global_entry:
            node.source_reason = (
                f"public_or_external_entrypoint: {GLOBAL_INITIALIZER_ENTRYPOINT_REASON}"
            )
        elif node.is_public_entrypoint:
            reason = node.entrypoint_reason or "public or external entrypoint"
            node.source_reason = f"public_or_external_entrypoint: {reason}"
        elif node.language == "c":
            node.source_reason = (
                "no resolved internal callers in tree-sitter call graph"
            )
        else:
            node.source_reason = "no resolved internal callers in CodeGraph"


def _annotate_language_semantics(
    graph: CodeGraph,
    semantics_for_path: Mapping[str, str | None],
    catalog: CodeGraphSemanticsCatalog,
) -> tuple[tuple[str, ...], tuple[CodeGraphDiagnostic, ...]]:
    providers: dict[str, CodeGraphSemantics] = {}
    failed_files: set[str] = set()
    diagnostics: list[CodeGraphDiagnostic] = []
    for node in graph.nodes.values():
        if node.file_path in failed_files:
            continue
        semantics_name = semantics_for_path.get(node.file_path)
        if not semantics_name:
            continue
        try:
            provider = providers.get(semantics_name)
            if provider is None:
                provider = catalog.resolve(semantics_name)
                providers[semantics_name] = provider
            with catalog.provider_lock(semantics_name):
                annotations = provider.analyze_node(
                    CodeGraphNodeFacts(
                        unique_name=node.unique_name,
                        file_path=node.file_path,
                        name=node.name,
                        language=node.language,
                        calls=tuple(node.calls),
                        unresolved_calls=tuple(graph.unresolved_calls_for(node)),
                    )
                )
            if not isinstance(annotations, CodeGraphAnnotations):
                raise TypeError(
                    f"CodeGraph semantics provider {semantics_name!r} returned "
                    "invalid annotations"
                )
        except Exception as exc:
            failed_files.add(node.file_path)
            diagnostics.append(
                CodeGraphDiagnostic(
                    node.file_path,
                    f"CodeGraph semantics {semantics_name!r} failed: {exc}",
                    severity="warning",
                )
            )
            continue
        if annotations.is_source:
            node.is_source = True
            node.source_reason = annotations.source_reason
        if annotations.is_sink:
            node.is_sink = True
            node.sink_type = annotations.sink_type
            node.sink_reason = annotations.sink_reason
        for key, tag in annotations.tags.items():
            node.set_tag(key, value=tag.value, reason=tag.reason)
    return tuple(sorted(failed_files)), tuple(diagnostics)


def _annotate_configured_functions(
    graph: CodeGraph,
    settings: CodeGraphConfiguration,
) -> tuple[int, int]:
    sources = {entry.name.lower(): entry for entry in settings.source_functions}
    sinks = {entry.name.lower(): entry for entry in settings.security_functions}
    configured_sources = 0
    configured_sinks = 0
    for node in graph.nodes.values():
        source = sources.get(node.name.lower()) or sources.get(node.unique_name.lower())
        if source is not None:
            if not node.is_source:
                configured_sources += 1
            node.is_source = True
            reason = (source.reason or "").strip() or "configured in metis.yaml"
            node.source_reason = f"configured source function: {reason}"
        if node.is_sink:
            continue
        matched_calls = [call for call in node.calls if call.lower() in sinks]
        if not matched_calls:
            continue
        call = matched_calls[0]
        sink = sinks[call.lower()]
        node.is_sink = True
        configured_sinks += 1
        node.sink_type = normalize_sink_type(sink.sink_type)
        reason = (sink.reason or "").strip() or "configured in metis.yaml"
        node.sink_reason = f"calls configured security function {call}: {reason}"
    return configured_sources, configured_sinks
