# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Reachability graph and path caching."""

from __future__ import annotations

from .c_family_rules import (
    C_FAMILY_PLUGIN_NAMES,
    _normalise_security_function_specs,
    _normalise_source_function_specs,
)
from .tracing import SourceRootedPathTracer


class ReachabilityGraphCache:
    """Build and cache the C/C++ reachability graph plus traced paths."""

    def __init__(self, config, repository):
        self._config = config
        self._repository = repository
        self._builder = None
        self._graph = None
        self._paths = None
        self._paths_max_length = None

    def build_graph(self, files=None, *, progress_callback=None):
        selected = self._c_cpp_files(
            files if files is not None else self._repository.get_code_files()
        )
        return self._get_builder().build(
            selected,
            self._config.codebase_path,
            progress_callback=progress_callback,
        )

    def ensure_graph(
        self, *, progress_callback=None, source_functions=None, security_functions=None
    ):
        if self._graph is not None:
            self._annotate_configured_source_functions(
                self._graph,
                source_functions,
                progress_callback=progress_callback,
            )
            self._annotate_configured_security_functions(
                self._graph,
                security_functions,
                progress_callback=progress_callback,
            )
            return self._graph

        self._graph = self.build_graph(progress_callback=progress_callback)
        self._annotate_configured_source_functions(
            self._graph,
            source_functions,
            progress_callback=progress_callback,
        )
        self._annotate_configured_security_functions(
            self._graph,
            security_functions,
            progress_callback=progress_callback,
        )
        return self._graph

    def get_codebase_graph_and_paths(
        self,
        *,
        max_path_length=25,
        progress_callback=None,
        source_functions=None,
        security_functions=None,
    ):
        """Return the cached codebase graph and traced paths for shared analysis."""
        max_path_length = int(max_path_length or 25)
        if self._graph is not None:
            self._annotate_configured_source_functions(
                self._graph,
                source_functions,
                progress_callback=progress_callback,
            )
            self._annotate_configured_security_functions(
                self._graph,
                security_functions,
                progress_callback=progress_callback,
            )
        if (
            self._graph is not None
            and self._paths is not None
            and self._paths_max_length == max_path_length
        ):
            return self._graph, list(self._paths)

        graph = self.ensure_graph(
            progress_callback=progress_callback,
            source_functions=source_functions,
            security_functions=security_functions,
        )
        paths = SourceRootedPathTracer(
            graph, max_path_length=max_path_length
        ).find_all_paths()
        self._paths = list(paths)
        self._paths_max_length = max_path_length
        return graph, list(paths)

    def _c_cpp_files(self, files) -> list[str]:
        return [
            str(path)
            for path in files
            if self._repository.is_path_supported_by_plugins(
                str(path), C_FAMILY_PLUGIN_NAMES
            )
        ]

    def _annotate_configured_source_functions(
        self, graph, source_functions, *, progress_callback=None
    ):
        specs = _normalise_source_function_specs(source_functions)
        if not specs:
            return 0
        updated = 0
        for node in graph.nodes.values():
            spec = specs.get(node.name.lower()) or specs.get(node.unique_name.lower())
            if spec is None:
                continue
            if not node.is_source:
                updated += 1
            node.is_source = True
            node.source_reason = f"configured source function: {spec['reason']}"

        if updated:
            self._invalidate_paths()
            if progress_callback:
                progress_callback(
                    {"event": "configured_source_functions_done", "sources": updated}
                )
        return updated

    def _annotate_configured_security_functions(
        self, graph, security_functions, *, progress_callback=None
    ):
        specs = _normalise_security_function_specs(security_functions)
        if not specs:
            return 0
        updated = 0
        for node in graph.nodes.values():
            if node.is_sink:
                continue
            matched_calls = [
                str(call)
                for call in node.calls or []
                if str(call or "").lower() in specs
            ]
            if not matched_calls:
                continue
            spec = specs[str(matched_calls[0]).lower()]
            node.is_sink = True
            node.sink_type = spec["sink_type"]
            node.sink_reason = (
                f"calls configured security function {matched_calls[0]}: "
                f"{spec['reason']}"
            )
            updated += 1

        if updated:
            self._invalidate_paths()
            if progress_callback:
                progress_callback(
                    {"event": "configured_security_functions_done", "sinks": updated}
                )
        return updated

    def _invalidate_paths(self):
        self._paths = None
        self._paths_max_length = None

    def _get_builder(self):
        if self._builder is None:
            from .builder import TreeSitterReachabilityGraphBuilder

            self._builder = TreeSitterReachabilityGraphBuilder()
        return self._builder
