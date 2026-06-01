# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0


from metis.reachability_settings import DEFAULT_REACHABILITY_MAX_PATH_LENGTH

from .c_family import CFamilyTreeSitterExtractor
from .c_family_rules import (
    _normalise_security_function_specs,
    _normalise_source_function_specs,
    external_sink_type,
)
from .graph_utils import _emit_progress
from .models import ReachabilityGraph
from .tracing import SourceRootedPathTracer


class ReachabilityGraphCache:
    def __init__(self, config, repository):
        self._config = config
        self._repository = repository
        self._extractor = CFamilyTreeSitterExtractor(repository)
        self._graph = None
        self._paths = None
        self._paths_max_length = None

    def build_graph(self, files=None, *, progress_callback=None):
        selected = self._reachability_files(
            files if files is not None else self._repository.get_code_files()
        )
        return self._build_graph_from_files(
            selected,
            self._config.codebase_path,
            progress_callback=progress_callback,
        )

    def ensure_graph(
        self, *, progress_callback=None, source_functions=None, security_functions=None
    ):
        if self._graph is None:
            self._graph = self.build_graph(progress_callback=progress_callback)
        self._annotate_configured_functions(
            self._graph, source_functions, security_functions, progress_callback
        )
        return self._graph

    def get_codebase_graph_and_paths(
        self,
        *,
        max_path_length=DEFAULT_REACHABILITY_MAX_PATH_LENGTH,
        progress_callback=None,
        source_functions=None,
        security_functions=None,
    ):
        max_path_length = int(max_path_length or DEFAULT_REACHABILITY_MAX_PATH_LENGTH)
        if self._graph is not None:
            self._annotate_configured_functions(
                self._graph, source_functions, security_functions, progress_callback
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

    def _annotate_configured_functions(
        self, graph, source_functions, security_functions, progress_callback
    ):
        self._annotate_configured_source_functions(
            graph, source_functions, progress_callback=progress_callback
        )
        self._annotate_configured_security_functions(
            graph, security_functions, progress_callback=progress_callback
        )

    def _reachability_files(self, files) -> list[str]:
        return [str(path) for path in files if self._supports_reachability_file(path)]

    def _supports_reachability_file(self, path) -> bool:
        plugin = self._repository.get_plugin_for_path(str(path))
        supports = getattr(plugin, "supports_reachability_review", None)
        return bool(callable(supports) and supports())

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
            _emit_progress(
                progress_callback, "configured_source_functions_done", sources=updated
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
            _emit_progress(
                progress_callback, "configured_security_functions_done", sinks=updated
            )
        return updated

    def _invalidate_paths(self):
        self._paths = None
        self._paths_max_length = None

    def _build_graph_from_files(
        self, files, codebase_path: str, *, progress_callback=None
    ) -> ReachabilityGraph:
        graph = ReachabilityGraph()
        files = sorted(str(file) for file in files)
        total = len(files)
        errors: list[str] = []
        _emit_progress(progress_callback, "treesitter_graph_start", total=total)

        for completed, file_path in enumerate(files, start=1):
            parsed = self._extractor.parse_file(
                codebase_path=codebase_path,
                file_path=file_path,
            )
            errors.extend(parsed.errors)
            for node in parsed.nodes:
                graph.add_node(node)
            for global_construct in parsed.globals:
                graph.add_global(global_construct)
            _emit_progress(
                progress_callback,
                "treesitter_graph_progress",
                completed=completed,
                total=total,
                file=file_path,
                functions=len(parsed.nodes),
                globals=len(parsed.globals),
                errors=len(parsed.errors),
                error_messages=parsed.errors[:3],
            )

        graph.resolve_all_calls()
        graph.annotate_automatic_sources()
        graph.annotate_external_call_sinks(external_sink_type)
        _emit_progress(
            progress_callback,
            "treesitter_graph_done",
            nodes=graph.node_count(),
            edges=graph.edge_count(),
            sources=len(graph.get_sources()),
            sinks=len(graph.get_sinks()),
            globals=len(graph.get_globals()),
            errors=errors,
        )
        return graph
