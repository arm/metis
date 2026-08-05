# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0


from collections import deque
from functools import partial

from metis.engine.nodes.reachability.options import DEFAULT_REACHABILITY_MAX_PATH_LENGTH

from .domain import ReachabilityPath
from .graph_utils import _dedupe_paths, _node_sort_key, _source_rooted_path_sort_key
from .progress import ReachabilityProgress as Progress
from .progress import emit_progress
from .workers import bounded_worker_count, run_reachability_jobs


class SourceRootedPathTracer:
    def __init__(
        self,
        graph,
        *,
        max_path_length=DEFAULT_REACHABILITY_MAX_PATH_LENGTH,
        max_workers: int | str | None = None,
        progress_callback=None,
    ):
        self._g = graph
        self._ml = max(1, int(max_path_length or 1))
        self._mw = max_workers
        self._progress_callback = progress_callback
        self._node_sort_key = partial(_node_sort_key, self._g)
        self._path_sort_key = partial(_source_rooted_path_sort_key, self._g)

    def find_all_paths(self):
        sources = sorted(self._g.get_sources(), key=self._node_sort_key)
        if not sources:
            return []
        worker_count = bounded_worker_count(self._mw, len(sources))
        source_names = [source.unique_name for source in sources]
        chunks = _round_robin_chunks(
            source_names,
            min(len(source_names), max(32, worker_count * 4)),
        )
        emit_progress(
            self._progress_callback,
            Progress.PATHS_START,
            total=len(source_names),
            sources=len(source_names),
            chunks=len(chunks),
            workers=worker_count,
            paths=0,
        )
        paths = []
        completed_sources = 0
        found_paths = 0

        def _path_progress(chunk_size, _completed, _total, chunk_paths):
            nonlocal completed_sources, found_paths
            completed_sources += int(chunk_size or 0)
            found_paths += len(chunk_paths or [])
            emit_progress(
                self._progress_callback,
                Progress.PATHS_PROGRESS,
                completed=min(completed_sources, len(source_names)),
                total=len(source_names),
                sources=len(source_names),
                chunks=len(chunks),
                workers=worker_count,
                paths=found_paths,
            )

        for chunk_paths in run_reachability_jobs(
            chunks,
            self._terminal_paths_from_sources,
            max_workers=worker_count,
            label="Reachability path tracing",
            result_key=len,
            on_result=_path_progress,
            swallow_exceptions=False,
        ):
            paths.extend(chunk_paths)
        return sorted(_dedupe_paths(paths), key=self._path_sort_key)

    def _terminal_paths_from_sources(self, source_names):
        paths = []
        for source_name in source_names:
            paths.extend(self._terminal_paths_from_source(source_name))
        return paths

    def _terminal_paths_from_source(self, source_name):
        results = []
        queue = deque([[source_name]])
        while queue:
            path = queue.popleft()
            node = self._g.get_node(path[-1])
            if not node:
                continue
            callees = [
                callee
                for callee in sorted(node.resolved_calls or [], key=self._node_sort_key)
                if callee not in path
            ]
            if node.is_sink or not callees or len(path) >= self._ml:
                results.append(self._to_path(source_name, path))
            if len(path) >= self._ml:
                continue
            for callee in callees:
                queue.append(path + [callee])
        return results

    def _to_path(self, source_name, path):
        endpoint_name = path[-1]
        endpoint = self._g.get_node(endpoint_name)
        return ReachabilityPath(
            source_name,
            endpoint_name,
            list(path),
            (
                endpoint.sink_type
                if endpoint and endpoint.is_sink
                else "reachable_endpoint"
            ),
        )


def _round_robin_chunks(items, chunk_count: int):
    chunks = [[] for _ in range(max(1, int(chunk_count or 1)))]
    for index, item in enumerate(items):
        chunks[index % len(chunks)].append(item)
    return [chunk for chunk in chunks if chunk]
