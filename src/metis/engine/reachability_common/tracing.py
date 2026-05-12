# SPDX-FileCopyrightText: Copyright 2025-2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations
from collections import defaultdict, deque

from .models import ReachabilityPath
from .utils import _dedupe_paths
_EXTRACTION_SYSTEM_PROMPT = """\
You are a C and C++ static analysis tool. Analyze the following source file and \
extract ALL function definitions with their security relevant metadata.

For each function defined in this file (with body), provide:
1. "name": the function name
2. "line": line number where the function definition starts
3. "calls": list of ALL function and macro names called inside this function body
4. "is_source": true if this function directly receives or processes external/untrusted input
5. "source_reason": if is_source, briefly explain why
6. "is_sink": true if this function performs operations that could be dangerous with attacker-controlled input
7. "sink_type": if is_sink, one of: buffer_overflow, use_after_free, double_free, null_deref, \
command_injection, format_string, integer_overflow, path_traversal, race_condition, \
uninitialized_memory, type_confusion, out_of_bounds, other
8. "sink_reason": if is_sink, briefly explain the danger

Source indicators - mark is_source=true when a function:
- Reads from stdin, files, network sockets, pipes, IPC
- Processes command-line arguments (argc/argv) or environment variables
- Is a callback or handler for external events (ioctl, sysfs, debugfs, netlink)
- Is main() or an entry point that receives external parameters
- Handles hardware interrupts, DMA completions, firmware responses, or device register reads
- Is invoked from user-space via file_operations, ioctl dispatch, or similar interfaces

Sink indicators - mark is_sink=true when a function:
- Calls memcpy/strcpy/strcat/sprintf/gets/scanf with sizes derived from parameters
- Performs pointer arithmetic without bounds checking
- Has integer arithmetic that could overflow and influence buffer sizes or indices
- Calls system/popen/exec* with constructed strings
- Uses format strings built from variables
- Frees memory that may be used afterward, or frees the same pointer twice
- Dereferences pointers without null checks after allocation or lookup
- Accesses arrays with indices derived from untrusted input
- Has realloc/malloc with arithmetic on the size argument that could wrap
- Casts void* to a concrete type without type validation
- Writes to hardware registers, MMIO, or DMA buffers
- Manipulates refcounts, state flags, or power management transitions
- Performs cleanup/teardown that may race with pending work items or callbacks

A function CAN be both a source and a sink.
Do NOT include mere declarations/prototypes (no body).
DO include static, inline, and helper functions.

Also extract global constructs that bind external entry points or callbacks:
- struct file_operations / fops tables
- ops tables and callback tables
- timer/work/watchdog initializer structs
- global function-pointer structs

Return ONLY valid JSON:
{{"functions": [{{"name": "example", "line": 1, "calls": [], "is_source": false, \
"source_reason": "", "is_sink": false, "sink_type": "", "sink_reason": ""}}],
"globals": [{{"name": "gpu_fops", "line": 152, "kind": "file_operations",
"initializer": ".open = gpu_file_open, .release = gpu_file_release",
"referenced_functions": ["gpu_file_open", "gpu_file_release"]}}]}}

If the file has no function definitions or global constructs, return: {{"functions": [], "globals": []}}"""

_EXTRACTION_USER_TEMPLATE = "File: {file_path}\n\nCode:\n{file_content}"


class PathTracer:
    def __init__(self, graph, *, max_path_length=25, max_paths_per_source=200):
        self._g = graph; self._ml = max_path_length; self._mp = max_paths_per_source

    def find_all_paths(self):
        sources = self._g.get_sources()
        sinks = {n.unique_name for n in self._g.get_sinks()}
        if not sources or not sinks: return []
        paths = []
        for s in sources:
            if s.unique_name in sinks:
                paths.append(ReachabilityPath(source=s.unique_name, sink=s.unique_name, path=[s.unique_name], sink_type=s.sink_type))
            paths.extend(self._bfs(s.unique_name, sinks))
        return paths

    def _bfs(self, src, sinks):
        results, q = [], deque([[src]])
        while q and len(results) < self._mp:
            path = q.popleft(); node = self._g.get_node(path[-1])
            if not node: continue
            for c in node.resolved_calls:
                if c in path: continue
                np = path + [c]
                if c in sinks:
                    sn = self._g.get_node(c)
                    results.append(ReachabilityPath(source=src, sink=c, path=list(np), sink_type=sn.sink_type if sn else ""))
                    if len(results) >= self._mp: break
                    if len(np) < self._ml: q.append(np)
                elif len(np) < self._ml: q.append(np)
        return results


class SourceRootedPathTracer:
    """Trace maximal source-rooted paths without relying on sink labels."""

    def __init__(self, graph, *, max_path_length=25, max_paths_per_source=200):
        self._g = graph
        self._ml = max(1, int(max_path_length or 1))
        self._mp = max(1, int(max_paths_per_source or 1))

    def find_all_paths(self):
        sources = sorted(self._g.get_sources(), key=self._node_sort_key)
        if not sources:
            return []
        paths = []
        for source in sources:
            paths.extend(self._terminal_paths_from_source(source.unique_name))
        return self._drop_strict_prefix_paths(_dedupe_paths(paths))

    def _terminal_paths_from_source(self, source_name):
        results, stack = [], [[source_name]]
        while stack and len(results) < self._mp:
            path = stack.pop()
            node = self._g.get_node(path[-1])
            if not node:
                continue
            callees = [
                callee
                for callee in sorted(node.resolved_calls or [], key=self._node_sort_key)
                if callee not in path
            ]
            if not callees or len(path) >= self._ml:
                results.append(self._to_path(source_name, path))
                continue
            for callee in reversed(callees):
                stack.append(path + [callee])
        return results

    def _to_path(self, source_name, path):
        endpoint_name = path[-1]
        endpoint = self._g.get_node(endpoint_name)
        return ReachabilityPath(
            source=source_name,
            sink=endpoint_name,
            path=list(path),
            sink_type=endpoint.sink_type if endpoint and endpoint.is_sink else "reachable_endpoint",
        )

    def _drop_strict_prefix_paths(self, paths):
        by_source = defaultdict(list)
        for path in paths:
            by_source[path.source].append(path)

        selected = []
        for group in by_source.values():
            tuples = [(path, tuple(path.path or [])) for path in group if path.path]
            for path, path_tuple in tuples:
                if any(
                    len(other_tuple) > len(path_tuple)
                    and other_tuple[:len(path_tuple)] == path_tuple
                    for _other, other_tuple in tuples
                ):
                    continue
                selected.append(path)
        return sorted(selected, key=self._path_sort_key)

    def _node_sort_key(self, node_or_name):
        node = node_or_name
        if isinstance(node_or_name, str):
            node = self._g.get_node(node_or_name)
        if not node:
            return ("", 0, str(node_or_name))
        return (node.file_path, int(node.line_number or 0), node.name, node.unique_name)

    def _path_sort_key(self, path):
        endpoint = self._g.get_node(path.sink)
        source = self._g.get_node(path.source)
        return (
            source.file_path if source else "",
            int(source.line_number or 0) if source else 0,
            source.name if source else path.source,
            len(path.path or []),
            endpoint.file_path if endpoint else "",
            int(endpoint.line_number or 0) if endpoint else 0,
            endpoint.name if endpoint else path.sink,
            tuple(path.path or []),
        )
