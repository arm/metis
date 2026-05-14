# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""LLM classification of project-specific security sinks."""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate

from metis.usage import submit_with_current_context
from metis.utils import parse_json_output

from .utils import _build_file_grouped_node_chunks, _chat_model_kwargs, _lookup_fn

logger = logging.getLogger("metis")

_PROJECT_SINK_TYPE_NAMES = (
    "buffer_overflow",
    "out_of_bounds",
    "use_after_free",
    "double_free",
    "null_deref",
    "command_injection",
    "format_string",
    "integer_overflow",
    "path_traversal",
    "race_condition",
    "uninitialized_memory",
    "type_confusion",
    "missing_auth",
    "permission_mismatch",
    "refcount_imbalance",
    "state_order",
    "teardown_race",
    "other",
)
_PROJECT_SINK_TYPES = frozenset(_PROJECT_SINK_TYPE_NAMES)
_PROJECT_SINK_TYPE_LIST = ", ".join(_PROJECT_SINK_TYPE_NAMES)

_PROJECT_SINK_SYS = f"""\
You classify project-defined C/C++ functions as security-sensitive sink abstractions.

A project sink is a function that callers should treat as security-sensitive even if
it is not a standard C/POSIX/kernel primitive. Include project wrappers and project
APIs that materially perform or gate risky operations, such as:
- copying, parsing, serializing, deserializing, or importing caller-controlled data
- allocating, freeing, releasing, closing, refcounting, or managing object lifetime
- checking authorization, permissions, capabilities, identity, roles, or ownership
- opening, deleting, renaming, canonicalizing, or otherwise using filesystem paths
- launching commands or building command strings
- mutating hardware/device state, MMIO/register/DMA state, or async callback/work state
- publishing/removing objects from global/shared tables, queues, lists, maps, or registries

Do NOT report ordinary helper functions just because their name sounds important.
Do NOT report standard library/POSIX/kernel primitives unless their implementation is
shown as a project-defined function in the input.
Do NOT report final vulnerabilities here. This is only sink classification.

The sink_type field is mandatory and MUST be exactly one of these values:
{_PROJECT_SINK_TYPE_LIST}.
Do not invent aliases such as authorization, lifetime, bounds, parser, filesystem,
or concurrency. Map the classification to the closest allowed sink_type yourself.

Return ONLY valid JSON:
{{{{"sinks": [{{{{"function_name": "relative/path.c::function_name",
"sink_type": "permission_mismatch", "reason": "why callers should treat it as sensitive"}}}}]}}}}
Return {{{{"sinks": []}}}} if no project-specific sinks are present. Be conservative."""

_PROJECT_SINK_USR = "Functions:\n\n{functions_code}"


class ProjectSinkClassifier:
    """Annotate graph nodes with project-specific sink labels from source context."""

    def __init__(
        self,
        llm_provider,
        model,
        usage_runtime,
        codebase_path,
        *,
        max_tokens=8192,
        reasoning_effort=None,
    ):
        self._p = llm_provider
        self._model = model
        self._u = usage_runtime
        self._cb = codebase_path
        self._max_tokens = max_tokens
        self._reasoning_effort = reasoning_effort

    def annotate(self, graph, *, max_workers=4, progress_callback=None):
        candidates = [
            node
            for node in sorted(
                graph.nodes.values(),
                key=lambda item: (item.file_path, item.line_number, item.name),
            )
            if not node.is_sink
        ]
        if not candidates:
            return 0
        chunks = _build_file_grouped_node_chunks(
            self._cb,
            candidates,
            max_total_chars=50000,
            per_fn_chars=3500,
        )
        if not chunks:
            return 0
        if progress_callback:
            progress_callback(
                {"event": "project_sink_discovery_start", "functions": len(candidates)}
            )

        classified = []
        worker_count = max(1, min(int(max_workers or 1), len(chunks)))
        if worker_count == 1:
            for chunk_nodes, text in chunks:
                classified.extend(self._classify_chunk(chunk_nodes, text))
        else:
            with ThreadPoolExecutor(max_workers=worker_count) as executor:
                futures = [
                    submit_with_current_context(
                        executor, self._classify_chunk, chunk_nodes, text
                    )
                    for chunk_nodes, text in chunks
                ]
                for future in as_completed(futures):
                    try:
                        classified.extend(future.result())
                    except Exception as exc:
                        logger.debug("Project sink discovery chunk failed: %s", exc)

        annotated = 0
        seen = set()
        for node, sink_type, reason in classified:
            if node.unique_name in seen or node.is_sink:
                continue
            seen.add(node.unique_name)
            node.is_sink = True
            node.sink_type = sink_type
            node.sink_reason = f"project-specific sink: {reason}"
            annotated += 1

        if progress_callback:
            progress_callback(
                {"event": "project_sink_discovery_done", "sinks": annotated}
            )
        return annotated

    def _classify_chunk(self, chunk_nodes, functions_code):
        kw = _chat_model_kwargs(self._u, reasoning_effort=self._reasoning_effort)
        chat = self._p.get_chat_model(
            model=self._model, max_tokens=self._max_tokens, temperature=0.1, **kw
        )
        prompt = ChatPromptTemplate.from_messages(
            [("system", _PROJECT_SINK_SYS), ("user", _PROJECT_SINK_USR)]
        )
        raw = (
            (prompt | chat | StrOutputParser())
            .invoke({"functions_code": functions_code})
            .strip()
        )
        return self._parse(raw, chunk_nodes)

    def _parse(self, raw, functions):
        parsed = parse_json_output(str(raw or ""))
        if not isinstance(parsed, dict):
            return []
        sinks = parsed.get("sinks")
        if not isinstance(sinks, list):
            return []

        by_name = {fn.name: fn for fn in functions}
        by_unique = {fn.unique_name: fn for fn in functions}
        classified = []
        for item in sinks:
            if not isinstance(item, dict):
                continue
            node = _lookup_fn(
                str(item.get("function_name") or ""), by_name, by_unique, functions
            )
            if not node:
                continue
            sink_type = _normalise_project_sink_type(item.get("sink_type"))
            reason = str(item.get("reason") or "").strip()
            if not reason:
                reason = "classified by source-context analysis"
            classified.append((node, sink_type, reason))
        return classified


def _normalise_project_sink_type(value):
    raw = str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
    if raw in _PROJECT_SINK_TYPES:
        return raw
    return "other"
