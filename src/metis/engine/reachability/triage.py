# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass
from functools import partial
import logging
import re
from typing import Any

from metis.engine.graphs.schemas import TriageDecisionModel
from metis.engine.llm_runner import JsonPromptRequest, JsonPromptRunner
from metis.utils import parse_json_output

from .file_focus import FileFocusBuilder
from .graph_utils import _build_reverse_edges, _node_sort_key
from .options import ReachabilityReviewOptions
from .source_context import _read_function_body, _read_line_context

logger = logging.getLogger("metis")

_MAX_CONTEXT_CHARS = 36000
_MAX_RELATED_FUNCTIONS = 14
_MAX_PATHS = 10
_RELATED_FUNCTION_CHARS = 2600
_TARGET_FUNCTION_CHARS = 7000


@dataclass(frozen=True, slots=True)
class ReachabilityTriageRequest:
    message: str
    file_path: str
    line: int
    rule_id: str = ""
    snippet: str = ""
    source_tool: str = ""
    explanation: str = ""


class ReachabilityTriageRunner:
    def __init__(
        self,
        llm_provider,
        model: str,
        usage_runtime,
        codebase_path: str,
        *,
        options: ReachabilityReviewOptions,
        chat_model_kwargs: dict[str, Any] | None = None,
        model_tools: tuple[Any, ...] = (),
        max_tool_rounds: int | None = None,
    ):
        self._model = model
        self._codebase_path = codebase_path
        self._options = options
        self._chat_model_kwargs = dict(chat_model_kwargs or {})
        self._model_tools = tuple(model_tools or ())
        self._max_tool_rounds = max_tool_rounds
        self._runner = JsonPromptRunner(llm_provider, usage_runtime)

    def triage(self, finding: ReachabilityTriageRequest, graph) -> dict[str, Any]:
        context = self._build_context(finding, graph)
        decision = self._invoke_decision(
            finding,
            context,
            model_tools=self._model_tools,
            max_tool_rounds=self._max_tool_rounds,
            label="Reachability triage",
        )
        if decision is None and self._model_tools:
            decision = self._invoke_decision(
                finding,
                context,
                model_tools=(),
                max_tool_rounds=None,
                label="Reachability triage structured fallback",
            )
        if decision is None:
            decision = TriageDecisionModel(
                status="inconclusive",
                reason="Reachability triage did not return a valid decision payload.",
                evidence=[],
                resolution_chain=[],
                unresolved_hops=["reachability triage response parsing failed"],
            )
        return _decision_dict(decision)

    def _invoke_decision(
        self,
        finding: ReachabilityTriageRequest,
        context: str,
        *,
        model_tools: tuple[Any, ...],
        max_tool_rounds: int | None,
        label: str,
    ) -> TriageDecisionModel | None:
        return self._runner.invoke(
            JsonPromptRequest(
                model=self._model,
                max_tokens=5000,
                temperature=0.1,
                system_prompt=_SYSTEM_PROMPT,
                user_prompt=_USER_PROMPT,
                variables={
                    "finding": _finding_section(finding),
                    "reachability_context": context,
                },
                parse=_parse_triage_decision,
                logger=logger,
                label=label,
                batch_size=1,
                invalid_message="expected triage decision JSON object",
                final_keep_message="marking finding inconclusive",
                response_model=TriageDecisionModel,
                reasoning_effort=self._options.reasoning_effort,
                chat_model_kwargs=self._chat_model_kwargs,
                model_tools=model_tools,
                max_tool_rounds=max_tool_rounds,
            )
        )

    def _build_context(self, finding: ReachabilityTriageRequest, graph) -> str:
        target = _target_node_for_finding(graph, finding.file_path, finding.line)
        reverse_edges = _build_reverse_edges(graph, partial(_node_sort_key, graph))
        focus = FileFocusBuilder(
            graph,
            max_path_length=self._options.max_path_length,
            max_incoming_paths=self._options.max_paths
            if self._options.max_paths > 0
            else None,
        ).build(finding.file_path)

        sections = [
            "== REPORTED LINE CONTEXT ==\n"
            + (
                _read_line_context(
                    self._codebase_path,
                    finding.file_path,
                    finding.line,
                    context=6,
                    max_chars=2400,
                )
                or "<unavailable>"
            )
        ]

        if finding.snippet:
            sections.append(f"== FINDING SNIPPET ==\n{finding.snippet}")
        if finding.explanation:
            sections.append(f"== FINDING EXPLANATION ==\n{finding.explanation}")

        if target is not None:
            sections.append(
                "== TARGET FUNCTION ==\n"
                f"{target.unique_name} (line {target.line_number})\n"
                + (
                    _read_function_body(
                        self._codebase_path,
                        target,
                        max_chars=_TARGET_FUNCTION_CHARS,
                    )
                    or "<unavailable>"
                )
            )
            sections.append(_relationship_section(graph, target, reverse_edges))
            paths = _paths_for_target(focus, target.unique_name)
            if paths:
                sections.append(_paths_section(graph, paths))
            related_nodes = _related_nodes(graph, target, reverse_edges, paths)
            related_context = _related_functions_section(
                self._codebase_path,
                related_nodes,
            )
            if related_context:
                sections.append(related_context)
        else:
            file_nodes = graph.get_file_nodes(finding.file_path)
            if file_nodes:
                sections.append(
                    "== FILE FUNCTIONS NEAR FINDING ==\n"
                    + _related_functions_section(
                        self._codebase_path,
                        _nearest_nodes(
                            file_nodes, finding.line, _MAX_RELATED_FUNCTIONS
                        ),
                    )
                )
            else:
                sections.append("== TREE-SITTER TARGET ==\nNo function node found.")

        globals_section = _globals_section(graph, finding.file_path)
        if globals_section:
            sections.append(globals_section)

        return _clip_sections(sections, max_chars=_MAX_CONTEXT_CHARS)


def _target_node_for_finding(graph, file_path: str, line: int):
    nodes = graph.get_file_nodes(file_path)
    if not nodes:
        return None
    line = max(1, int(line or 1))
    before = [node for node in nodes if int(node.line_number or 0) <= line]
    if before:
        return max(before, key=lambda node: int(node.line_number or 0))
    return min(nodes, key=lambda node: abs(int(node.line_number or 0) - line))


def _relationship_section(graph, target, reverse_edges: dict[str, list[str]]) -> str:
    callers = [
        name
        for name in reverse_edges.get(target.unique_name, [])
        if graph.get_node(name)
    ]
    callees = [name for name in target.resolved_calls or [] if graph.get_node(name)]
    unresolved = graph.unresolved_calls_for(target)
    parts = [
        "== GRAPH RELATIONSHIPS ==",
        f"target: {target.unique_name}",
        "direct_callers: " + (", ".join(callers[:12]) if callers else "<none>"),
        "direct_callees: " + (", ".join(callees[:12]) if callees else "<none>"),
        "unresolved_calls: " + (", ".join(unresolved[:12]) if unresolved else "<none>"),
    ]
    return "\n".join(parts)


def _paths_for_target(focus, target_name: str):
    out = []
    for path in list(focus.incoming_paths or []) + list(
        focus.outgoing_context_paths or []
    ):
        if target_name in (path.path or []):
            out.append(path)
        if len(out) >= _MAX_PATHS:
            break
    return out


def _paths_section(graph, paths) -> str:
    lines = ["== REACHABILITY PATHS =="]
    for index, path in enumerate(paths):
        lines.append(f"Path {index}: {' -> '.join(path.path or [])}")
        for name in path.path or []:
            node = graph.get_node(name)
            if not node:
                continue
            marker = []
            if node.is_source:
                marker.append(f"source={node.source_reason or 'source'}")
            if node.is_sink:
                marker.append(f"sink={node.sink_type or 'sink'}")
            suffix = f" [{' | '.join(marker)}]" if marker else ""
            lines.append(
                f"  - {node.unique_name} {node.file_path}:{node.line_number}{suffix}"
            )
    return "\n".join(lines)


def _related_nodes(graph, target, reverse_edges, paths) -> list[Any]:
    names: list[str] = []
    for name in reverse_edges.get(target.unique_name, []):
        names.append(name)
    names.extend(target.resolved_calls or [])
    for path in paths:
        names.extend(path.path or [])
    out = []
    seen = {target.unique_name}
    for name in names:
        if name in seen:
            continue
        node = graph.get_node(name)
        if node is None:
            continue
        seen.add(name)
        out.append(node)
        if len(out) >= _MAX_RELATED_FUNCTIONS:
            break
    return out


def _nearest_nodes(nodes, line: int, limit: int):
    return sorted(
        nodes,
        key=lambda node: (abs(int(node.line_number or 0) - int(line or 1)), node.name),
    )[:limit]


def _related_functions_section(codebase_path: str, nodes) -> str:
    parts = []
    for node in nodes:
        body = _read_function_body(
            codebase_path,
            node,
            max_chars=_RELATED_FUNCTION_CHARS,
        )
        if not body:
            continue
        parts.append(f"--- {node.unique_name} (line {node.line_number}) ---\n{body}")
    if not parts:
        return ""
    return "== RELATED FUNCTION CONTEXT ==\n" + "\n\n".join(parts)


def _globals_section(graph, file_path: str) -> str:
    entries = []
    for item in graph.get_globals():
        if item.file_path != file_path:
            continue
        refs = ", ".join(item.referenced_functions or [])
        entries.append(
            f"{item.unique_name} line {item.line_number}\n"
            f"initializer: {item.initializer[:900]}\n"
            f"referenced_functions: {refs}"
        )
        if len(entries) >= 8:
            break
    if not entries:
        return ""
    return "== GLOBALS IN TARGET FILE ==\n" + "\n\n".join(entries)


def _clip_sections(sections: list[str], *, max_chars: int) -> str:
    out = []
    total = 0
    for section in sections:
        text = str(section or "").strip()
        if not text:
            continue
        remaining = max_chars - total
        if remaining <= 0:
            break
        if len(text) > remaining:
            out.append(text[:remaining].rstrip() + "\n[context truncated]")
            break
        out.append(text)
        total += len(text) + 2
    return "\n\n".join(out)


def _finding_section(finding: ReachabilityTriageRequest) -> str:
    fields = [
        ("source_tool", finding.source_tool),
        ("rule_id", finding.rule_id),
        ("file", finding.file_path),
        ("line", str(finding.line)),
        ("message", finding.message),
    ]
    return "\n".join(f"{key}: {value}" for key, value in fields if value)


def _parse_triage_decision(raw) -> TriageDecisionModel | None:
    if isinstance(raw, TriageDecisionModel):
        return raw
    payload = raw
    if hasattr(raw, "model_dump"):
        payload = raw.model_dump()
    elif isinstance(raw, str):
        payload = parse_json_output(raw)
    if not isinstance(payload, dict):
        return None
    payload = _normalize_decision_payload(payload)
    try:
        return TriageDecisionModel(**payload)
    except Exception:
        return None


def _normalize_decision_payload(payload: dict[str, Any]) -> dict[str, Any]:
    normalized = {
        "status": (
            payload.get("status")
            or payload.get("verdict")
            or payload.get("decision")
            or ""
        ),
        "reason": (
            payload.get("reason")
            or payload.get("justification")
            or payload.get("rationale")
            or payload.get("explanation")
            or ""
        ),
        "evidence": payload.get("evidence") or payload.get("citations") or [],
        "resolution_chain": (
            payload.get("resolution_chain")
            or payload.get("chain")
            or payload.get("path")
            or []
        ),
        "unresolved_hops": (
            payload.get("unresolved_hops")
            or payload.get("missing_evidence")
            or payload.get("unresolved")
            or []
        ),
    }
    status = str(normalized.get("status") or "").strip().lower()
    if status in {"true_positive", "confirmed"}:
        status = "valid"
    elif status in {"false_positive", "refuted", "not_valid"}:
        status = "invalid"
    if status:
        normalized["status"] = status
    reason = str(normalized.get("reason") or "").strip()
    normalized["reason"] = reason or "No reachability triage reason provided."
    for key in ("evidence", "resolution_chain", "unresolved_hops"):
        normalized[key] = _coerce_string_list(normalized.get(key))
    if normalized.get("status") == "valid" and not normalized.get("evidence"):
        normalized["evidence"] = _extract_file_line_citations(reason)
    if normalized.get("status") == "valid" and not normalized.get("evidence"):
        normalized["status"] = "inconclusive"
        normalized["unresolved_hops"] = list(
            normalized.get("unresolved_hops") or []
        ) + ["valid verdict did not include concrete evidence"]
    if normalized.get("status") == "valid" and not normalized.get("resolution_chain"):
        normalized["resolution_chain"] = [
            "reported finding -> cited reachability evidence"
        ]
    if normalized.get("status") == "inconclusive" and not normalized.get(
        "unresolved_hops"
    ):
        normalized["unresolved_hops"] = ["reachability evidence remains unresolved"]
    return normalized


def _coerce_string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        text = value.strip()
        return [text] if text else []
    if not isinstance(value, list):
        text = str(value).strip()
        return [text] if text else []
    out = []
    for item in value:
        if isinstance(item, dict):
            file_name = str(item.get("file") or item.get("path") or "").strip()
            line = str(item.get("line") or "").strip()
            text = f"{file_name}:{line}" if file_name and line else str(item)
        else:
            text = str(item)
        text = text.strip()
        if text:
            out.append(text)
    return out


def _extract_file_line_citations(text: str) -> list[str]:
    return re.findall(r"\b[\w./+-]+\.[A-Za-z0-9_+.-]+:\d+\b", text or "")


def _decision_dict(decision: TriageDecisionModel) -> dict[str, Any]:
    unresolved_hops = list(decision.unresolved_hops or [])
    return {
        "status": decision.status,
        "reason": decision.reason,
        "evidence": list(decision.evidence or []),
        "resolution_chain": list(decision.resolution_chain or []),
        "unresolved_hops": unresolved_hops,
        "evidence_obligations": ["reachability_context"],
        "evidence_coverage": {"reachability_context": 1},
        "missing_evidence": unresolved_hops
        if decision.status == "inconclusive"
        else [],
    }


_SYSTEM_PROMPT = """\
You triage one C/C++ static-analysis finding using tree-sitter reachability context.
Do not discover new findings. Decide only whether the reported finding is valid,
invalid, or inconclusive for the shown codebase.

Use the reachability graph context as primary evidence:
- reported line and enclosing function
- direct callers, wrappers, callees, and unresolved calls
- source-to-target or target-to-sink paths when available
- globals, registration tables, callback tables, and initializers

You may call navigation tools when the context is missing a concrete definition,
macro, guard, caller, wrapper, table registration, build/config gate, or nearby line.
Keep navigation calls narrow and cite file:line evidence.

Verdict rules:
- valid: the reported defect is present and reachable through the shown caller,
  wrapper, table, or path context.
- invalid: shown evidence directly contradicts the claim, proves a guarding
  precondition, or shows the claimed path/use is not reachable.
- inconclusive: a required caller, wrapper, entrypoint, macro, build gate, or
  input-provenance hop remains unresolved.

Return exactly one JSON object matching this schema:
- status: exactly one of "valid", "invalid", or "inconclusive"
- reason: non-empty concise justification
- evidence: array of concrete file:line citations supporting the verdict
- resolution_chain: array of static-analysis hops from the reported claim to evidence
- unresolved_hops: array of missing callers, wrappers, aliases, macros, build gates,
  entrypoints, or provenance gaps; non-empty when status is "inconclusive"

Return JSON only. Do not wrap it in markdown."""

_USER_PROMPT = """\
Reported finding:
{finding}

Reachability context:
{reachability_context}
"""
