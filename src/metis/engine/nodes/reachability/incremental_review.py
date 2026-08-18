# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import json
import logging
import os
from collections import defaultdict
from collections import deque
from collections.abc import Mapping
from collections.abc import Sequence
from dataclasses import dataclass
from dataclasses import replace
from functools import partial
from typing import TYPE_CHECKING
from typing import Any
from typing import Literal
from typing import cast

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field
from pydantic import ValidationError

from metis.engine.codegraph import CodeGraph
from metis.engine.codegraph import FunctionNode
from metis.engine.concurrency import run_jobs
from metis.engine.llm_runner import JsonPromptRequest
from metis.engine.llm_runner import JsonPromptRunner
from metis.engine.llm_runner import rendered_prompt_token_count
from metis.engine.nodes.simple_llm_review.prompt import build_review_system_prompt
from metis.engine.nodes.simple_llm_review.schema import ReviewIssueModel
from metis.engine.nodes.simple_llm_review.schema import review_schema_prompt
from metis.engine.prompt_catalog import get_engine_prompts
from metis.engine.source import SourceMap
from metis.engine.threat_context_retrieval import format_threat_model_context
from metis.engine.threat_context_retrieval import get_threat_model_context
from metis.engine.threat_context_retrieval import threat_model_review_scope_guidance
from metis.usage import usage_operation
from metis.utils import parse_json_output

from . import finding_admission
from . import prompt_evidence
from .domain import FrontierReviewFailure
from .domain import VulnerabilityFinding
from .domain_hints import format_domain_hints_for_prompt
from .domain_hints import normalize_domain_hints
from .finding_adapter import review_item_to_finding
from .graph_utils import _node_sort_key
from .graph_utils import function_for_location
from .options import ReachabilityReviewOptions
from .progress import ReachabilityProgress as Progress
from .progress import emit_progress
from .source_context import _build_file_grouped_node_chunks
from .state import FunctionContract
from .state import TrackedObjectSubject
from .state import augment_function_contracts

if TYPE_CHECKING:
    from metis.engine.repository import EngineRepository
    from metis.engine.runtime import EngineConfig
    from metis.memory import MemoryService

logger = logging.getLogger(__name__)

_SOURCE_PLACEHOLDER = "[[METIS_FRONTIER_SOURCE]]"
_PROMPTS = get_engine_prompts("reachability_incremental_review")


class _NecessaryConditionModel(BaseModel):
    call_result_index: int = Field(ge=0)

    model_config = ConfigDict(extra="forbid", frozen=True)


class _NecessaryConditionAlternativeModel(BaseModel):
    sink_call_index: int = Field(ge=0)
    all_of: list[_NecessaryConditionModel] = Field(min_length=1)

    model_config = ConfigDict(extra="forbid", frozen=True)


class _ReachabilityReviewIssueModel(ReviewIssueModel):
    necessary_condition_alternatives: list[_NecessaryConditionAlternativeModel]

    model_config = ConfigDict(extra="forbid", frozen=True)


class _DiscoveryReviewResponseModel(BaseModel):
    reviews: list[_ReachabilityReviewIssueModel] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid", frozen=True)


@dataclass(frozen=True, slots=True)
class FrontierReviewStats:
    planned_node_count: int
    reviewed_node_count: int
    represented_edge_count: int
    packet_count: int
    contradicted_finding_count: int = 0


@dataclass(frozen=True, slots=True)
class FrontierReviewOutcome:
    findings: tuple[VulnerabilityFinding, ...]
    stats: FrontierReviewStats
    failures: tuple[FrontierReviewFailure, ...] = ()

    @property
    def failed_node_ids(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(failure.function_id for failure in self.failures))


@dataclass(frozen=True, slots=True)
class _FrontierPacket:
    index: int
    graph: CodeGraph
    file_path: str
    nodes: tuple[FunctionNode, ...]
    system_prompt: str
    body_text: str
    shown_lines: frozenset[int]
    cache_key: str
    model: str
    reasoning_effort: str | None


@dataclass(frozen=True, slots=True)
class _PacketResponse:
    index: int
    analysis: _PacketAnalysis | None
    failure_kind: Literal["invalid_output", "provider_error"] | None = None


@dataclass(frozen=True, slots=True)
class _FrontierResponses:
    packets: tuple[_FrontierPacket, ...]
    responses: dict[int, _PacketResponse]
    failures: frozenset[FrontierReviewFailure]
    packet_count: int


@dataclass(frozen=True, slots=True)
class _PacketAnalysis:
    reviews: tuple[dict[str, Any], ...]


def _unique_packet_schedule(
    packets: Sequence[_FrontierPacket],
) -> tuple[list[_FrontierPacket], dict[int, int]]:
    representatives: dict[str, _FrontierPacket] = {}
    representative_by_index: dict[int, int] = {}
    for packet in packets:
        representative = representatives.setdefault(packet.cache_key, packet)
        representative_by_index[packet.index] = representative.index
    return list(representatives.values()), representative_by_index


def _fan_out_packet_results(
    packets: Sequence[_FrontierPacket],
    responses: Sequence[_PacketResponse],
    representative_by_index: Mapping[int, int],
) -> dict[int, _PacketResponse]:
    representative_responses = {response.index: response for response in responses}
    return {
        packet.index: replace(response, index=packet.index)
        for packet in packets
        if (
            response := representative_responses.get(
                representative_by_index[packet.index]
            )
        )
        is not None
    }


class IncrementalGraphReviewer:
    def __init__(
        self,
        config: EngineConfig,
        repository: EngineRepository,
        llm_provider: Any,
        usage_runtime: Any,
    ) -> None:
        self._config = config
        self._repository = repository
        self._llm_provider = llm_provider
        self._runner = JsonPromptRunner(llm_provider, usage_runtime)
        self._schema_prompt = review_schema_prompt()
        self._discovery_schema_json = json.dumps(
            _DiscoveryReviewResponseModel.model_json_schema(),
            sort_keys=True,
            separators=(",", ":"),
        )

    def review(
        self,
        graph: CodeGraph,
        *,
        options: ReachabilityReviewOptions,
        memory_service: MemoryService | None = None,
        evidence_graph: CodeGraph | None = None,
    ) -> FrontierReviewOutcome:
        discovery_graph = evidence_graph or graph
        node_ids = tuple(sorted(graph.nodes, key=partial(_node_sort_key, graph)))
        represented_edges = {
            (node.unique_name, callee)
            for node in graph.nodes.values()
            for callee in node.resolved_calls
            if callee in graph.nodes
        }
        emit_progress(
            options.progress_callback,
            Progress.FRONTIER_REVIEW_START,
            frontiers=1,
            nodes=len(node_ids),
            edges=len(represented_edges),
        )
        contracts = augment_function_contracts(graph)
        packets, build_failures = self._build_packets(
            graph,
            node_ids,
            options=options,
            memory_service=memory_service,
            evidence_graph=discovery_graph,
            contracts=contracts,
        )
        responses = self._review_frontier_packets(
            graph,
            node_ids,
            packets,
            options=options,
            memory_service=memory_service,
            evidence_graph=discovery_graph,
            contracts=contracts,
        )
        failures = set(build_failures)
        failures.update(responses.failures)
        findings_by_id: dict[str, VulnerabilityFinding] = {}
        necessary_alternatives_by_id: dict[
            str,
            tuple[finding_admission._GroundedNecessaryAlternative, ...],
        ] = {}
        statuses: dict[str, list[bool]] = defaultdict(list)
        for packet in responses.packets:
            response = responses.responses.get(packet.index)
            succeeded = response is not None and response.analysis is not None
            for node in packet.nodes:
                statuses[node.unique_name].append(succeeded)
            if not succeeded or response is None or response.analysis is None:
                continue
            for finding, alternatives in self._anchor_reviews(
                graph,
                packet,
                response.analysis.reviews,
            ):
                findings_by_id[finding.id] = finding
                necessary_alternatives_by_id[finding.id] = alternatives

        failed_node_ids = {
            node_id
            for node_id in node_ids
            if not statuses.get(node_id) or not all(statuses[node_id])
        }
        failed_node_ids.update(failure.function_id for failure in failures)
        admitted_ids, contradicted_finding_count = (
            finding_admission._admitted_finding_ids(
                graph,
                findings_by_id,
                necessary_alternatives_by_id,
                contracts,
            )
        )
        findings = tuple(
            finding
            for finding_id, finding in findings_by_id.items()
            if finding_id in admitted_ids
        )
        ordered_failures = tuple(
            sorted(
                failures,
                key=lambda failure: (
                    _node_sort_key(graph, failure.function_id),
                    failure.kind,
                ),
            )
        )
        stats = FrontierReviewStats(
            planned_node_count=len(node_ids),
            reviewed_node_count=len(set(node_ids) - failed_node_ids),
            represented_edge_count=len(represented_edges),
            packet_count=responses.packet_count,
            contradicted_finding_count=contradicted_finding_count,
        )
        emit_progress(
            options.progress_callback,
            Progress.FRONTIER_REVIEW_DONE,
            frontiers=1,
            planned_nodes=stats.planned_node_count,
            reviewed_nodes=stats.reviewed_node_count,
            represented_edges=stats.represented_edge_count,
            packets=stats.packet_count,
            contradicted_findings=stats.contradicted_finding_count,
            findings=len(findings),
            failed_nodes=len(failed_node_ids),
            operational_failures=[
                {
                    "function_id": failure.function_id,
                    "kind": failure.kind,
                }
                for failure in ordered_failures
            ],
        )
        return FrontierReviewOutcome(
            findings=findings,
            stats=stats,
            failures=ordered_failures,
        )

    def _review_frontier_packets(
        self,
        graph: CodeGraph,
        node_ids: tuple[str, ...],
        initial_packets: list[_FrontierPacket],
        *,
        options: ReachabilityReviewOptions,
        memory_service: MemoryService | None,
        evidence_graph: CodeGraph | None = None,
        contracts: Mapping[str, FunctionContract] | None = None,
    ) -> _FrontierResponses:
        pending = list(initial_packets)
        leaf_packets: list[_FrontierPacket] = []
        leaf_responses: dict[int, _PacketResponse] = {}
        failures: set[FrontierReviewFailure] = set()
        packet_count = 0
        next_index = max((packet.index for packet in pending), default=-1) + 1

        while pending:
            unique_scheduled, representative_by_index = _unique_packet_schedule(pending)
            responses = run_jobs(
                unique_scheduled,
                self._review_packet,
                max_workers=options.max_workers,
                label="Reachability security review",
                result_key=lambda packet: packet.index,
            )
            responses_by_index = _fan_out_packet_results(
                pending,
                responses,
                representative_by_index,
            )
            packet_count += len(responses)
            child_packets: list[_FrontierPacket] = []
            for packet in pending:
                response = responses_by_index.get(packet.index)
                invalid_output = (
                    response is not None
                    and response.analysis is None
                    and response.failure_kind == "invalid_output"
                    and len(packet.nodes) > 1
                )
                if not invalid_output:
                    leaf_packets.append(packet)
                    if response is not None:
                        leaf_responses[packet.index] = response
                        if response.failure_kind is not None:
                            failures.update(
                                FrontierReviewFailure(
                                    node.unique_name, response.failure_kind
                                )
                                for node in packet.nodes
                            )
                    continue
                midpoint = len(packet.nodes) // 2
                for nodes in (
                    packet.nodes[:midpoint],
                    packet.nodes[midpoint:],
                ):
                    children, child_failures = self._build_packets(
                        graph,
                        node_ids,
                        options=options,
                        memory_service=memory_service,
                        selected_node_ids={node.unique_name for node in nodes},
                        evidence_graph=evidence_graph,
                        contracts=contracts,
                    )
                    failures.update(child_failures)
                    for child in children:
                        child_packets.append(replace(child, index=next_index))
                        next_index += 1
            pending = child_packets

        return _FrontierResponses(
            packets=tuple(leaf_packets),
            responses=leaf_responses,
            failures=frozenset(failures),
            packet_count=packet_count,
        )

    def _build_packets(
        self,
        graph: CodeGraph,
        node_ids: tuple[str, ...],
        *,
        options: ReachabilityReviewOptions,
        memory_service: MemoryService | None,
        selected_node_ids: set[str] | None = None,
        evidence_graph: CodeGraph | None = None,
        contracts: Mapping[str, FunctionContract] | None = None,
    ) -> tuple[list[_FrontierPacket], set[FrontierReviewFailure]]:
        discovery_graph = evidence_graph or graph
        nodes = [
            node
            for node_id in node_ids
            if selected_node_ids is None or node_id in selected_node_ids
            if (node := graph.get_node(node_id)) is not None
        ]
        candidate_node_ids = {node.unique_name for node in nodes}
        nodes_by_file: dict[str, list[FunctionNode]] = defaultdict(list)
        for node in nodes:
            nodes_by_file[node.file_path].append(node)

        packets: list[_FrontierPacket] = []
        scheduled_node_ids: set[str] = set()
        failures: set[FrontierReviewFailure] = set()
        for file_path in sorted(nodes_by_file):
            file_nodes = sorted(
                nodes_by_file[file_path],
                key=partial(_node_sort_key, graph),
            )
            system_prompt = self._system_prompt(
                file_path,
                options,
            )
            threat_sections = self._threat_sections(memory_service, file_path)
            model = options.confirmation_model or self._config.llama_query_model
            response_schema_json = self._discovery_schema_json
            pending_groups: deque[list[FunctionNode]] = deque((file_nodes,))
            while pending_groups:
                group_nodes = pending_groups.popleft()
                body_template = self._render_discovery_body(
                    discovery_graph,
                    group_nodes,
                    file_path=file_path,
                    source_text=_SOURCE_PLACEHOLDER,
                    threat_sections=threat_sections,
                    contracts=contracts,
                )
                chunks: list[tuple[list[FunctionNode], str]] = []
                overflow_error: RuntimeError | ValueError | None = None
                try:
                    source_token_budget = self._source_token_budget(
                        system_prompt,
                        body_template,
                        response_schema_json,
                    )
                except RuntimeError as exc:
                    overflow_error = exc
                if overflow_error is None:
                    try:
                        chunks = _build_file_grouped_node_chunks(
                            self._config.codebase_path,
                            group_nodes,
                            max_tokens=source_token_budget,
                            token_counter=self._llm_provider.count_tokens,
                        )
                    except ValueError as exc:
                        overflow_error = exc
                if overflow_error is not None:
                    if len(group_nodes) > 1:
                        midpoint = len(group_nodes) // 2
                        for child_nodes in reversed(
                            (group_nodes[:midpoint], group_nodes[midpoint:])
                        ):
                            pending_groups.appendleft(child_nodes)
                        continue
                    logger.warning(
                        "%s for %s; leaving %s incomplete",
                        overflow_error,
                        file_path,
                        group_nodes[0].unique_name,
                    )
                    failures.add(
                        FrontierReviewFailure(
                            function_id=group_nodes[0].unique_name,
                            kind="context_overflow",
                        )
                    )
                    continue
                for chunk_nodes, source_text in chunks:
                    packet_node_ids = tuple(node.unique_name for node in chunk_nodes)
                    body_text = self._render_discovery_body(
                        discovery_graph,
                        chunk_nodes,
                        file_path=file_path,
                        source_text=source_text,
                        threat_sections=threat_sections,
                        contracts=contracts,
                    )
                    if (
                        self._rendered_token_count(
                            system_prompt,
                            body_text,
                            response_schema_json,
                        )
                        > self._config.max_token_length
                    ):
                        logger.warning(
                            "Incremental graph context exceeds the global model "
                            "input limit for %s; leaving %d function(s) incomplete",
                            file_path,
                            len(chunk_nodes),
                        )
                        failures.update(
                            FrontierReviewFailure(
                                function_id=node.unique_name,
                                kind="context_overflow",
                            )
                            for node in chunk_nodes
                        )
                        continue
                    cache_key = self._cache_key(
                        system_prompt,
                        body_text,
                        model=model,
                        reasoning_effort=options.reasoning_effort,
                        response_schema_json=response_schema_json,
                    )
                    packets.append(
                        _FrontierPacket(
                            index=len(packets),
                            graph=graph,
                            file_path=file_path,
                            nodes=tuple(chunk_nodes),
                            system_prompt=system_prompt,
                            body_text=body_text,
                            shown_lines=prompt_evidence._shown_lines(source_text),
                            cache_key=cache_key,
                            model=model,
                            reasoning_effort=options.reasoning_effort,
                        )
                    )
                    scheduled_node_ids.update(packet_node_ids)
        failed_node_ids = {failure.function_id for failure in failures}
        failures.update(
            FrontierReviewFailure(
                function_id=node_id,
                kind="missing_source",
            )
            for node_id in candidate_node_ids - scheduled_node_ids
            if node_id not in failed_node_ids
        )
        return packets, failures

    def _system_prompt(
        self,
        file_path: str,
        options: ReachabilityReviewOptions,
    ) -> str:
        absolute_path = os.path.join(self._config.codebase_path, file_path)
        plugin = self._repository.get_plugin_for_path(absolute_path)
        if plugin is None:
            raise RuntimeError(f"No review prompt is available for {file_path}")
        language_prompts = plugin.get_prompts()
        report_prompt = self._config.plugin_config.get("general_prompts", {}).get(
            "security_review_report", ""
        )
        review_prompt = build_review_system_prompt(
            language_prompts,
            "security_review_file",
            report_prompt,
            self._config.custom_prompt_text,
            self._config.custom_guidance_precedence,
            self._schema_prompt,
        )
        system_prompt = f"{review_prompt}\n\n{_PROMPTS['discovery_graph_guidance']}"
        domain_hints = format_domain_hints_for_prompt(
            normalize_domain_hints(options.domain_hints, options.domain_profiles)
        )
        if domain_hints:
            return f"{system_prompt}\n\n{domain_hints}"
        return system_prompt

    def _threat_sections(
        self,
        memory_service: MemoryService | None,
        file_path: str,
    ) -> tuple[str, ...]:
        records = get_threat_model_context(memory_service, path=file_path)
        context = format_threat_model_context(records)
        guidance = threat_model_review_scope_guidance(records)
        sections: list[str] = []
        if context:
            sections.extend(("THREAT_MODEL_CONTEXT:", context, ""))
        if guidance:
            sections.extend(("THREAT_MODEL_SCOPE_GUIDANCE:", guidance, ""))
        return tuple(sections)

    def _source_token_budget(
        self,
        system_prompt: str,
        body_template: str,
        response_schema_json: str,
    ) -> int:
        prefix, marker, suffix = body_template.rpartition(_SOURCE_PLACEHOLDER)
        if not marker:
            raise RuntimeError("Incremental graph source template is invalid")
        fixed_tokens = self._rendered_token_count(
            system_prompt,
            f"{prefix}{suffix}",
            response_schema_json,
        )
        available = self._config.max_token_length - fixed_tokens
        if available <= 0:
            raise RuntimeError(
                "Incremental graph context exceeds the global model input limit"
            )
        return available

    def _rendered_token_count(
        self,
        system_prompt: str,
        body_text: str,
        response_schema_json: str,
    ) -> int:
        return rendered_prompt_token_count(
            self._llm_provider.count_tokens,
            system_prompt=system_prompt,
            user_prompt="{body_text}",
            variables={"body_text": body_text},
        ) + self._llm_provider.count_tokens(response_schema_json)

    def _render_discovery_body(
        self,
        graph: CodeGraph,
        nodes: Sequence[FunctionNode],
        *,
        file_path: str,
        source_text: str,
        threat_sections: tuple[str, ...],
        contracts: Mapping[str, FunctionContract] | None = None,
    ) -> str:
        evidence = prompt_evidence._compact_source_evidence(
            prompt_evidence._codegraph_evidence_data(
                graph,
                nodes,
                contracts,
                shown_lines=prompt_evidence._shown_lines(source_text),
                file_path=file_path,
            ),
            codebase_path=self._config.codebase_path,
            file_path=file_path,
            source_text=source_text,
        )
        return "\n".join(
            (
                f"FILE: {file_path}",
                *threat_sections,
                _PROMPTS["omission_convention"],
                "CODEGRAPH_EVIDENCE (untrusted JSON):",
                prompt_evidence._prompt_json(evidence),
                "",
                "SNIPPET:",
                source_text,
                "",
            )
        )

    def _review_packet(self, packet: _FrontierPacket) -> _PacketResponse:
        validation_failed = False
        output_limited = False

        def validate(raw: object) -> _PacketAnalysis | None:
            nonlocal validation_failed
            validated = self._validated_packet_analysis(packet, raw)
            if validated is None:
                validation_failed = True
            return validated

        def mark_output_limit() -> None:
            nonlocal output_limited
            output_limited = True

        with usage_operation("review_discovery"):
            analysis = self._runner.invoke(
                JsonPromptRequest(
                    model=packet.model,
                    system_prompt=packet.system_prompt,
                    user_prompt="{body_text}",
                    variables={"body_text": packet.body_text},
                    parse=validate,
                    logger=logger,
                    label="Reachability security review",
                    batch_size=len(packet.nodes),
                    invalid_message="expected grounded review JSON",
                    final_keep_message="leaving this review packet incomplete",
                    response_model=_DiscoveryReviewResponseModel,
                    reasoning_effort=packet.reasoning_effort,
                    chat_model_kwargs=self._config.chat_model_kwargs,
                    on_output_limit=mark_output_limit,
                )
            )
        if isinstance(analysis, _PacketAnalysis):
            return _PacketResponse(packet.index, analysis)
        failure_kind: Literal["invalid_output", "provider_error"] = (
            "invalid_output"
            if validation_failed or output_limited
            else "provider_error"
        )
        return _PacketResponse(packet.index, None, failure_kind)

    def _validated_packet_analysis(
        self,
        packet: _FrontierPacket,
        raw: object,
    ) -> _PacketAnalysis | None:
        discovery_response = _parse_review_response(
            raw,
            _DiscoveryReviewResponseModel,
        )
        if discovery_response is None:
            return None
        call_result_count = len(
            prompt_evidence._call_result_entries(
                packet.graph,
                tuple(node.unique_name for node in packet.nodes),
                shown_lines=packet.shown_lines,
            )
        )
        reviews = tuple(
            item.model_dump(mode="json")
            for item in discovery_response.reviews
            if item.confidence > 0.0
        )
        for item in reviews:
            anchored = self._review_anchor(packet, item)
            if anchored is None:
                return None
            node, anchor = anchored
            if not _valid_necessary_condition_alternatives(
                item,
                call_result_count,
                node,
                anchor_start=anchor.start_line,
                anchor_end=anchor.end_line,
            ):
                return None
        return _PacketAnalysis(reviews=reviews)

    def _review_anchor(
        self,
        packet: _FrontierPacket,
        item: dict[str, Any],
    ) -> tuple[FunctionNode, Any] | None:
        source_map = SourceMap.for_file(self._config.codebase_path, packet.file_path)
        if source_map is None or not packet.shown_lines:
            return None
        hint = range(min(packet.shown_lines), max(packet.shown_lines) + 1)
        anchor = source_map.resolve_issue(
            snippet=str(item.get("code_snippet") or ""),
            start_line=item.get("start_line"),
            end_line=item.get("end_line"),
            hint=hint,
            context_text=f"{item.get('issue') or ''} {item.get('reasoning') or ''}",
        )
        shown_span = range(anchor.start_line, anchor.end_line + 1)
        if anchor.start_line <= 0 or any(
            line not in packet.shown_lines for line in shown_span
        ):
            return None
        matching_nodes = [
            node
            for node in packet.nodes
            if node.line_number <= anchor.start_line
            and anchor.end_line <= (node.end_line or node.line_number)
        ]
        if len(matching_nodes) != 1:
            return None
        return matching_nodes[0], anchor

    def _anchor_reviews(
        self,
        graph: CodeGraph,
        packet: _FrontierPacket,
        reviews: tuple[dict[str, Any], ...],
    ) -> list[
        tuple[
            VulnerabilityFinding,
            tuple[finding_admission._GroundedNecessaryAlternative, ...],
        ]
    ]:
        anchored: list[
            tuple[
                VulnerabilityFinding,
                tuple[finding_admission._GroundedNecessaryAlternative, ...],
            ]
        ] = []
        for review_index, raw_item in enumerate(reviews):
            item = dict(raw_item)
            resolved = self._review_anchor(packet, item)
            if resolved is None:
                raise RuntimeError("Validated frontier review lost its source anchor")
            packet_node, anchor = resolved
            node = function_for_location(
                graph,
                packet.file_path,
                anchor.start_line,
                symbol=packet_node.unique_name,
            )
            if node is None or node.unique_name != packet_node.unique_name:
                raise RuntimeError("Validated frontier review changed graph ownership")
            anchor = replace(anchor, symbol=node.unique_name)
            finding_id = f"local-{packet.cache_key[:12]}-{review_index}"
            path = [node.unique_name]
            call_result_entries = prompt_evidence._call_result_entries(
                packet.graph,
                tuple(node.unique_name for node in packet.nodes),
                shown_lines=packet.shown_lines,
            )
            necessary_alternatives = tuple(
                finding_admission._GroundedNecessaryAlternative(
                    sink_call_index=cast(int, alternative["sink_call_index"]),
                    conditions=tuple(
                        finding_admission._GroundedNecessaryCondition(
                            subject=cast(
                                TrackedObjectSubject,
                                call_result_entries[
                                    cast(int, condition["call_result_index"])
                                ][0],
                            ),
                        )
                        for condition in cast(
                            list[dict[str, object]], alternative["all_of"]
                        )
                    ),
                )
                for alternative in cast(
                    list[dict[str, object]],
                    item.pop("necessary_condition_alternatives"),
                )
            )
            canonical_key = prompt_evidence._finding_evidence_key(
                node,
                anchor.start_line,
                item,
            )
            item.update(
                {
                    "finding_id": finding_id,
                    "anchor": anchor.to_dict(),
                    "line_number": anchor.start_line,
                    "primary_file": node.file_path,
                    "primary_function": node.unique_name,
                    "analysis_type": "reachability_local",
                    "path": path,
                    "canonical_key": canonical_key,
                }
            )
            finding = review_item_to_finding(
                item,
                finding_id=finding_id,
            )
            anchored.append((finding, necessary_alternatives))
        return anchored

    def _cache_key(
        self,
        system_prompt: str,
        body_text: str,
        *,
        model: str,
        reasoning_effort: str | None,
        response_schema_json: str,
    ) -> str:
        payload = {
            "model": model,
            "reasoning_effort": reasoning_effort,
            "chat_model_kwargs": self._config.chat_model_kwargs,
            "system_prompt": system_prompt,
            "body_text": body_text,
            "response_schema": response_schema_json,
        }
        return hashlib.sha256(
            json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()


def _parse_review_response[ResponseModelT: BaseModel](
    raw: object,
    response_model: type[ResponseModelT],
) -> ResponseModelT | None:
    try:
        if isinstance(raw, response_model):
            return raw
        payload: object = raw
        if hasattr(raw, "model_dump"):
            payload = raw.model_dump()
        elif isinstance(raw, str):
            payload = parse_json_output(raw)
        if isinstance(payload, dict):
            return response_model.model_validate(payload)
    except (TypeError, ValueError, ValidationError):
        return None
    return None


def _valid_necessary_condition_alternatives(
    review: Mapping[str, object],
    call_result_count: int,
    node: FunctionNode,
    *,
    anchor_start: int,
    anchor_end: int,
) -> bool:
    alternatives = cast(
        list[dict[str, object]],
        review["necessary_condition_alternatives"],
    )
    calls = prompt_evidence._ordered_node_callsites(node)
    alternative_identities: list[tuple[int, tuple[int, ...]]] = []
    for alternative in alternatives:
        sink_call_index = cast(int, alternative["sink_call_index"])
        if not 0 <= sink_call_index < len(calls):
            return False
        selected_sink = calls[sink_call_index]
        if not anchor_start <= selected_sink.line <= anchor_end:
            return False
        conditions = cast(list[dict[str, object]], alternative["all_of"])
        identities = [
            cast(int, condition["call_result_index"]) for condition in conditions
        ]
        if any(
            not 0 <= call_result_index < call_result_count
            for call_result_index in identities
        ) or len(set(identities)) != len(identities):
            return False
        alternative_identities.append((sink_call_index, tuple(sorted(identities))))
    return len(set(alternative_identities)) == len(alternative_identities)
