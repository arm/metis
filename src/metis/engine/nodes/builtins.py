# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from metis.runtime_settings import TriageOptions

from ..capabilities.engine import EngineCapabilities
from ..llm_runner import JsonPromptRunner
from ..repository import EngineRepository
from ..runtime import EngineConfig
from ..stages.configuration import ExecutionConfiguration
from ..stages.service import ExecutionGraphService
from ..stages.triage.service import TriageService
from .codegraph import CodeGraphService
from .codegraph import registration as codegraph_node
from .compilation_profile import registration as compilation_profile_node
from .finding_dedup import registration as finding_dedup_node
from .index import registration as index_node
from .reachability import review as reachability_node
from .reachability.review import ReachabilityReviewService
from .reachability.service import ReachabilityService
from .result import review as review_result_node
from .result import triage as triage_result_node
from .simple_llm_review import registration as simple_llm_review_node
from .simple_llm_review.service import SimpleLlmReviewService
from .threat_model import registration as threat_model_node
from .triage import registration as triage_node
from .triage.service import TriageClassifierService

if TYPE_CHECKING:
    from ..capabilities.index import IndexCapability
    from .simple_llm_review.graph import ReviewGraph


@dataclass(frozen=True, slots=True)
class BuiltinExecution:
    execution: ExecutionGraphService
    triage_service: TriageService | None
    triage_classifier: TriageClassifierService | None


def build_builtin_execution(
    configuration: ExecutionConfiguration,
    *,
    engine_config: EngineConfig,
    repository: EngineRepository,
    capabilities: EngineCapabilities,
    codegraphs: CodeGraphService,
    reachability_settings: dict[str, object],
    triage_options: TriageOptions,
    triage_checkpoint_every: int,
    review_graph_factory: Callable[[IndexCapability | None, str | None], ReviewGraph],
) -> BuiltinExecution:
    selected_nodes = configuration.selected_nodes()
    static_registrations = (
        index_node.registration,
        codegraph_node.registration,
        finding_dedup_node,
        review_result_node.registration,
        triage_result_node.registration,
    )
    registrations = [
        registration
        for registration in static_registrations
        if (registration.stage, registration.name) in selected_nodes
    ]

    if ("initialize", "threat_model") in selected_nodes:
        registrations.append(threat_model_node.create_node(engine_config, repository))
    if ("initialize", "compilation_profile") in selected_nodes:
        registrations.append(compilation_profile_node.create_node(repository))

    simple_llm_review = None
    simple_review_selected = ("review", "simple_llm_review") in selected_nodes
    reachability_selected = ("review", "reachability") in selected_nodes
    if {
        ("review", "simple_llm_review"),
        ("review", "reachability"),
    } & selected_nodes:
        simple_llm_review = SimpleLlmReviewService(
            engine_config,
            repository,
            review_graph_factory=review_graph_factory,
        )
    if simple_review_selected:
        assert simple_llm_review is not None
        registrations.append(simple_llm_review_node.create_node(simple_llm_review))

    reachability = (
        ReachabilityService(
            config=engine_config,
            repository=repository,
            llm_provider=engine_config.llm_provider,
            usage_runtime=engine_config.usage_runtime,
        )
        if reachability_selected
        else None
    )
    if reachability_selected:
        assert reachability is not None
        reachability_review = ReachabilityReviewService(
            engine_config,
            repository,
            reachability,
            None if simple_review_selected else simple_llm_review,
            reachability_settings,
            supports_file=lambda path: (
                codegraphs.supports_file(path) and codegraphs.supports_semantics(path)
            ),
        )
        registrations.append(reachability_node.create_node(reachability_review))

    triage_service = (
        TriageService(
            triage_checkpoint_every=triage_checkpoint_every,
        )
        if configuration.stages.triage is not None
        else None
    )
    triage_classifier = None
    try:
        if ("triage", "triage") in selected_nodes:
            triage_classifier = TriageClassifierService(
                llm_provider=engine_config.llm_provider,
                model=engine_config.llama_query_model,
                chat_model_kwargs=engine_config.chat_model_kwargs,
                plugin_config=engine_config.plugin_config,
                get_plugin_for_path=repository.get_plugin_for_path,
                get_language_name_for_path=repository.get_language_name_for_path,
                normalize_path=repository.normalize_match_path,
                usage_hooks=engine_config.usage_runtime.hooks,
                model_tool_max_contract_chars=(
                    engine_config.capability_settings.model_tools.max_contract_chars
                ),
                navigation_manifest=capabilities.manifest("navigation"),
            )
            registrations.append(triage_node.create_node(triage_classifier))

        execution = ExecutionGraphService(
            configuration,
            engine_config=engine_config,
            repository=repository,
            capabilities=capabilities,
            prompt_runner=JsonPromptRunner(
                engine_config.llm_provider,
                engine_config.usage_runtime,
            ),
            codegraphs=codegraphs,
            triage_adjudicator=triage_service,
            triage_options=triage_options,
            registrations=registrations,
        )
    except BaseException as exc:
        if triage_classifier is not None:
            try:
                triage_classifier.close()
            except BaseException as cleanup_error:
                exc.add_note(f"Triage classifier cleanup also failed: {cleanup_error}")
        raise
    return BuiltinExecution(execution, triage_service, triage_classifier)
