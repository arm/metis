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
from .index import registration as index_node
from .reachability import review as reachability_node
from .reachability.review import ReachabilityReviewService
from .reachability.service import ReachabilityService
from .reachability_triage import registration as reachability_triage_node
from .reachability_triage.service import ReachabilityTriageService
from .result import review as review_result_node
from .result import triage as triage_result_node
from .simple_llm_review import registration as simple_llm_review_node
from .simple_llm_review.service import SimpleLlmReviewService
from .simple_llm_triage import registration as simple_llm_triage_node
from .simple_llm_triage.service import SimpleLlmTriageService
from .threat_model import registration as threat_model_node

if TYPE_CHECKING:
    from .simple_llm_review.graph import ReviewGraph
    from ..capabilities.index import IndexCapability


@dataclass(frozen=True, slots=True)
class BuiltinExecution:
    execution: ExecutionGraphService
    triage_service: TriageService | None
    simple_llm_triage: SimpleLlmTriageService | None


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
    review_graph_factory: Callable[[IndexCapability | None], ReviewGraph],
) -> BuiltinExecution:
    selected_nodes = configuration.selected_nodes()
    static_registrations = (
        index_node.registration,
        codegraph_node.registration,
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

    simple_llm_review = None
    if {
        ("review", "simple_llm_review"),
        ("review", "reachability"),
    } & selected_nodes:
        simple_llm_review = SimpleLlmReviewService(
            engine_config,
            repository,
            review_graph_factory=review_graph_factory,
        )
    if ("review", "simple_llm_review") in selected_nodes:
        assert simple_llm_review is not None
        registrations.append(simple_llm_review_node.create_node(simple_llm_review))

    reachability_selected = ("review", "reachability") in selected_nodes
    reachability_triage_selected = (
        "triage",
        "reachability_triage",
    ) in selected_nodes
    reachability = (
        ReachabilityService(
            config=engine_config,
            repository=repository,
            llm_provider=engine_config.llm_provider,
            usage_runtime=engine_config.usage_runtime,
            codegraphs=codegraphs,
        )
        if reachability_selected or reachability_triage_selected
        else None
    )
    if reachability_selected:
        assert reachability is not None
        reachability_review = ReachabilityReviewService(
            engine_config,
            repository,
            reachability,
            (
                None
                if ("review", "simple_llm_review") in selected_nodes
                else simple_llm_review
            ),
            reachability_settings,
        )
        registrations.append(reachability_node.create_node(reachability_review))

    triage_service = (
        TriageService(
            max_workers=engine_config.max_workers,
            triage_checkpoint_every=triage_checkpoint_every,
        )
        if configuration.stages.triage is not None
        else None
    )
    selected_triage_nodes = {
        name for stage, name in selected_nodes if stage == "triage"
    }
    simple_llm_triage = None
    if {"simple_llm_triage", "reachability_triage"} & selected_triage_nodes:
        simple_llm_triage = SimpleLlmTriageService(
            llm_provider=engine_config.llm_provider,
            model=engine_config.llama_query_model,
            chat_model_kwargs=engine_config.chat_model_kwargs,
            plugin_config=engine_config.plugin_config,
            get_plugin_for_path=repository.get_plugin_for_path,
            get_language_name_for_path=repository.get_language_name_for_path,
            usage_hooks=engine_config.usage_runtime.hooks,
            model_tool_max_contract_chars=(
                engine_config.capability_settings.model_tools.max_contract_chars
            ),
            navigation_manifest=capabilities.manifest("navigation"),
        )
        if "simple_llm_triage" in selected_triage_nodes:
            registrations.append(simple_llm_triage_node.create_node(simple_llm_triage))
    if "reachability_triage" in selected_triage_nodes:
        assert reachability is not None
        assert simple_llm_triage is not None
        reachability_triage = ReachabilityTriageService(
            reachability_service=reachability,
            settings=reachability_settings,
            max_workers=engine_config.max_workers,
            llm_provider=engine_config.llm_provider,
            model=engine_config.llama_query_model,
            usage_runtime=engine_config.usage_runtime,
            codebase_path=engine_config.codebase_path,
            chat_model_kwargs=engine_config.chat_model_kwargs,
            normalize_path=repository.normalize_match_path,
            model_tool_max_contract_chars=(
                engine_config.capability_settings.model_tools.max_contract_chars
            ),
            navigation_manifest=capabilities.manifest("navigation"),
        )
        registrations.append(
            reachability_triage_node.create_node(
                reachability_triage,
                simple_llm_triage,
            )
        )

    try:
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
    except Exception:
        if simple_llm_triage is not None:
            simple_llm_triage.close()
        raise
    return BuiltinExecution(execution, triage_service, simple_llm_triage)
