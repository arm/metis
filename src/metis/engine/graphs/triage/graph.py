# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from functools import partial

from langgraph.cache.memory import InMemoryCache
from langgraph.graph import END, StateGraph

from ..schemas import TriageDecisionModel
from .adjudication import (
    adjudicate_status_deterministic,
    compose_final_reason,
    contains_contradiction_signal,
    contains_uncertainty_signal,
    has_critical_unresolved_hops,
)
from .nodes import (
    triage_node_collect_evidence,
    triage_node_llm,
    triage_node_retrieve,
)
from ..types import TriageRequest, TriageState


class TriageGraph:
    def __init__(
        self,
        llm_provider,
        llama_query_model,
        tool_runner,
        plugin_config=None,
    ):
        self.llm_provider = llm_provider
        self.llama_query_model = llama_query_model
        self.tool_runner = tool_runner
        general_prompts = (plugin_config or {}).get("general_prompts", {})
        self.triage_system_prompt = (
            general_prompts.get("triage_system_prompt")
            or "You triage static analysis findings. "
            "Only decide whether the finding is valid or invalid based on static code evidence. "
            "Treat the reported line as potentially inaccurate. "
            "Prefer inspecting nearby code first with sed/cat in the reported file."
        )
        self.triage_decision_prompt = (
            general_prompts.get("triage_decision_prompt")
            or "Given the finding details, RAG context, and tool outputs, return a final triage decision.\n\n"
            "The reported line number might be off; rely on nearby code regions and related symbols.\n\n"
            "{triage_input}\n\nTool Outputs:\n{tool_outputs}\n"
        )
        self._app = None
        self._decision_model = None

    def _ensure_models(self):
        if self._decision_model is not None:
            return
        chat_model = self.llm_provider.get_chat_model(model=self.llama_query_model)
        self._decision_model = chat_model.with_structured_output(
            TriageDecisionModel, method="function_calling"
        )

    def _get_app(self):
        if self._app is not None:
            return self._app
        self._ensure_models()
        graph = StateGraph(TriageState)
        graph.add_node("retrieve", triage_node_retrieve)
        graph.add_node(
            "collect_evidence",
            partial(triage_node_collect_evidence, tool_runner=self.tool_runner),
        )
        graph.add_node(
            "triage",
            partial(
                triage_node_llm,
                decision_model=self._decision_model,
            ),
        )
        graph.set_entry_point("retrieve")
        graph.add_edge("retrieve", "collect_evidence")
        graph.add_edge("collect_evidence", "triage")
        graph.add_edge("triage", END)
        self._app = graph.compile(cache=InMemoryCache())
        return self._app

    def triage(self, request: TriageRequest) -> dict:
        out = self._get_app().invoke(
            {
                "finding_message": request["finding_message"],
                "finding_file_path": request["finding_file_path"],
                "finding_line": request["finding_line"],
                "finding_rule_id": request["finding_rule_id"],
                "finding_snippet": request["finding_snippet"],
                "retriever_code": request["retriever_code"],
                "retriever_docs": request["retriever_docs"],
                "triage_analyzer": request.get("triage_analyzer"),
                "triage_codebase_path": request.get("triage_codebase_path", "."),
                "debug_callback": request.get("debug_callback"),
                "triage_system_prompt": self.triage_system_prompt,
                "triage_decision_prompt": self.triage_decision_prompt,
            }
        )
        try:
            validated = TriageDecisionModel(
                status=out.get("decision_status", ""),
                reason=out.get("decision_reason", ""),
                evidence=list(out.get("decision_evidence") or []),
                resolution_chain=list(out.get("decision_resolution_chain") or []),
                unresolved_hops=list(out.get("decision_unresolved_hops") or []),
            )
        except Exception as exc:
            raise ValueError(f"Invalid triage decision from model: {exc}") from exc

        model_status = validated.status
        reason = validated.reason
        evidence = list(validated.evidence)
        resolution_chain = list(validated.resolution_chain)
        unresolved_hops = list(validated.unresolved_hops)
        status = adjudicate_status_deterministic(
            model_status=model_status,
            evidence=evidence,
            resolution_chain=resolution_chain,
            unresolved_hops=unresolved_hops,
            reason=reason,
        )
        cb = request.get("debug_callback")
        if callable(cb):
            try:
                has_critical_unresolved = has_critical_unresolved_hops(
                    unresolved_hops,
                    resolution_chain,
                )
                cb(
                    {
                        "event": "status_adjudication",
                        "model_status": model_status,
                        "final_status": status,
                        "has_evidence": bool(evidence),
                        "has_resolution_chain": bool(resolution_chain),
                        "has_unresolved_hops": bool(unresolved_hops),
                        "has_critical_unresolved_hops": has_critical_unresolved,
                        "uncertainty_signal": contains_uncertainty_signal(reason),
                        "contradiction_signal": contains_contradiction_signal(reason),
                    }
                )
            except Exception:
                pass
        if status == "inconclusive" and not unresolved_hops:
            unresolved_hops = [
                "deterministic adjudicator marked evidence as insufficiently stable"
            ]
        reason = compose_final_reason(status, model_status, reason)
        return {
            "status": status,
            "reason": reason,
            "evidence": evidence,
            "resolution_chain": resolution_chain,
            "unresolved_hops": unresolved_hops,
        }
