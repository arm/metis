# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from functools import partial
import logging
from typing import Any
from typing import cast

from langgraph.cache.memory import InMemoryCache
from langgraph.graph import END, StateGraph

from metis.engine.llm_runner import JsonPromptRequest, JsonPromptRunner
from metis.utils import parse_json_output

from ..schemas import TriageDecisionModel
from .adjudication import (
    adjudicate_status_deterministic,
    compose_final_reason,
)
from .nodes import (
    triage_node_collect_evidence,
    triage_node_llm,
)
from ..types import TriageRequest, TriageState

logger = logging.getLogger("metis")


class TriageGraph:
    def __init__(
        self,
        llm_provider,
        llama_query_model,
        toolbox,
        plugin_config=None,
        chat_model_kwargs=None,
        model_tools: tuple[Any, ...] = (),
        model_tool_max_rounds: int | None = None,
    ):
        self.llm_provider = llm_provider
        self.llama_query_model = llama_query_model
        self.toolbox = toolbox
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
            or "Given the finding details and tool outputs, return a final triage decision.\n\n"
            "The reported line number might be off; rely on nearby code regions and related symbols.\n\n"
            "{triage_input}\n\nTool Outputs:\n{tool_outputs}\n"
        )
        self._app = None
        self.chat_model_kwargs = chat_model_kwargs or {}
        self.model_tools = tuple(model_tools or ())
        self.model_tool_max_rounds = model_tool_max_rounds
        self._prompt_runner = JsonPromptRunner(self.llm_provider)

    def _invoke_triage_model(self, system_prompt: str, decision_prompt: str):
        decision = self._invoke_triage_model_once(
            system_prompt,
            decision_prompt,
            model_tools=self.model_tools,
            max_tool_rounds=self.model_tool_max_rounds,
            label="Triage graph",
        )
        if decision is None and self.model_tools:
            decision = self._invoke_triage_model_once(
                system_prompt,
                decision_prompt,
                model_tools=(),
                max_tool_rounds=None,
                label="Triage graph structured fallback",
            )
        return decision

    def _invoke_triage_model_once(
        self,
        system_prompt: str,
        decision_prompt: str,
        *,
        model_tools: tuple[Any, ...],
        max_tool_rounds: int | None,
        label: str,
    ):
        return self._prompt_runner.invoke(
            JsonPromptRequest(
                model=self.llama_query_model,
                system_prompt=_triage_json_system_prompt(system_prompt),
                user_prompt="{decision_prompt}",
                variables={"decision_prompt": decision_prompt},
                parse=_normalize_triage_decision,
                logger=logger,
                label=label,
                batch_size=1,
                invalid_message="expected triage decision JSON object",
                final_keep_message="marking finding inconclusive",
                response_model=TriageDecisionModel,
                chat_model_kwargs=self.chat_model_kwargs,
                model_tools=model_tools,
                max_tool_rounds=max_tool_rounds,
            )
        )

    def _get_app(self):
        if self._app is not None:
            return self._app
        graph = StateGraph(cast(Any, TriageState))
        graph.add_node(
            "collect_evidence",
            partial(triage_node_collect_evidence, toolbox=self.toolbox),
        )
        graph.add_node(
            "triage",
            partial(
                triage_node_llm,
                invoke_decision=self._invoke_triage_model,
            ),
        )
        graph.set_entry_point("collect_evidence")
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
                "finding_source_tool": request.get("finding_source_tool", ""),
                "finding_is_metis": bool(request.get("finding_is_metis", False)),
                "finding_explanation": request.get("finding_explanation", ""),
                "triage_language": request.get("triage_language", ""),
                "triage_language_guidance": request.get("triage_language_guidance", ""),
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
        evidence_gate_missing = list(out.get("evidence_gate_missing") or [])
        obligations = list(out.get("evidence_obligations") or [])
        obligation_coverage = dict(out.get("obligation_coverage") or {})
        status, reason_codes = adjudicate_status_deterministic(
            model_status=model_status,
            evidence=evidence,
            resolution_chain=resolution_chain,
            unresolved_hops=unresolved_hops,
            reason=reason,
            obligations=obligations,
            obligation_coverage=obligation_coverage,
        )
        if evidence_gate_missing and status != "inconclusive":
            status = "inconclusive"
            reason_codes.append("OVERRIDE_EVIDENCE_GATE_INCOMPLETE")
        for tag in evidence_gate_missing:
            code = f"EVIDENCE_GATE_MISSING:{tag}"
            if code not in reason_codes:
                reason_codes.append(code)
        missing_evidence = _normalize_missing_evidence(evidence_gate_missing)
        if status == "inconclusive" and not unresolved_hops:
            unresolved_hops = [
                "deterministic adjudicator marked evidence as insufficiently stable"
            ]
        reason = compose_final_reason(status, model_status, reason, reason_codes)
        return {
            "status": status,
            "reason": reason,
            "evidence": evidence,
            "resolution_chain": resolution_chain,
            "unresolved_hops": unresolved_hops,
            "evidence_obligations": obligations,
            "evidence_coverage": obligation_coverage,
            "missing_evidence": missing_evidence,
        }


def _triage_json_system_prompt(system_prompt: str) -> str:
    return "\n".join(
        [
            system_prompt.rstrip(),
            "",
            "Return exactly one JSON object with these keys:",
            "- status: one of valid, invalid, inconclusive",
            "- reason: non-empty concise justification",
            "- evidence: concrete file:line citations supporting the decision",
            "- resolution_chain: ordered static-analysis hops from finding to evidence",
            "- unresolved_hops: unresolved imports, wrappers, aliases, definitions, or evidence gaps",
            "Use empty arrays only when the schema permits them. Valid decisions require evidence and resolution_chain. Inconclusive decisions require unresolved_hops.",
        ]
    ).strip()


def _normalize_triage_decision(raw) -> TriageDecisionModel | None:
    if isinstance(raw, TriageDecisionModel):
        return raw

    payload = raw
    if isinstance(raw, str):
        payload = parse_json_output(raw)
    if isinstance(payload, dict):
        try:
            return TriageDecisionModel(**payload)
        except Exception:
            return None
    return None


def _normalize_missing_evidence(items: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for item in items:
        text = str(item or "").strip()
        if not text:
            continue
        if text.startswith("OBLIGATION_MISSING:"):
            text = text.split(":", 1)[1].strip()
        if text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out
