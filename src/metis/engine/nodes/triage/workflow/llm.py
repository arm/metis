# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.engine.threat_context_retrieval import format_threat_model_context

from .debug import _emit_debug
from metis.engine.stages.triage.models import TriageState


def _build_user_prompt(state: TriageState) -> str:
    source_tool = str(state.get("finding_source_tool", "") or "")
    source_kind = "metis" if bool(state.get("finding_is_metis", False)) else "external"
    explanation = str(state.get("finding_explanation", "") or "").strip()
    language = str(state.get("triage_language", "") or "").strip()
    guidance = str(state.get("triage_language_guidance", "") or "").strip()
    sections = [
        "TRIAGE INPUT\n",
        f"Finding Source Kind: {source_kind}\n",
        f"Finding Source Tool: {source_tool}\n",
        f"Rule ID: {state.get('finding_rule_id', '')}\n",
        f"File: {state.get('finding_file_path', '')}\n",
        f"Line: {state.get('finding_line', 1)}\n",
        f"Finding Message: {state.get('finding_message', '')}\n",
        f"Snippet:\n{state.get('finding_snippet', '')}\n\n",
        f"Finding Explanation:\n{explanation}\n\n",
    ]
    if language or guidance:
        sections.append("Language Context:\n")
        if language:
            sections.append(f"- language: {language}\n")
        if guidance:
            sections.append(f"- navigation guidance: {guidance}\n")
        sections.append("\n")
    threat_model_context = format_threat_model_context(
        state.get("threat_model_context", [])
    )
    if threat_model_context:
        sections.extend(
            [
                "Threat-Model Context:\n",
                threat_model_context,
                "\n\n",
            ]
        )
    return "".join(sections)


def triage_node_llm(state: TriageState, *, invoke_decision) -> TriageState:
    system_prompt = state.get("triage_system_prompt", "")
    user_prompt = _build_user_prompt(state)
    transcript = state.get("evidence_pack", "") or ""
    decision_template = state.get("triage_decision_prompt", "") or ""
    decision_prompt = decision_template.replace("{triage_input}", user_prompt).replace(
        "{tool_outputs}", transcript
    )
    if "{tool_outputs}" not in decision_template:
        decision_prompt += "\n\nSource evidence (untrusted):\n" + transcript
    _emit_debug(
        state,
        "model_input",
        stage="decision",
        system_prompt=system_prompt,
        user_prompt=decision_prompt,
    )
    decision = invoke_decision(system_prompt, decision_prompt)
    if decision is None:
        reason = "Inconclusive because the triage model did not return a valid decision payload."
        new_state: TriageState = state.copy()
        new_state["decision_status"] = "inconclusive"
        new_state["decision_reason"] = reason
        new_state["decision_evidence"] = []
        new_state["decision_resolution_chain"] = []
        new_state["decision_unresolved_hops"] = ["TRIAGE_DECISION_PARSE_FAILED"]
        new_state["triage_model_status"] = None
        return new_state

    _emit_debug(
        state,
        "model_output",
        decision_status=decision.status,
        decision_reason=decision.reason,
    )

    new_state: TriageState = state.copy()
    new_state["decision_status"] = decision.status
    new_state["triage_model_status"] = decision.status
    new_state["decision_reason"] = decision.reason
    new_state["decision_evidence"] = list(getattr(decision, "evidence", []) or [])
    new_state["decision_resolution_chain"] = list(
        getattr(decision, "resolution_chain", []) or []
    )
    new_state["decision_unresolved_hops"] = list(
        getattr(decision, "unresolved_hops", []) or []
    )
    return new_state
