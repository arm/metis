# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from langchain_core.messages import HumanMessage, SystemMessage

from .debug import _emit_debug
from ..types import TriageState


def _build_decision_prompt_template(state: TriageState) -> str:
    template = state.get("triage_decision_prompt", "") or ""
    if state.get("use_retrieval_context", True):
        return template
    return template.replace(
        "Given the finding details, RAG context, and tool outputs",
        "Given the finding details and tool outputs",
    )


def _build_user_prompt(state: TriageState) -> str:
    source_tool = str(state.get("finding_source_tool", "") or "")
    source_kind = "metis" if bool(state.get("finding_is_metis", False)) else "external"
    explanation = str(state.get("finding_explanation", "") or "").strip()
    sections = [
        "TRIAGE INPUT\n",
        f"SARIF Source Kind: {source_kind}\n",
        f"SARIF Source Tool: {source_tool}\n",
        f"Rule ID: {state.get('finding_rule_id', '')}\n",
        f"File: {state.get('finding_file_path', '')}\n",
        f"Line: {state.get('finding_line', 1)}\n",
        f"Finding Message: {state.get('finding_message', '')}\n",
        f"Snippet:\n{state.get('finding_snippet', '')}\n\n",
        f"Finding Explanation:\n{explanation}\n\n",
    ]
    if state.get("use_retrieval_context", True):
        sections.append(f"RAG Context:\n{state.get('context', '')}\n")
    return "".join(sections)


def _build_gate_reason(missing: list[str]) -> str:
    cleaned = []
    for tag in missing:
        text = str(tag).strip()
        if not text:
            continue
        if text.startswith("OBLIGATION_MISSING:"):
            text = text.split(":", 1)[1]
        cleaned.append(text)
    missing_tags = ", ".join(cleaned)
    if not missing_tags:
        missing_tags = "unknown"
    return (
        "Inconclusive due to evidence completeness gate failure. "
        f"Missing evidence dimensions: {missing_tags}."
    )


def triage_node_llm(state: TriageState, *, decision_model) -> TriageState:
    gate_missing = list(state.get("evidence_gate_missing") or [])
    if gate_missing:
        reason = _build_gate_reason(gate_missing)
        _emit_debug(
            state,
            "model_output",
            decision_status="inconclusive",
            decision_reason=reason,
        )
        new_state: TriageState = dict(state)
        new_state["tool_transcript"] = state.get("evidence_pack", "") or ""
        new_state["decision_status"] = "inconclusive"
        new_state["decision_reason"] = reason
        new_state["decision_evidence"] = []
        new_state["decision_resolution_chain"] = []
        new_state["decision_unresolved_hops"] = [
            f"EVIDENCE_GATE_MISSING:{tag}" for tag in gate_missing
        ]
        return new_state

    system_prompt = state.get("triage_system_prompt", "")
    user_prompt = _build_user_prompt(state)
    transcript = state.get("evidence_pack", "") or ""
    decision_template = _build_decision_prompt_template(state)
    decision_prompt = decision_template.replace("{triage_input}", user_prompt).replace(
        "{tool_outputs}", transcript
    )
    _emit_debug(
        state,
        "model_input",
        stage="decision",
        system_prompt=system_prompt,
        user_prompt=decision_prompt,
    )
    decision = decision_model.invoke(
        [SystemMessage(content=system_prompt), HumanMessage(content=decision_prompt)]
    )

    _emit_debug(
        state,
        "model_output",
        decision_status=decision.status,
        decision_reason=decision.reason,
    )

    new_state: TriageState = dict(state)
    new_state["tool_transcript"] = transcript
    new_state["decision_status"] = decision.status
    new_state["decision_reason"] = decision.reason
    new_state["decision_evidence"] = list(getattr(decision, "evidence", []) or [])
    new_state["decision_resolution_chain"] = list(
        getattr(decision, "resolution_chain", []) or []
    )
    new_state["decision_unresolved_hops"] = list(
        getattr(decision, "unresolved_hops", []) or []
    )
    return new_state
