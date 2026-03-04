# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from langchain_core.messages import HumanMessage, SystemMessage

from .debug import _emit_debug
from ..types import TriageState


def _build_user_prompt(state: TriageState) -> str:
    return (
        "TRIAGE INPUT\n"
        f"Rule ID: {state.get('finding_rule_id', '')}\n"
        f"File: {state.get('finding_file_path', '')}\n"
        f"Line: {state.get('finding_line', 1)}\n"
        f"Finding Message: {state.get('finding_message', '')}\n"
        f"Snippet:\n{state.get('finding_snippet', '')}\n\n"
        f"RAG Context:\n{state.get('context', '')}\n"
    )


def triage_node_llm(state: TriageState, *, decision_model) -> TriageState:
    system_prompt = state.get("triage_system_prompt", "")
    user_prompt = _build_user_prompt(state)
    transcript = state.get("evidence_pack", "") or ""
    decision_template = state.get("triage_decision_prompt", "")
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
