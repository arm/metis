# SPDX-FileCopyrightText: Copyright 2025-2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from typing import Any
from typing_extensions import NotRequired
from typing_extensions import Required
from typing_extensions import TypedDict


class ReviewRequest(TypedDict):
    # Required fields
    file_path: Required[str]
    snippet: Required[str]
    language_prompts: Required[dict[str, str]]

    # Optional fields
    default_prompt_key: NotRequired[str]
    relative_file: NotRequired[str | None]
    # Explicit mode: 'file' or 'patch'
    mode: NotRequired[str]
    # Optional original file contents for patch mode
    original_file: NotRequired[str | None]
    debug_callback: NotRequired[Any]


class AskRequest(TypedDict):
    # Required fields
    question: Required[str]
    retriever_code: Required[Any]
    retriever_docs: Required[Any]


class ReviewState(TypedDict, total=False):
    # Input
    file_path: str
    snippet: str
    chunk_start: int
    chunk_end: int
    source_map: Any
    relative_file: str | None
    mode: str
    original_file: str | None
    debug_callback: Any
    # Derived
    system_prompt: str
    parsed_reviews: list[dict]


class AskState(TypedDict, total=False):
    # Input
    question: str
    retriever_code: Any
    retriever_docs: Any
    # Derived
    context: str
    code: str
    docs: str
    answer: str


class TriageRequest(TypedDict):
    finding_message: Required[str]
    finding_file_path: Required[str]
    finding_line: Required[int]
    finding_rule_id: Required[str]
    finding_snippet: Required[str]
    finding_source_tool: NotRequired[str]
    finding_is_metis: NotRequired[bool]
    finding_explanation: NotRequired[str]
    debug_callback: NotRequired[Any]
    triage_language: NotRequired[str]
    triage_language_guidance: NotRequired[str]


class TriageState(TypedDict, total=False):
    finding_message: str
    finding_file_path: str
    finding_line: int
    finding_rule_id: str
    finding_snippet: str
    finding_source_tool: str
    finding_is_metis: bool
    finding_explanation: str
    debug_callback: Any
    triage_language: str
    triage_language_guidance: str
    triage_system_prompt: str
    triage_decision_prompt: str
    evidence_pack: str
    tool_transcript: str
    decision_status: str
    decision_reason: str
    decision_evidence: list[str]
    decision_resolution_chain: list[str]
    decision_unresolved_hops: list[str]
    evidence_gate_missing: list[str]
    evidence_obligations: list[str]
    obligation_coverage: dict[str, int]
