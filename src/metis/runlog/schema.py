# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

SCHEMA_VERSION = 1
DEFAULT_BLOB_THRESHOLD = 8 * 1024
DEFAULT_MAX_DEPTH = 32
DEFAULT_MAX_COLLECTION_ITEMS = 10_000
PREVIEW_CHARS = 200

ContentMode = Literal["full", "metadata"]
SpanStatus = Literal["ok", "error", "cancelled", "inconclusive"]

_SPAN_KIND_EXPLANATIONS = {
    "run": "The complete Metis run, from startup through shutdown, including aggregate activity and totals.",
    "command": "A CLI or programmatic command issued during this run and all work it triggered.",
    "execution": "An engine workflow or standalone operation executed for the current command.",
    "stage": "One configured initialize, review, or triage stage executed as part of the workflow.",
    "node": "One selected execution node, with the validated inputs it received and outputs it produced.",
    "task": "One bounded unit of work processed independently or in parallel.",
    "workflow": "One inner workflow invocation, including its initial state, steps, and final state.",
    "step": "One step executed inside an inner workflow and the state it returned.",
    "prompt": "One logical model request, including its prompt inputs, response parsing, and retries.",
    "attempt": "One attempt made to obtain and parse a valid response for the logical model request.",
    "llm.call": "One request sent to the model provider, including the rendered messages, provider response, duration, and token usage.",
    "model_loop": "A sequence of model responses and tool calls used to produce a final answer.",
    "tool": "One tool call requested by the model, including its arguments, output, and outcome.",
    "retrieval": "One search of the configured index for context relevant to a query, with the returned documents.",
    "memory": "One repository-memory lookup or update used by the current operation.",
    "threat_context": "The threat-model context and scope policy evaluated for the current source path or finding.",
}

_SPAN_NAME_EXPLANATIONS = {
    (
        "task",
        "Supplementary lens",
    ): "One supplementary security-analysis lens applied to the current CodeGraph.",
    (
        "task",
        "Global lifecycle chunk",
    ): "A size-bounded batch of functions checked for lifecycle asymmetry involving global callbacks, timers, work items, operation tables, or shared references.",
    (
        "task",
        "review_file",
    ): "The review of one source file and the model-derived findings it produced.",
    (
        "task",
        "triage_finding",
    ): "The triage of one SARIF finding using threat policy, code evidence, and the selected classifier.",
    (
        "task",
        "threat_source",
    ): "One configured threat-model source distilled into repository-memory claims.",
    (
        "workflow",
        "simple_llm_review",
    ): "A review workflow that built a prompt, requested model findings, and mapped them back to source.",
    (
        "workflow",
        "simple_llm_triage",
    ): "A triage workflow that collected evidence, requested a model decision, and applied deterministic adjudication.",
    (
        "model_loop",
        "tool_loop",
    ): "The sequence of model responses and tool calls used to reach a final answer or the round limit.",
    (
        "prompt",
        "Supplementary reachability analysis",
    ): "A model analysis of source context for the supplementary security checks selected by the active lens.",
    (
        "memory",
        "threat_model_context",
    ): "The authoritative and applicable history-derived threat-model records loaded for a source path.",
    (
        "threat_context",
        "scope_policy",
    ): "The authoritative threat-model scope policy evaluated for the current finding.",
}

_EVENT_EXPLANATIONS = {
    "execution.topology": "The stage and node topology selected for this execution.",
    "debug": "Structured diagnostic details emitted by the active node.",
    "checkpoint": "A triage checkpoint written after the reported number of findings was processed.",
    "diagnostic": "An execution warning or error raised during the current operation.",
    "retry": "A retry scheduled after the previous attempt failed or returned an invalid result.",
    "model.round": "One model response in the tool loop and the tool calls it requested.",
    "usage": "The token usage reported for this model-provider request.",
    "decision": "A policy, model, or deterministic adjudication decision made during the current operation.",
    "artifact": "An in-memory review, triage, or threat-model result produced by Metis.",
    "artifact.written": "An output file written by Metis, with its format, size, path, and digest.",
}

_PROGRESS_EXPLANATIONS = {
    "start": "Processing began for one item; attributes identify the item and total workload.",
    "done": "One item finished successfully; attributes include its result.",
    "error": "One item failed; attributes identify the item and observed error.",
    "execution_stage_start": "A configured stage began execution.",
    "execution_stage_end": "The configured stage finished; attributes show its status and duration.",
    "execution_node_start": "A selected node began execution within the current stage.",
    "execution_node_end": "The selected node finished; attributes show its status and duration.",
    "execution_node_skipped": "A node was skipped because a required dependency failed.",
    "codegraph_start": "CodeGraph materialization began for the selected source files and language providers.",
    "codegraph_progress": "File-level progress from one CodeGraph language provider.",
    "codegraph_done": "CodeGraph materialization finished; attributes show graph and file-coverage totals.",
    "combined_graph_lenses_start": "Combined supplementary graph analysis began for the selected functions and lens set.",
    "combined_graph_lenses_done": "Combined supplementary graph analysis finished; the findings count is its raw candidate output.",
    "reachability_file_paths_done": "File-focused path discovery finished; attributes show incoming, outgoing, and focus-node counts.",
    "reachability_file_review_done": "File-focused reachability review finished; attributes show supplementary and path findings.",
    "global_lifecycle_start": "Global-lifecycle analysis began after global constructs and related functions were selected; work was split into size-bounded chunks.",
    "global_lifecycle_done": "Global-lifecycle analysis finished; the findings count is its raw candidate output before downstream validation and deduplication.",
    "confirmation_start": "Model-backed confirmation began for the selected reachability path batches.",
    "confirmation_progress": "One reachability confirmation batch finished.",
    "confirmation_done": "Model-backed reachability confirmation finished; attributes show its candidate count.",
    "findings_finalization_start": "Final validation and deduplication began for the collected candidate findings.",
    "findings_finalization_progress": "Progress through candidate validation or representative adjudication.",
    "findings_finalization_done": "Final validation and deduplication finished; attributes show kept and removed findings.",
    "intra_audit_start": "Per-file intra-function auditing began for the selected functions.",
    "intra_audit_progress": "One per-file intra-function audit batch finished.",
    "lock_order_extraction_start": "Lock-order analysis began for the extracted conflicting acquisition candidates.",
    "lock_order_extraction_done": "Lock-order analysis finished; attributes show its candidate findings.",
    "supplementary_done": "All selected supplementary lenses finished; counts are grouped by analysis type before finalization.",
    "reachability_paths_start": "Deterministic reachability path discovery began for the selected source nodes.",
    "reachability_paths_progress": "Current progress through deterministic reachability path discovery.",
    "reachability_paths_done": "Reachability path discovery and confirmation-path selection finished.",
}


def span_explanation(kind: str, name: str) -> str:
    """Returns stable visualizer help text for a span."""

    specific = _SPAN_NAME_EXPLANATIONS.get((kind, name))
    if specific is not None:
        return specific
    generic = _SPAN_KIND_EXPLANATIONS.get(kind)
    if generic is not None:
        return generic
    return f"The {name} {kind} operation, including its inputs, outcome, and duration."


def event_explanation(name: str, attributes: object = None) -> str:
    """Returns stable visualizer help text for a point event."""

    if name == "progress" and isinstance(attributes, dict):
        return progress_explanation(str(attributes.get("event") or "progress"))
    specific = _EVENT_EXPLANATIONS.get(name)
    if specific is not None:
        return specific
    return f"The {name} event emitted by the containing operation."


def progress_explanation(event: str) -> str:
    specific = _PROGRESS_EXPLANATIONS.get(event)
    if specific is not None:
        return specific
    label = event.replace("_", " ").strip()
    if event.endswith("_start"):
        return f"Start of {label.removesuffix(' start')} processing; attributes summarize the selected workload."
    if event.endswith("_progress"):
        return f"Current progress through {label.removesuffix(' progress')} processing."
    if event.endswith("_done"):
        return f"Completion of {label.removesuffix(' done')} processing; attributes summarize its output before later stages."
    if event.endswith("_error"):
        return f"A failure during {label.removesuffix(' error')} processing, with the observed error in attributes."
    return f"Progress information for {label} processing."


@dataclass(frozen=True, slots=True)
class RunLogConfig:
    """Configuration for one run-log bundle."""

    path: str | Path | None = None
    content: ContentMode = "full"
    blob_threshold: int = DEFAULT_BLOB_THRESHOLD
    max_depth: int = DEFAULT_MAX_DEPTH
    max_collection_items: int = DEFAULT_MAX_COLLECTION_ITEMS

    def __post_init__(self) -> None:
        if self.content not in {"full", "metadata"}:
            raise ValueError("Run-log content must be 'full' or 'metadata'")
        if self.blob_threshold < 1:
            raise ValueError("Run-log blob threshold must be positive")
        if self.max_depth < 1:
            raise ValueError("Run-log maximum depth must be positive")
        if self.max_collection_items < 1:
            raise ValueError("Run-log maximum collection size must be positive")
