# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from concurrent.futures import CancelledError

from metis.engine.stages.triage.models import TriageState
from metis.utils import source_lines

from . import constants as C
from .debug import _emit_debug


def triage_node_collect_evidence(state: TriageState, *, toolbox) -> TriageState:
    new_state: TriageState = {**state, "source_observations": []}
    file_path = state.get("finding_file_path", "") or ""
    if file_path.startswith("~"):
        file_path = f"./{file_path}"
    line = int(state.get("finding_line", 1) or 1)
    is_metis_source = bool(state.get("finding_is_metis", False))
    sections: list[str] = []

    if file_path:
        radius = (
            C.FILE_WINDOW_RADIUS_METIS
            if is_metis_source
            else C.FILE_WINDOW_RADIUS_EXTERNAL
        )
        start = max(1, line - radius)
        end = line + radius
        arguments = {"path": file_path, "start_line": start, "end_line": end}
        header = f"[FILE_WINDOW {file_path}:{start}-{end}]\n"
        try:
            output = toolbox.sed(file_path, start, end)
        except CancelledError:
            raise
        except Exception as exc:
            sections.append(f"[FILE_WINDOW_ERROR]\n{exc}")
            debug_output = f"Tool execution failed: {exc}"
        else:
            source_output = "".join(
                source_lines(output[: C.DEFAULT_CAPTURE_MAX_CHARS], keepends=True)[
                    : end - start + 1
                ]
            )
            debug_output = source_output
            if len(source_output) < len(output):
                debug_output += "\n...[truncated]"
            sections.append(header + debug_output)
            shown_output = source_output[
                : max(0, C.EVIDENCE_PACK_MAX_CHARS - len(header))
            ]
            if shown_output:
                new_state["source_observations"].append(
                    {
                        "tool": "sed",
                        "arguments": dict(arguments),
                        "output": shown_output,
                    }
                )
        _emit_debug(
            state,
            "tool_call",
            tool_name="sed",
            tool_args=arguments,
            tool_output=debug_output,
        )

    if is_metis_source and "{triage_input}" not in (
        state.get("triage_decision_prompt", "") or ""
    ):
        explanation = str(state.get("finding_explanation", "") or "").strip()
        if explanation:
            sections.append(f"[METIS_EXPLANATION]\n{explanation}")
    codegraph_context = str(state.get("codegraph_context", "") or "").strip()
    if codegraph_context:
        sections.append(f"[CODEGRAPH_CONTEXT]\n{codegraph_context}")

    evidence_pack = "\n\n".join(sections)
    if len(evidence_pack) > C.EVIDENCE_PACK_MAX_CHARS:
        evidence_pack = evidence_pack[: C.EVIDENCE_PACK_MAX_CHARS] + "\n...[truncated]"
    new_state["evidence_pack"] = evidence_pack
    _emit_debug(
        state,
        "evidence_collection",
        section_labels=[section[1:].split("]", 1)[0] for section in sections],
    )
    return new_state
