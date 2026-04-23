# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import logging
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage
from langchain_core.tools import StructuredTool
from pydantic import BaseModel, Field

logger = logging.getLogger("metis")

MAX_REVIEW_TOOL_ROUNDS = 3
MAX_REVIEW_TOOL_EVIDENCE_CHARS = 6000
MAX_REVIEW_RAG_CALLS = 2


class _RagArgs(BaseModel):
    query: str = Field(
        description=(
            "A focused security question for indexed code and documentation retrieval. "
            "Name the relevant file, function, API, or behavior and ask for one missing fact."
        )
    )


def _clip_text(value: Any, limit: int = MAX_REVIEW_TOOL_EVIDENCE_CHARS) -> str:
    text = str(value or "")
    if len(text) <= limit:
        return text
    return text[:limit] + "\n...[truncated]"


def build_review_langchain_tools(
    toolbox,
    *,
    retriever_code=None,
    retriever_docs=None,
    debug_callback=None,
):
    if not toolbox.has("rag_search"):
        return [], {}

    def _runner(query: str) -> str:
        try:
            output = toolbox.rag_search(
                query,
                retriever_code=retriever_code,
                retriever_docs=retriever_docs,
            )
        except Exception as exc:
            result = f"Tool execution failed: {exc}"
            if callable(debug_callback):
                try:
                    debug_callback(
                        {
                            "event": "tool_call",
                            "tool_name": "rag_search",
                            "tool_args": {"query": query},
                            "tool_output": result,
                        }
                    )
                except Exception:
                    logger.debug("Review debug callback failed", exc_info=True)
            return result

        result = str(output or "")
        if callable(debug_callback):
            try:
                debug_callback(
                    {
                        "event": "tool_call",
                        "tool_name": "rag_search",
                        "tool_args": {"query": query},
                        "tool_output": result,
                    }
                )
            except Exception:
                logger.debug("Review debug callback failed", exc_info=True)
        return result

    tool = StructuredTool.from_function(
        func=_runner,
        name="rag_search",
        description=(
            "Ask a natural-language security question over indexed code and documentation. "
            "Use this only for a specific missing fact about callers, externally controlled inputs, "
            "trust boundaries, validation, authorization, enforcement points, or intended design. "
            "Obligation-focused RAG may already be present in TOOL_EVIDENCE, so do not repeat it. "
            "Results may be empty or noisy; ignore anything not clearly relevant to the reviewed code."
        ),
        args_schema=_RagArgs,
    )
    return [tool], {tool.name: tool}


def _message_content_to_text(content: Any) -> str:
    if isinstance(content, str):
        return content.strip()
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
                continue
            if isinstance(item, dict):
                text = item.get("text") or item.get("content")
                if text:
                    parts.append(str(text))
        return "\n".join(part.strip() for part in parts if str(part).strip()).strip()
    return str(content or "").strip()


def run_review_tool_phase(
    *,
    chat_model,
    tools: list[StructuredTool],
    tools_by_name: dict[str, StructuredTool],
    system_prompt: str,
    body_text: str,
) -> dict[str, str]:
    rag_results: list[str] = []
    citations: list[str] = []
    messages = [SystemMessage(system_prompt), HumanMessage(body_text)]
    tool_model = chat_model.bind_tools(tools)
    summary = ""
    rag_calls = 0

    for _ in range(MAX_REVIEW_TOOL_ROUNDS):
        ai_message = tool_model.invoke(messages)
        messages.append(ai_message)
        tool_calls = list(getattr(ai_message, "tool_calls", []) or [])
        if not tool_calls:
            summary = _message_content_to_text(getattr(ai_message, "content", ""))
            break

        for tool_call in tool_calls:
            tool_name = str(tool_call.get("name", "") or "")
            tool_id = str(tool_call.get("id", "") or "")
            tool_args = dict(tool_call.get("args") or {})
            if tool_name != "rag_search":
                result_text = f"Unknown review tool: {tool_name}"
            elif rag_calls >= MAX_REVIEW_RAG_CALLS:
                result_text = "rag_search call limit reached for this review chunk."
            else:
                tool = tools_by_name.get(tool_name)
                if tool is None:
                    result_text = f"Unknown review tool: {tool_name}"
                else:
                    try:
                        result = tool.invoke(tool_args)
                    except Exception as exc:
                        result = f"Tool execution failed: {exc}"
                    result_text = str(result or "")
                    rag_calls += 1

            rag_results.append(
                f"[RAG_SEARCH]\nargs={json.dumps(tool_args, sort_keys=True)}\n{_clip_text(result_text, limit=1800)}"
            )
            query = str(tool_args.get("query", "") or "").strip()
            if query:
                citations.append(f"query={json.dumps(query)}")
            messages.append(
                ToolMessage(
                    content=result_text,
                    tool_call_id=tool_id,
                )
            )

    sections: list[str] = []
    if summary:
        sections.extend(["[RAG_TOOL_SUMMARY]", summary.strip(), ""])
    if rag_results:
        sections.extend(["[RAG_TOOL_RESULTS]", "\n\n".join(rag_results), ""])
    if citations:
        sections.extend(["[RAG_TOOL_QUERIES]", "\n".join(citations), ""])
    evidence = _clip_text("\n".join(part for part in sections if part).strip())
    return {"tool_evidence": evidence}
