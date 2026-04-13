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

MAX_REVIEW_TOOL_ROUNDS = 4
MAX_REVIEW_TOOL_EVIDENCE_CHARS = 6000
MAX_REVIEW_TOOL_CITATION_EXCERPT_CHARS = 240


class _SedArgs(BaseModel):
    path: str = Field(description="Repository-relative file path to inspect")
    start_line: int = Field(description="Inclusive 1-based start line number")
    end_line: int = Field(description="Inclusive 1-based end line number")


class _CatArgs(BaseModel):
    path: str = Field(description="Repository-relative file path to read")


class _GrepArgs(BaseModel):
    pattern: str = Field(description="Regular expression or literal text to search")
    path: str = Field(description="Repository-relative file or directory to search")


class _FindNameArgs(BaseModel):
    name: str = Field(description="Exact filename to locate")
    max_results: int = Field(
        default=20, description="Maximum number of matches to return"
    )


class _RagArgs(BaseModel):
    query: str = Field(
        description="Question or search text for indexed code and docs retrieval"
    )


def _clip_text(value: Any, limit: int = MAX_REVIEW_TOOL_EVIDENCE_CHARS) -> str:
    text = str(value or "")
    if len(text) <= limit:
        return text
    return text[:limit] + "\n...[truncated]"


def _stringify_tool_output(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "\n".join(str(item) for item in value)
    if isinstance(value, dict):
        return json.dumps(value, indent=2, sort_keys=True)
    return str(value)


def _emit_review_debug(debug_callback, event: str, **payload) -> None:
    if not callable(debug_callback):
        return
    try:
        debug_callback({"event": event, **payload})
    except Exception:
        logger.debug("Review debug callback failed", exc_info=True)


def build_review_langchain_tools(
    toolbox,
    *,
    retriever_code=None,
    retriever_docs=None,
    debug_callback=None,
):
    def _tool_debug_args(name: str, **kwargs) -> dict[str, Any]:
        out = dict(kwargs)
        describe_call = getattr(toolbox, "describe_call", None)
        try:
            if callable(describe_call):
                details = describe_call(name, **kwargs)
            else:
                details = toolbox.describe(name)
        except Exception:
            return out
        if not isinstance(details, dict):
            return out
        for key, value in details.items():
            out.setdefault(key, value)
        return out

    def _wrap_tool(name: str, description: str, args_schema, invoke):
        def _runner(**kwargs):
            try:
                result = invoke(**kwargs)
            except Exception as exc:
                output = f"Tool execution failed: {exc}"
                _emit_review_debug(
                    debug_callback,
                    "tool_call",
                    tool_name=name,
                    tool_args=_tool_debug_args(name, **kwargs),
                    tool_output=output,
                )
                return output

            output = _stringify_tool_output(result)
            _emit_review_debug(
                debug_callback,
                "tool_call",
                tool_name=name,
                tool_args=_tool_debug_args(name, **kwargs),
                tool_output=output,
            )
            return output

        return StructuredTool.from_function(
            func=_runner,
            name=name,
            description=description,
            args_schema=args_schema,
        )

    tools = [
        _wrap_tool(
            "sed",
            (
                "Read an inclusive line range from a repository-relative file. "
                "Prefer this first for local inspection around the reported code."
            ),
            _SedArgs,
            lambda path, start_line, end_line: toolbox.sed(path, start_line, end_line),
        ),
        _wrap_tool(
            "cat",
            "Read an entire repository-relative file when local context is needed.",
            _CatArgs,
            lambda path: toolbox.cat(path),
        ),
        _wrap_tool(
            "grep",
            (
                "Search for text, regex matches, references, or call sites inside a "
                "repository-relative file or directory."
            ),
            _GrepArgs,
            lambda pattern, path: toolbox.grep(pattern, path),
        ),
        _wrap_tool(
            "find_name",
            "Locate files by exact filename inside the repository.",
            _FindNameArgs,
            lambda name, max_results=20: toolbox.find_name(
                name, max_results=max_results
            ),
        ),
    ]
    if toolbox.has("rag_search"):
        tools.append(
            _wrap_tool(
                "rag_search",
                (
                    "Ask a natural-language question over indexed code and documentation. "
                    "Returns separate CODE_RAG and DOCS_RAG sections. Use this for broader "
                    "semantic context such as what a module does, how it is used, what related "
                    "code or docs matter, and what higher-level behavior or assumptions explain "
                    "the current file. Do not use this for exact symbol or file lookup when grep, "
                    "find_name, sed, or cat are a better fit."
                ),
                _RagArgs,
                lambda query: toolbox.rag_search(
                    query,
                    retriever_code=retriever_code,
                    retriever_docs=retriever_docs,
                ),
            )
        )
    return tools, {tool.name: tool for tool in tools}


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


def _clip_excerpt(
    value: Any,
    *,
    limit: int = MAX_REVIEW_TOOL_CITATION_EXCERPT_CHARS,
) -> str:
    text = " ".join(str(value or "").split())
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + "..."


def _format_tool_citation(
    tool_name: str,
    tool_args: dict[str, Any],
    result_text: str,
) -> str:
    details: list[str] = [f"tool={tool_name}"]
    path = str(tool_args.get("path", "") or "").strip()
    if path:
        details.append(f"path={path}")
    if tool_name == "sed":
        start_line = tool_args.get("start_line")
        end_line = tool_args.get("end_line")
        if start_line is not None and end_line is not None:
            details.append(f"lines={start_line}-{end_line}")
    query = str(tool_args.get("query", "") or "").strip()
    if query:
        details.append(f"query={json.dumps(query)}")
    pattern = str(tool_args.get("pattern", "") or "").strip()
    if pattern:
        details.append(f"pattern={json.dumps(pattern)}")
    name = str(tool_args.get("name", "") or "").strip()
    if name:
        details.append(f"name={json.dumps(name)}")

    excerpt = _clip_excerpt(result_text)
    if excerpt:
        details.append(f"excerpt={json.dumps(excerpt)}")
    return " | ".join(details)


def _format_tool_evidence(
    *,
    summary: str,
    citations: list[str],
    transcript: str,
) -> str:
    sections: list[str] = []
    if summary:
        sections.extend(["[SUMMARY]", summary.strip(), ""])
    if citations:
        sections.extend(["[CITATIONS]", "\n".join(citations), ""])
    formatted = "\n".join(part for part in sections if part).strip()
    if formatted:
        return _clip_text(formatted)
    return _clip_text(transcript)


def run_review_tool_phase(
    *,
    chat_model,
    tools: list[StructuredTool],
    tools_by_name: dict[str, StructuredTool],
    system_prompt: str,
    body_text: str,
) -> dict[str, str]:
    transcript_parts: list[str] = []
    citations: list[str] = []
    messages = [SystemMessage(system_prompt), HumanMessage(body_text)]
    tool_model = chat_model.bind_tools(tools)
    summary = ""

    for _ in range(MAX_REVIEW_TOOL_ROUNDS):
        ai_message = tool_model.invoke(messages)
        messages.append(ai_message)
        tool_calls = list(getattr(ai_message, "tool_calls", []) or [])
        if not tool_calls:
            summary = _message_content_to_text(getattr(ai_message, "content", ""))
            if summary:
                transcript_parts.append(f"[EVIDENCE_SUMMARY]\n{summary}")
            break

        for tool_call in tool_calls:
            tool_name = str(tool_call.get("name", "") or "")
            tool_id = str(tool_call.get("id", "") or "")
            tool_args = tool_call.get("args") or {}
            tool = tools_by_name.get(tool_name)
            if tool is None:
                result_text = f"Unknown tool: {tool_name}"
            else:
                try:
                    result = tool.invoke(tool_args)
                except Exception as exc:
                    result = f"Tool execution failed: {exc}"
                result_text = _stringify_tool_output(result)

            transcript_parts.append(
                f"[TOOL {tool_name}]\nargs={json.dumps(tool_args, sort_keys=True)}\n{_clip_text(result_text, limit=1600)}"
            )
            citations.append(_format_tool_citation(tool_name, tool_args, result_text))
            messages.append(
                ToolMessage(
                    content=result_text,
                    tool_call_id=tool_id,
                )
            )

    transcript = "\n\n".join(part for part in transcript_parts if part)
    evidence = _format_tool_evidence(
        summary=summary,
        citations=citations,
        transcript=transcript,
    )
    return {
        "tool_evidence": evidence,
        "tool_evidence_summary": _clip_text(summary) if summary else "",
        "tool_evidence_citations": (
            _clip_text("\n".join(citations)) if citations else ""
        ),
    }
