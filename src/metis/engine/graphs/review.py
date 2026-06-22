# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import logging
from functools import partial
from typing import Any
from typing import cast

from langgraph.graph import StateGraph, END
from langgraph.cache.memory import InMemoryCache

from metis.engine.llm_runner import JsonPromptRequest, JsonPromptRunner
from metis.engine.source import SourceMap
from metis.utils import split_snippet, parse_json_output
from .schemas import ReviewResponseModel, review_schema_prompt
from .utils import (
    build_review_system_prompt,
    normalize_review_fields,
    sanitize_review_payload,
)
from .types import ReviewRequest, ReviewState

logger = logging.getLogger("metis")


def _normalize_reviews(raw) -> list[dict]:
    """
    Normalize arbitrary LLM responses into review dicts, preserving partially
    structured entries with empty fields when necessary.
    """
    if isinstance(raw, ReviewResponseModel):
        return [
            normalize_review_fields(r) for r in (raw.model_dump().get("reviews") or [])
        ]

    payload = None
    if isinstance(raw, dict):
        payload = raw
    elif isinstance(raw, str):
        parsed = parse_json_output(raw)
        if isinstance(parsed, dict):
            payload = parsed
        elif parsed not in ("", None):
            logger.warning("LLM fallback returned non-JSON response: %s", parsed)
    elif raw not in (None, ""):
        logger.warning("Unexpected review payload type %s", type(raw).__name__)

    if isinstance(payload, dict):
        return sanitize_review_payload(payload)

    return []


def _build_body_text(state: ReviewState) -> str:
    """
    Format the user/body portion of the review prompt based on mode.
    """
    snippet = state.get("snippet", "") or ""
    mode = state.get("mode", "file")

    if mode == "file":
        file_path = state.get("file_path", "") or ""
        chunk_start = state.get("chunk_start") or 1
        sections = [
            f"FILE: {file_path}",
            "SNIPPET:",
            SourceMap.number_text(snippet, chunk_start),
            "",
        ]
    else:
        original_file = state.get("original_file") or ""
        sections = [
            "ORIGINAL_FILE:",
            SourceMap.number_text(original_file, 1) if original_file else "",
            "",
            "FILE_CHANGES:",
            snippet,
            "",
        ]

    return "\n".join(sections)


def review_node_build_prompt(
    state: ReviewState,
    language_prompts: dict,
    default_prompt_key: str,
    report_prompt: str,
    custom_prompt_text: str | None,
    custom_guidance_precedence: str,
    schema_prompt_section: str,
) -> ReviewState:
    system = build_review_system_prompt(
        language_prompts,
        default_prompt_key,
        report_prompt,
        custom_prompt_text,
        custom_guidance_precedence,
        schema_prompt_section,
    )
    new_state: ReviewState = state.copy()
    new_state["system_prompt"] = system
    return new_state


def review_node_llm(
    state: ReviewState,
    invoke_review,
) -> ReviewState:
    body_text = _build_body_text(state)
    system_prompt = state.get("system_prompt") or ""
    reviews = invoke_review(system_prompt, body_text) or []
    new_state: ReviewState = state.copy()
    new_state["parsed_reviews"] = reviews
    return new_state


def review_node_parse(state: ReviewState) -> ReviewState:
    reviews = state.get("parsed_reviews") or []
    smap = state.get("source_map")
    chunk_start = state.get("chunk_start")
    chunk_end = state.get("chunk_end")
    hint = (
        range(chunk_start, chunk_end + 1)
        if isinstance(chunk_start, int) and isinstance(chunk_end, int)
        else None
    )

    use_hint = state.get("mode", "file") == "file"
    for issue in reviews:
        if not isinstance(issue, dict):
            continue
        if smap is None:
            issue.setdefault("anchor", None)
            issue.setdefault("line_number", 0)
            continue
        anchor = smap.resolve_issue(
            snippet=str(issue.get("code_snippet") or ""),
            start_line=issue.get("start_line"),
            end_line=issue.get("end_line"),
            hint=hint if use_hint else None,
            context_text=f"{issue.get('issue') or ''} {issue.get('reasoning') or ''}",
        )
        issue["anchor"] = anchor.to_dict()
        issue["line_number"] = anchor.start_line or 0

    new_state: ReviewState = state.copy()
    new_state["parsed_reviews"] = reviews
    return new_state


class ReviewGraph:
    def __init__(
        self,
        llm_provider,
        plugin_config,
        custom_prompt_text,
        custom_guidance_precedence,
        llama_query_model,
        max_token_length,
        chat_model_kwargs: dict[str, Any] | None = None,
        model_tools: tuple[Any, ...] = (),
        model_tool_max_rounds: int | None = None,
    ):
        self.llm_provider = llm_provider
        self.plugin_config = plugin_config
        self.custom_prompt_text = custom_prompt_text
        self.custom_guidance_precedence = custom_guidance_precedence or ""
        self.llama_query_model = llama_query_model
        self.max_token_length = max_token_length
        self.chat_model_kwargs = chat_model_kwargs or {}
        self.model_tools = tuple(model_tools or ())
        self.model_tool_max_rounds = model_tool_max_rounds
        self._schema_prompt_section = review_schema_prompt()

        self.report_prompt = self.plugin_config.get("general_prompts", {}).get(
            "security_review_report", ""
        )

        get_chat_model = getattr(self.llm_provider, "get_chat_model", None)
        if not callable(get_chat_model):
            raise RuntimeError(
                "Unable to create review runnable; LangChain chat provider required."
            )
        self._prompt_runner = JsonPromptRunner(self.llm_provider)
        self._app_cache = {}

    def _invoke_review_model(self, system_prompt, body_text):
        return self._prompt_runner.invoke(
            JsonPromptRequest(
                model=self.llama_query_model,
                system_prompt=system_prompt,
                user_prompt="{body_text}",
                variables={"body_text": body_text},
                parse=_normalize_reviews,
                logger=logger,
                label="Review graph",
                batch_size=1,
                invalid_message="expected review JSON object",
                final_keep_message="returning no findings for this chunk",
                response_model=ReviewResponseModel,
                chat_model_kwargs=self.chat_model_kwargs,
                model_tools=self.model_tools,
                max_tool_rounds=self.model_tool_max_rounds,
            )
        )

    def _build_app(self, language_prompts, default_prompt_key):
        cache_key = (id(language_prompts), default_prompt_key)
        cached = self._app_cache.get(cache_key)
        if cached is not None:
            return cached

        graph = StateGraph(cast(Any, ReviewState))
        build_prompt = partial(
            review_node_build_prompt,
            language_prompts=language_prompts,
            default_prompt_key=default_prompt_key,
            report_prompt=self.report_prompt,
            custom_prompt_text=self.custom_prompt_text,
            custom_guidance_precedence=self.custom_guidance_precedence,
            schema_prompt_section=self._schema_prompt_section,
        )
        review = partial(
            review_node_llm,
            invoke_review=self._invoke_review_model,
        )
        parse = review_node_parse

        graph.add_node("build_prompt", build_prompt)
        graph.add_node("review", review)
        graph.add_node("parse", parse)

        graph.set_entry_point("build_prompt")
        graph.add_edge("build_prompt", "review")
        graph.add_edge("review", "parse")
        graph.add_edge("parse", END)

        compiled = graph.compile(cache=InMemoryCache())
        self._app_cache[cache_key] = compiled
        return compiled

    def review(self, request: ReviewRequest):
        file_path = request["file_path"]
        snippet = request["snippet"]
        language_prompts = request["language_prompts"]
        default_prompt_key = request.get("default_prompt_key", "security_review_file")
        relative_file = request.get("relative_file")
        mode = request.get("mode", "file")
        original_file = request.get("original_file")

        rel_path = relative_file or file_path
        if mode == "file":
            smap = SourceMap.for_text(rel_path, snippet)
        elif original_file:
            smap = SourceMap.for_text(rel_path, original_file)
        else:
            smap = None
        chunks = split_snippet(
            snippet, self.max_token_length, self.llm_provider.count_tokens
        )
        accumulated = []
        app = self._build_app(language_prompts, default_prompt_key)
        for chunk, chunk_start in chunks:
            chunk_end = chunk_start + chunk.count("\n")
            state = {
                "file_path": file_path,
                "snippet": chunk,
                "chunk_start": chunk_start,
                "chunk_end": chunk_end,
                "source_map": smap,
                "relative_file": relative_file,
                "mode": mode,
                "original_file": original_file,
            }
            out = app.invoke(state)
            chunk_reviews = out.get("parsed_reviews", []) or []
            if chunk_reviews:
                accumulated.extend(chunk_reviews)

        if not accumulated:
            file_display = relative_file if relative_file else file_path
            result = {
                "file": file_display,
                "file_path": file_path,
                "reviews": [],
            }
            return result

        file_display = relative_file if relative_file else file_path
        result = {
            "file": file_display,
            "file_path": file_path,
            "reviews": accumulated,
        }

        return result
