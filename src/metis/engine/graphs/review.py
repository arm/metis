# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import logging
from functools import partial

from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langgraph.graph import StateGraph, END
from langgraph.cache.memory import InMemoryCache

from metis.utils import split_snippet, parse_json_output, enrich_issues
from .schemas import ReviewResponseModel, review_schema_prompt
from .utils import (
    retrieve_text,
    synthesize_context,
    build_review_system_prompt,
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
        return raw.model_dump().get("reviews", []) or []

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
    context = state.get("context", "") or ""
    mode = state.get("mode", "file")

    if mode == "file":
        file_path = state.get("file_path", "") or ""
        sections = [
            f"FILE: {file_path}",
            "SNIPPET:",
            snippet,
            "",
            "CONTEXT:",
            context,
            "",
        ]
    else:
        original_file = state.get("original_file") or ""
        sections = [
            "ORIGINAL_FILE:",
            original_file,
            "",
            "FILE_CHANGES:",
            snippet,
            "",
            "CONTEXT:",
            context,
            "",
        ]

    return "\n".join(sections)


def _post_process_reviews(
    reviews: list[dict],
    file_path: str,
) -> list[dict]:
    """Enrich parsed reviews with derived metadata."""
    normalized_reviews = reviews or []
    try:
        enrich_issues(file_path, normalized_reviews)
    except Exception:
        pass

    return normalized_reviews


def review_node_retrieve(state: ReviewState) -> ReviewState:
    cp = state.get("context_prompt", "")
    code = retrieve_text(state["retriever_code"], cp)
    docs = retrieve_text(state["retriever_docs"], cp)
    context = synthesize_context(code, docs)
    new_state: ReviewState = dict(state)
    new_state["context"] = context
    return new_state


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
    new_state: ReviewState = dict(state)
    new_state["system_prompt"] = system
    return new_state


def review_node_llm(
    state: ReviewState,
    structured_node,
    fallback_node=None,
) -> ReviewState:
    body_text = _build_body_text(state)
    system_prompt = state.get("system_prompt") or ""
    payload = {"system_prompt": system_prompt, "body_text": body_text}
    raw = None
    attempts = (
        (structured_node, logger.warning, "Structured review invocation failed: %s"),
        (fallback_node, logger.error, "Fallback review invocation failed: %s"),
    )
    for runnable, log_fn, message in attempts:
        if runnable is None:
            continue
        if raw not in (None, ""):
            break
        try:
            raw = runnable.invoke(payload)
        except Exception as exc:
            log_fn(message, exc)
            raw = None

    reviews = _normalize_reviews(raw)
    new_state: ReviewState = dict(state)
    new_state["parsed_reviews"] = reviews
    return new_state


def review_node_parse(state: ReviewState) -> ReviewState:
    reviews = state.get("parsed_reviews") or []
    normalized = _post_process_reviews(
        reviews,
        state.get("file_path", "") or "",
    )

    new_state: ReviewState = dict(state)
    new_state["parsed_reviews"] = normalized
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
    ):
        self.llm_provider = llm_provider
        self.plugin_config = plugin_config
        self.custom_prompt_text = custom_prompt_text
        self.custom_guidance_precedence = custom_guidance_precedence or ""
        self.llama_query_model = llama_query_model
        self.max_token_length = max_token_length
        self._schema_prompt_section = review_schema_prompt()

        self.report_prompt = self.plugin_config.get("general_prompts", {}).get(
            "security_review_report", ""
        )

        self._structured_review_node = None
        self._fallback_review_node = None
        self._structured_review_node = self._create_structured_review_runnable()
        if self._structured_review_node is None and self._fallback_review_node is None:
            raise RuntimeError(
                "Unable to create review runnable; OpenAI-based provider required."
            )
        self._app_cache = {}

    def _create_structured_review_runnable(self):
        get_chat_model = getattr(self.llm_provider, "get_chat_model", None)
        if not callable(get_chat_model):
            return None
        try:
            chat_model = get_chat_model(model=self.llama_query_model)
        except Exception as exc:
            logger.warning(
                "Unable to instantiate chat model for structured output: %s", exc
            )
            return None
        prompt = ChatPromptTemplate.from_messages(
            [("system", "{system_prompt}"), ("user", "{body_text}")]
        )
        self._fallback_review_node = prompt | chat_model | StrOutputParser()
        try:
            structured_model = chat_model.with_structured_output(
                ReviewResponseModel, method="function_calling"
            )
        except Exception as exc:
            logger.warning(
                "Failed to bind structured output schema for review graph: %s", exc
            )
            return None
        return prompt | structured_model

    def _build_app(self, language_prompts, default_prompt_key):
        cache_key = (id(language_prompts), default_prompt_key)
        cached = self._app_cache.get(cache_key)
        if cached is not None:
            return cached

        graph = StateGraph(ReviewState)
        retrieve = review_node_retrieve
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
            structured_node=self._structured_review_node,
            fallback_node=self._fallback_review_node,
        )
        parse = review_node_parse

        graph.add_node("retrieve", retrieve)
        graph.add_node("build_prompt", build_prompt)
        graph.add_node("review", review)
        graph.add_node("parse", parse)

        graph.set_entry_point("retrieve")
        graph.add_edge("retrieve", "build_prompt")
        graph.add_edge("build_prompt", "review")
        graph.add_edge("review", "parse")
        graph.add_edge("parse", END)

        compiled = graph.compile(cache=InMemoryCache())
        self._app_cache[cache_key] = compiled
        return compiled

    def review(self, request: ReviewRequest):
        file_path = request["file_path"]
        snippet = request["snippet"]
        retriever_code = request["retriever_code"]
        retriever_docs = request["retriever_docs"]
        context_prompt = request["context_prompt"]
        language_prompts = request["language_prompts"]
        default_prompt_key = request.get("default_prompt_key", "security_review_file")
        relative_file = request.get("relative_file")
        mode = request.get("mode", "file")
        original_file = request.get("original_file")

        chunks = split_snippet(snippet, self.max_token_length)
        accumulated = []
        app = self._build_app(language_prompts, default_prompt_key)
        for chunk in chunks:
            state = {
                "file_path": file_path,
                "snippet": chunk,
                "retriever_code": retriever_code,
                "retriever_docs": retriever_docs,
                "context_prompt": context_prompt,
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
