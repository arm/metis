# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import logging
import json
from functools import partial
from typing import Optional, Callable

from langchain_core.runnables import RunnableLambda
from langgraph.graph import StateGraph, END

from metis.utils import parse_json_output, split_snippet
from metis.utils import llm_call
from metis.utils import enrich_issues
from .utils import (
    retrieve_text,
    synthesize_context,
    build_review_system_prompt,
    get_review_schema,
    validate_json_schema,
)
from .types import ReviewRequest, ReviewState


logger = logging.getLogger("metis")


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
) -> ReviewState:
    system = build_review_system_prompt(
        language_prompts,
        default_prompt_key,
        report_prompt,
        custom_prompt_text,
        custom_guidance_precedence,
    )
    new_state: ReviewState = dict(state)
    new_state["system_prompt"] = system
    return new_state


def review_node_llm(state: ReviewState, review_node: RunnableLambda) -> ReviewState:
    snippet = state.get("snippet", "")
    context = state.get("context", "")
    file_path = state.get("file_path", "")
    mode = state.get("mode", "file")
    if mode == "file":
        body_text = "\n".join(
            [
                f"FILE: {file_path}",
                "SNIPPET:",
                snippet or "",
                "",
                "CONTEXT:",
                context or "",
                "",
            ]
        )
    else:
        original_file = state.get("original_file") or ""
        body_text = "\n".join(
            [
                "ORIGINAL_FILE:",
                original_file,
                "",
                "FILE_CHANGES:",
                snippet or "",
                "",
                "CONTEXT:",
                context or "",
                "",
            ]
        )
    system_prompt = state.get("system_prompt") or ""
    raw = review_node.invoke(
        {"system_prompt": system_prompt, "payload": {"body_text": body_text}}
    )
    new_state: ReviewState = dict(state)
    new_state["raw_review"] = raw
    return new_state


def review_node_parse(
    state: ReviewState,
    validate_fn: Optional[Callable] = None,
    repair_fn: Optional[Callable] = None,
) -> ReviewState:
    raw = state.get("raw_review") or ""
    parsed = parse_json_output(raw)
    reviews = []
    schema_valid = False
    if isinstance(parsed, dict) and "reviews" in parsed:
        if validate_fn is not None:
            if not validate_fn(parsed) and repair_fn is not None:
                fixed = repair_fn(raw)
                if isinstance(fixed, dict) and validate_fn(fixed):
                    parsed = fixed
            schema_valid = bool(validate_fn(parsed))
        else:
            schema_valid = True

        try:
            enrich_issues(state.get("file_path", ""), parsed.get("reviews", []))
        except Exception:
            pass
        reviews = parsed.get("reviews", []) or []

    new_state: ReviewState = dict(state)
    new_state["parsed_reviews"] = reviews
    new_state["schema_valid"] = schema_valid
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

        self.report_prompt = self.plugin_config.get("general_prompts", {}).get(
            "security_review_report", ""
        )

        self._review_node = RunnableLambda(self._run_llm_review)
        self._app_cache = {}
        self._review_schema = get_review_schema()
        self._validate_review = lambda obj: validate_json_schema(
            obj, self._review_schema
        )

    def _repair_to_schema(self, raw_output):
        """In case where the output is not conformant to the schema, try to repair it."""
        system_prompt = (
            "You convert model output into strictly valid JSON that conforms to the given schema. "
            "Output JSON only, with no code fences or commentary."
        )
        try:
            schema_str = json.dumps(self._review_schema)
        except Exception:
            schema_str = '{"type":"object","properties":{"reviews":{"type":"array"}}}'
        user_prompt = (
            "Schema:\n" + schema_str + "\n\n"
            "ModelOutput:\n" + (raw_output or "") + "\n\n"
            "Return: Only a JSON object matching the schema."
        )
        fixed = llm_call(
            self.llm_provider, system_prompt, user_prompt, model=self.llama_query_model
        )
        parsed = parse_json_output(fixed)
        return parsed

    def _run_llm_review(self, inputs):
        system_prompt = inputs["system_prompt"]
        payload = inputs.get("payload", {})

        if isinstance(payload, dict) and "body_text" in payload:
            prompt_text = str(payload.get("body_text") or "")
        else:
            lines = []
            for k, v in payload.items():
                lines.append(f"{k}:\n{v}")
            prompt_text = "\n\n".join(lines) + "\n"
        answer = llm_call(
            self.llm_provider, system_prompt, prompt_text, model=self.llama_query_model
        )
        if not answer:
            return '{"reviews": []}'
        return answer

    def _build_app(self, language_prompts, default_prompt_key):
        cache_key = (id(language_prompts), default_prompt_key)
        cached = self._app_cache.get(cache_key)
        if cached is not None:
            return cached

        graph = StateGraph(ReviewState)
        retrieve = partial(review_node_retrieve)
        build_prompt = partial(
            review_node_build_prompt,
            language_prompts=language_prompts,
            default_prompt_key=default_prompt_key,
            report_prompt=self.report_prompt,
            custom_prompt_text=self.custom_prompt_text,
            custom_guidance_precedence=self.custom_guidance_precedence,
        )
        review = partial(
            review_node_llm,
            review_node=self._review_node,
        )
        parse = partial(
            review_node_parse,
            validate_fn=self._validate_review,
            repair_fn=self._repair_to_schema,
        )

        graph.add_node("retrieve", retrieve)
        graph.add_node("build_prompt", build_prompt)
        graph.add_node("review", review)
        graph.add_node("parse", parse)

        graph.set_entry_point("retrieve")
        graph.add_edge("retrieve", "build_prompt")
        graph.add_edge("build_prompt", "review")
        graph.add_edge("review", "parse")
        graph.add_edge("parse", END)

        compiled = graph.compile()
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
