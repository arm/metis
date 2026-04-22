# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import logging
from functools import partial
from typing import Any, cast

from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langgraph.graph import StateGraph, END
from langgraph.cache.memory import InMemoryCache

from metis.engine.retrieval_support import retrieve_context_deterministic
from metis.utils import split_snippet, parse_json_output, enrich_issues
from .review_retrieval import (
    assess_review_context_quality,
    build_review_evidence_frame,
    build_review_retrieval_query,
    compute_review_obligation_coverage,
)
from .review_tools import build_review_langchain_tools, run_review_tool_phase
from .schemas import ReviewResponseModel, review_schema_prompt
from .utils import (
    build_review_system_prompt,
    sanitize_review_payload,
    synthesize_context,
)
from .types import ReviewRequest, ReviewState

logger = logging.getLogger("metis")

_REVIEW_BASELINE_CONTEXT_MAX_CHARS = 3600
_REVIEW_BASELINE_CODE_CONTEXT_CHARS = 2600
_REVIEW_BASELINE_DOC_CONTEXT_CHARS = 1000


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


def _build_body_text(state: ReviewState, *, include_tool_evidence: bool = True) -> str:
    """
    Format the user/body portion of the review prompt based on mode.
    """
    snippet = state.get("snippet", "") or ""
    baseline_context = state.get("baseline_context", "") or ""
    review_evidence_frame = state.get("review_evidence_frame", "") or ""
    tool_evidence = state.get("tool_evidence", "") or ""
    mode = state.get("mode", "file")

    if mode == "file":
        file_path = state.get("file_path", "") or ""
        sections = [
            f"FILE: {file_path}",
            "SNIPPET:",
            snippet,
            "",
        ]
        if baseline_context:
            sections.extend(["BASELINE_CONTEXT:", baseline_context, ""])
        if review_evidence_frame:
            sections.extend(["REVIEW_EVIDENCE_FRAME:", review_evidence_frame, ""])
        if include_tool_evidence and tool_evidence:
            sections.extend(["TOOL_EVIDENCE:", tool_evidence, ""])
    else:
        file_path = state.get("file_path", "") or ""
        original_file = state.get("original_file") or ""
        sections = [
            "FILE_PATH:",
            file_path,
            "",
            "ORIGINAL_FILE:",
            original_file,
            "",
            "FILE_CHANGES:",
            snippet,
            "",
        ]
        if baseline_context:
            sections.extend(["BASELINE_CONTEXT:", baseline_context, ""])
        if review_evidence_frame:
            sections.extend(["REVIEW_EVIDENCE_FRAME:", review_evidence_frame, ""])
        if include_tool_evidence and tool_evidence:
            sections.extend(["TOOL_EVIDENCE:", tool_evidence, ""])

    return "\n".join(sections)


def _emit_review_debug(debug_callback, event: str, **payload) -> None:
    if not callable(debug_callback):
        return
    try:
        debug_callback({"event": event, **payload})
    except Exception:
        logger.debug("Review debug callback failed", exc_info=True)


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


def review_node_build_prompt(
    state: ReviewState,
    language_prompts: dict,
    default_prompt_key: str,
    report_prompt: str,
    custom_prompt_text: str | None,
    custom_guidance_precedence: str,
    schema_prompt_section: str,
    hardware_cwe_guidance: str = "",
    tool_guidance: str = "",
) -> ReviewState:
    retrieval_enabled = bool(state.get("use_retrieval_context", True))
    new_state = cast(ReviewState, dict(state))
    grounding_guidance = ""
    if retrieval_enabled:
        grounding_guidance = (
            "Additional retrieval grounding may be provided as BASELINE_CONTEXT and "
            "REVIEW_EVIDENCE_FRAME. Treat BASELINE_CONTEXT as deterministic repository "
            "context and REVIEW_EVIDENCE_FRAME as evidence obligations plus likely gaps. "
            "If either section is empty, ignore it."
        )
    system = build_review_system_prompt(
        language_prompts,
        default_prompt_key,
        report_prompt,
        custom_prompt_text,
        custom_guidance_precedence,
        schema_prompt_section,
        hardware_cwe_guidance,
        tool_guidance=(
            "\n".join(part for part in (grounding_guidance, tool_guidance) if part)
            if retrieval_enabled
            else ""
        ),
    )
    new_state["system_prompt"] = system
    return new_state


def review_node_collect_baseline_context(state: ReviewState) -> ReviewState:
    new_state = cast(ReviewState, dict(state))
    new_state["baseline_context_query"] = ""
    new_state["baseline_context"] = ""
    new_state["baseline_context_quality"] = ""
    new_state["review_evidence_frame"] = ""
    if not bool(state.get("use_retrieval_context", True)):
        return new_state

    query, symbols, focus_terms = build_review_retrieval_query(
        file_path=str(state.get("file_path", "") or ""),
        relative_file=str(state.get("relative_file", "") or ""),
        mode=str(state.get("mode", "file") or "file"),
        snippet=str(state.get("snippet", "") or ""),
        original_file=str(state.get("original_file", "") or ""),
    )
    code = retrieve_context_deterministic(
        state.get("retriever_code"),
        query,
        max_chars=_REVIEW_BASELINE_CODE_CONTEXT_CHARS,
    )
    docs = retrieve_context_deterministic(
        state.get("retriever_docs"),
        query,
        max_chars=_REVIEW_BASELINE_DOC_CONTEXT_CHARS,
    )

    code_ok, code_quality = assess_review_context_quality(
        code,
        file_path=str(state.get("file_path", "") or ""),
        symbols=symbols,
        focus_terms=focus_terms,
    )
    docs_ok, docs_quality = assess_review_context_quality(
        docs,
        file_path=str(state.get("file_path", "") or ""),
        symbols=symbols,
        focus_terms=focus_terms,
    )

    accepted_code = code if code_ok else ""
    accepted_docs = docs if docs_ok else ""
    baseline_context = synthesize_context(accepted_code, accepted_docs)
    quality_parts = [
        f"code={code_quality or 'empty'}",
        f"docs={docs_quality or 'empty'}",
    ]
    if baseline_context and len(baseline_context) > _REVIEW_BASELINE_CONTEXT_MAX_CHARS:
        baseline_context = (
            baseline_context[:_REVIEW_BASELINE_CONTEXT_MAX_CHARS] + "\n...[truncated]"
        )

    new_state["baseline_context_query"] = query
    new_state["baseline_context"] = baseline_context
    new_state["baseline_context_quality"] = ", ".join(quality_parts)
    baseline_coverage = compute_review_obligation_coverage(
        baseline_context,
        symbols=symbols,
        focus_terms=focus_terms,
    )
    new_state["review_evidence_frame"] = build_review_evidence_frame(
        query=query,
        symbols=symbols,
        focus_terms=focus_terms,
        baseline_quality=new_state["baseline_context_quality"],
        baseline_context=baseline_context,
        coverage=baseline_coverage,
    )
    _emit_review_debug(
        state.get("debug_callback"),
        "retrieval",
        query=query,
        code_quality=code_quality,
        docs_quality=docs_quality,
        baseline_context=baseline_context,
    )
    return new_state


def review_node_collect_tool_evidence(
    state: ReviewState,
    *,
    chat_model,
    toolbox,
    tool_system_prompt: str,
    tool_system_prompt_no_rag: str,
) -> ReviewState:
    new_state = cast(ReviewState, dict(state))
    new_state["tool_evidence"] = ""
    if toolbox is None or chat_model is None:
        return new_state
    if not hasattr(chat_model, "bind_tools"):
        return new_state

    active_toolbox = (
        toolbox
        if bool(state.get("use_retrieval_context", True))
        else toolbox.without("rag_search")
    )
    active_tool_prompt = (
        tool_system_prompt
        if bool(state.get("use_retrieval_context", True))
        else tool_system_prompt_no_rag
    )
    tools, tools_by_name = build_review_langchain_tools(
        active_toolbox,
        retriever_code=state.get("retriever_code"),
        retriever_docs=state.get("retriever_docs"),
        debug_callback=state.get("debug_callback"),
    )
    if not tools:
        return new_state

    baseline_query, symbols, focus_terms = build_review_retrieval_query(
        file_path=str(state.get("file_path", "") or ""),
        relative_file=str(state.get("relative_file", "") or ""),
        mode=str(state.get("mode", "file") or "file"),
        snippet=str(state.get("snippet", "") or ""),
        original_file=str(state.get("original_file", "") or ""),
    )
    baseline_coverage = compute_review_obligation_coverage(
        str(state.get("baseline_context", "") or ""),
        symbols=symbols,
        focus_terms=focus_terms,
    )

    try:
        outputs = run_review_tool_phase(
            chat_model=chat_model,
            tools=tools,
            tools_by_name=tools_by_name,
            system_prompt=active_tool_prompt,
            body_text=_build_body_text(state, include_tool_evidence=False),
            review_search_context={
                "file_path": str(state.get("file_path", "") or ""),
                "mode": str(state.get("mode", "file") or "file"),
                "symbols": symbols,
                "focus_terms": focus_terms,
                "baseline_query": baseline_query,
                "uncovered_obligations": [
                    name for name, covered in baseline_coverage.items() if not covered
                ],
            },
        )
    except Exception as exc:
        logger.warning("Review tool evidence phase failed: %s", exc)
        return new_state

    new_state["tool_evidence"] = outputs.get("tool_evidence", "") or ""
    combined_evidence = "\n\n".join(
        part
        for part in (
            str(state.get("baseline_context", "") or "").strip(),
            new_state["tool_evidence"].strip(),
        )
        if part
    )
    combined_coverage = compute_review_obligation_coverage(
        combined_evidence,
        symbols=symbols,
        focus_terms=focus_terms,
    )
    new_state["review_evidence_frame"] = build_review_evidence_frame(
        query=baseline_query,
        symbols=symbols,
        focus_terms=focus_terms,
        baseline_quality=str(state.get("baseline_context_quality", "") or ""),
        baseline_context=str(state.get("baseline_context", "") or ""),
        coverage=combined_coverage,
    )
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
    new_state = cast(ReviewState, dict(state))
    new_state["parsed_reviews"] = reviews
    return new_state


def review_node_parse(state: ReviewState) -> ReviewState:
    reviews = state.get("parsed_reviews") or []
    normalized = _post_process_reviews(
        reviews,
        state.get("file_path", "") or "",
    )

    new_state = cast(ReviewState, dict(state))
    new_state["parsed_reviews"] = normalized
    return new_state


class ReviewGraph:
    def __init__(
        self,
        llm_provider,
        toolbox,
        plugin_config,
        custom_prompt_text,
        custom_guidance_precedence,
        llama_query_model,
        max_token_length,
        chat_model_kwargs: dict[str, Any] | None = None,
    ):
        self.llm_provider = llm_provider
        self.toolbox = toolbox
        self.plugin_config = plugin_config
        self.custom_prompt_text = custom_prompt_text
        self.custom_guidance_precedence = custom_guidance_precedence or ""
        self.llama_query_model = llama_query_model
        self.max_token_length = max_token_length
        self.chat_model_kwargs = chat_model_kwargs or {}
        self._schema_prompt_section = review_schema_prompt()

        self.report_prompt = self.plugin_config.get("general_prompts", {}).get(
            "security_review_report", ""
        )
        self.review_tool_guidance = self.plugin_config.get("general_prompts", {}).get(
            "review_tool_guidance", ""
        )
        self.review_tool_system_prompt = self.plugin_config.get(
            "general_prompts", {}
        ).get(
            "review_tool_system_prompt",
            (
                "You are gathering grounded static evidence for a security review. "
                "Use tools only when they materially improve confidence. "
                "Prefer local inspection first with sed/cat, then broader lookup with grep/find_name. "
                "Keep tool use bounded and return a concise plain-text evidence summary."
            ),
        )
        self.review_tool_system_prompt_no_rag = self.plugin_config.get(
            "general_prompts", {}
        ).get(
            "review_tool_system_prompt_no_rag",
            (
                "You are gathering grounded static evidence for a security review. "
                "Use tools only when they materially improve confidence. "
                "Prefer local inspection first with sed/cat on the current file or hunk. "
                "Use grep or find_name for broader lookup only when direct local inspection is not enough. "
                "Keep tool use bounded and evidence-driven. "
                "After finishing tool use, return a concise plain-text evidence summary. Do not return JSON."
            ),
        )
        self.hardware_cwe_guidance = self.plugin_config.get("general_prompts", {}).get(
            "hardware_cwe_guidance", ""
        )

        self._review_chat_model = None
        self._structured_review_node = None
        self._fallback_review_node = None
        self._structured_review_node = self._create_review_runnables()
        if self._structured_review_node is None and self._fallback_review_node is None:
            raise RuntimeError(
                "Unable to create review runnable; OpenAI-based provider required."
            )
        self._app_cache: dict[tuple[int, str], Any] = {}

    def _create_review_runnables(self):
        get_chat_model = getattr(self.llm_provider, "get_chat_model", None)
        if not callable(get_chat_model):
            return None
        try:
            chat_model = get_chat_model(
                model=self.llama_query_model, **self.chat_model_kwargs
            )
        except Exception as exc:
            logger.warning(
                "Unable to instantiate chat model for structured output: %s", exc
            )
            return None
        self._review_chat_model = chat_model
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
        build_prompt = partial(
            review_node_build_prompt,
            language_prompts=language_prompts,
            default_prompt_key=default_prompt_key,
            report_prompt=self.report_prompt,
            tool_guidance=self.review_tool_guidance,
            custom_prompt_text=self.custom_prompt_text,
            custom_guidance_precedence=self.custom_guidance_precedence,
            schema_prompt_section=self._schema_prompt_section,
            hardware_cwe_guidance=self.hardware_cwe_guidance,
        )
        collect_baseline_context = review_node_collect_baseline_context
        collect_tool_evidence = partial(
            review_node_collect_tool_evidence,
            chat_model=self._review_chat_model,
            toolbox=self.toolbox,
            tool_system_prompt=self.review_tool_system_prompt,
            tool_system_prompt_no_rag=self.review_tool_system_prompt_no_rag,
        )
        review = partial(
            review_node_llm,
            structured_node=self._structured_review_node,
            fallback_node=self._fallback_review_node,
        )
        parse = review_node_parse

        graph.add_node("build_prompt", build_prompt)
        graph.add_node("collect_baseline_context", collect_baseline_context)
        graph.add_node("collect_tool_evidence", collect_tool_evidence)
        graph.add_node("review", review)
        graph.add_node("parse", parse)

        graph.set_entry_point("build_prompt")
        graph.add_edge("build_prompt", "collect_baseline_context")
        graph.add_edge("collect_baseline_context", "collect_tool_evidence")
        graph.add_edge("collect_tool_evidence", "review")
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
        language_prompts = request["language_prompts"]
        default_prompt_key = request.get("default_prompt_key", "security_review_file")
        relative_file = request.get("relative_file")
        mode = request.get("mode", "file")
        original_file = request.get("original_file")
        use_retrieval_context = bool(request.get("use_retrieval_context", True))
        debug_callback = request.get("debug_callback")

        chunks = split_snippet(snippet, self.max_token_length)
        accumulated: list[dict] = []
        app = self._build_app(language_prompts, default_prompt_key)
        for chunk in chunks:
            state = {
                "file_path": file_path,
                "snippet": chunk,
                "retriever_code": retriever_code,
                "retriever_docs": retriever_docs,
                "relative_file": relative_file,
                "mode": mode,
                "original_file": original_file,
                "use_retrieval_context": use_retrieval_context,
                "debug_callback": debug_callback,
            }
            out = app.invoke(state)
            chunk_reviews = out.get("parsed_reviews", []) or []
            if chunk_reviews:
                accumulated.extend(chunk_reviews)

        if not accumulated:
            file_display = relative_file if relative_file else file_path
            empty_result: dict[str, Any] = {
                "file": file_display,
                "file_path": file_path,
                "reviews": [],
            }
            return empty_result

        file_display = relative_file if relative_file else file_path
        result: dict[str, Any] = {
            "file": file_display,
            "file_path": file_path,
            "reviews": accumulated,
        }

        return result
