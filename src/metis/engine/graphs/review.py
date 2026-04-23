# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import logging
import re
from functools import partial
from typing import Any, cast

from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langgraph.cache.memory import InMemoryCache
from langgraph.graph import END, StateGraph

from metis.utils import enrich_issues, parse_json_output, split_snippet

from .review_tools import build_review_langchain_tools, run_review_tool_phase
from .schemas import ReviewResponseModel, review_schema_prompt
from .types import ReviewRequest, ReviewState
from .utils import (
    build_review_system_prompt,
    retrieve_text,
    sanitize_review_payload,
    synthesize_context,
)

logger = logging.getLogger("metis")

_REVIEW_RAG_RESULT_CHARS = 2200
_REVIEW_OBLIGATION_CONTEXT_CHARS = 6000
_IDENTIFIER_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]{2,}\b")
_COMMON_IDENTIFIERS = {
    "and",
    "const",
    "def",
    "else",
    "for",
    "if",
    "int",
    "let",
    "return",
    "static",
    "struct",
    "the",
    "var",
    "void",
    "while",
}

_REVIEW_RAG_OBLIGATIONS = {
    "callers/reachability": (
        "Which callers, wrappers, API routes, or integration points reach this reviewed code, "
        "and can that path be external, cross-boundary, or attacker influenced?"
    ),
    "input/trust boundary": (
        "Which inputs or state reaching this code are externally controlled or cross a trust boundary, "
        "and where does that boundary come from?"
    ),
    "validation/authorization": (
        "Where are validation, sanitization, bounds checks, authorization checks, or enforcement responsibilities "
        "for this path defined or applied?"
    ),
    "memory/bounds": (
        "What evidence explains buffer sizes, allocation sizes, index ranges, pointer ownership, "
        "or bounds guarantees for the reviewed memory operations?"
    ),
    "lifetime/concurrency": (
        "What evidence explains object lifetime, ownership transfer, locking, reference counting, "
        "or concurrency guarantees for this reviewed code?"
    ),
}

DEFAULT_REVIEW_RAG_EVIDENCE_GUIDANCE = """
3. How to Use RAG Evidence
   - TOOL_EVIDENCE may include deterministic retrieval, OBLIGATION_RAG sections, and RAG_TOOL_RESULTS from rag_search.
   - Treat RAG as supporting context only. FILE, FILE_CHANGES, and ORIGINAL_FILE remain authoritative for the code being reviewed.
   - OBLIGATION_RAG sections are grouped by evidence obligation, such as callers/reachability, input/trust boundary, validation/authorization, memory/bounds, or lifetime/concurrency.
   - Ignore RAG sections that are empty, unavailable, generic, unrelated, or not clearly tied to the current file, symbols, data flow, or security condition.
   - Do not report a finding solely because RAG mentions a threat model, component purpose, possible caller, or security expectation. A report still needs concrete vulnerable behavior in the reviewed code plus plausible security impact.
   - If RAG conflicts with the reviewed code, prefer the reviewed code and lower confidence unless the conflict is resolved by concrete evidence.
   - Prefer returning an empty reviews list over speculative findings when RAG is weak, noisy, or only describes background design.
""".strip()

DEFAULT_REVIEW_RAG_TOOL_PROMPT = """
You are gathering optional RAG context for a security code review.
You have exactly one tool: rag_search.

Use rag_search only when one specific missing fact would materially change review confidence.
Do not ask for generic project or component summaries; obligation-focused RAG evidence is collected separately.
Prefer one focused query. Use a second query only for a different concrete obligation.

Good queries name the file, function, API, or changed behavior and ask one security question about:
- externally controlled inputs or reachability
- callers, wrappers, or integration points
- validation, sanitization, authorization, or enforcement responsibilities
- trust or privilege boundaries
- intended security contract documented elsewhere

If results are empty, unavailable, generic, or off-topic, say that no useful RAG evidence was found and stop.
Summarize only concrete evidence that is relevant to the reviewed code, plus any unresolved gap.
Do not turn broad design context into a vulnerability by itself.
Return a short plain-text summary, not JSON.
""".strip()


def _emit_review_debug(debug_callback, event: str, **payload) -> None:
    if not callable(debug_callback):
        return
    try:
        debug_callback({"event": event, **payload})
    except Exception:
        logger.debug("Review debug callback failed", exc_info=True)


def _normalize_reviews(raw) -> list[dict]:
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


def _clip_review_rag_text(text: str, limit: int) -> str:
    value = str(text or "")
    if len(value) <= limit:
        return value
    return value[:limit] + "\n...[truncated]"


def _extract_review_identifiers(snippet: str, *, limit: int = 10) -> list[str]:
    seen: set[str] = set()
    identifiers: list[str] = []
    for match in _IDENTIFIER_RE.finditer(snippet):
        identifier = match.group(0)
        lowered = identifier.lower()
        if lowered in _COMMON_IDENTIFIERS or lowered in seen:
            continue
        seen.add(lowered)
        identifiers.append(identifier)
        if len(identifiers) >= limit:
            break
    return identifiers


def _has_any(text: str, terms: tuple[str, ...]) -> bool:
    lowered = text.lower()
    return any(term in lowered for term in terms)


def _select_review_rag_obligations(state: ReviewState) -> list[str]:
    snippet = str(state.get("snippet", "") or "")
    selected = ["callers/reachability"]

    if _has_any(
        snippet,
        (
            "argv",
            "env",
            "http",
            "input",
            "ioctl",
            "parse",
            "read",
            "recv",
            "request",
            "socket",
            "user",
        ),
    ):
        selected.append("input/trust boundary")

    if _has_any(
        snippet,
        (
            "access",
            "auth",
            "bound",
            "check",
            "escape",
            "permission",
            "priv",
            "sanit",
            "token",
            "valid",
        ),
    ):
        selected.append("validation/authorization")

    if _has_any(
        snippet,
        (
            "alloc",
            "array",
            "buf",
            "copy",
            "free",
            "index",
            "malloc",
            "mem",
            "ptr",
            "size",
            "str",
        ),
    ):
        selected.append("memory/bounds")

    if _has_any(
        snippet,
        (
            "atomic",
            "free",
            "lock",
            "mutex",
            "ref",
            "release",
            "thread",
            "unlock",
        ),
    ):
        selected.append("lifetime/concurrency")

    if len(selected) == 1:
        selected.append("validation/authorization")

    deduped: list[str] = []
    for obligation in selected:
        if obligation not in deduped:
            deduped.append(obligation)
    return deduped[:3]


def _build_obligation_rag_query(state: ReviewState, obligation: str) -> str:
    file_path = str(state.get("file_path", "") or "")
    mode = str(state.get("mode", "file") or "file")
    snippet = str(state.get("snippet", "") or "")
    identifiers = _extract_review_identifiers(snippet)
    question = _REVIEW_RAG_OBLIGATIONS[obligation]
    id_text = ", ".join(identifiers) if identifiers else "<none extracted>"
    subject = "FILE_CHANGES" if mode == "patch" else "SNIPPET"
    return (
        "Security review obligation-focused RAG lookup.\n"
        f"File: {file_path or '<unknown>'}\n"
        f"Mode: {mode}\n"
        f"Evidence obligation: {obligation}\n"
        f"Relevant identifiers: {id_text}\n"
        f"Question: {question}\n\n"
        f"{subject}:\n{snippet}\n\n"
        "Return concrete code or documentation evidence only when it is tied to this file, "
        "these identifiers, or this security obligation."
    )


def _rag_result_has_signal(result: str) -> bool:
    text = str(result or "").strip()
    if not text:
        return False
    lowered = text.lower()
    if "tool execution failed:" in lowered:
        return False
    if "[rag_search]\nempty query" in lowered:
        return False
    if "retrieval unavailable; continuing without indexed context" in lowered:
        return False
    if "[code_rag]\n<none>" in lowered and "[docs_rag]\n<none>" in lowered:
        return False
    return bool(text.replace("<none>", "").strip())


def _build_review_context_query(state: ReviewState) -> str:
    return _build_obligation_rag_query(state, "callers/reachability")


def _build_body_text(state: ReviewState) -> str:
    snippet = state.get("snippet", "") or ""
    context = state.get("context", "") or ""
    obligation_context = state.get("obligation_context", "") or ""
    project_context = state.get("project_context", "") or ""
    tool_evidence = state.get("tool_evidence", "") or ""
    mode = state.get("mode", "file")
    include_context = bool(state.get("use_retrieval_context", True))
    combined_tool_evidence = "\n\n".join(
        part
        for part in (
            context.strip(),
            obligation_context.strip(),
            project_context.strip(),
            tool_evidence.strip(),
        )
        if part
    )

    if mode == "file":
        file_path = state.get("file_path", "") or ""
        sections = [
            f"FILE: {file_path}",
            "SNIPPET:",
            snippet,
            "",
        ]
        if include_context and combined_tool_evidence:
            sections.extend(["TOOL_EVIDENCE:", combined_tool_evidence, ""])
    else:
        original_file = state.get("original_file") or ""
        sections = [
            "ORIGINAL_FILE:",
            original_file,
            "",
            "FILE_CHANGES:",
            snippet,
            "",
        ]
        if include_context and combined_tool_evidence:
            sections.extend(["TOOL_EVIDENCE:", combined_tool_evidence, ""])

    return "\n".join(sections)


def _post_process_reviews(reviews: list[dict], file_path: str) -> list[dict]:
    normalized_reviews = reviews or []
    try:
        enrich_issues(file_path, normalized_reviews)
    except Exception:
        pass
    return normalized_reviews


def review_node_retrieve(state: ReviewState) -> ReviewState:
    new_state = cast(ReviewState, dict(state))
    if not state.get("use_retrieval_context", True):
        new_state["context"] = ""
        return new_state

    query = _build_review_context_query(state)
    code = retrieve_text(state.get("retriever_code"), query)
    docs = retrieve_text(state.get("retriever_docs"), query)
    context = synthesize_context(code, docs)
    new_state["context"] = (
        "\n".join(
            [
                "[DETERMINISTIC_RAG]",
                "obligation=callers/reachability",
                "[RAG_RESULT]",
                context,
            ]
        )
        if context
        else ""
    )
    return new_state


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
    new_state = cast(ReviewState, dict(state))
    system = build_review_system_prompt(
        language_prompts,
        default_prompt_key,
        report_prompt,
        custom_prompt_text,
        custom_guidance_precedence,
        schema_prompt_section,
        hardware_cwe_guidance,
        tool_guidance=tool_guidance if state.get("use_retrieval_context", True) else "",
    )
    new_state["system_prompt"] = system
    return new_state


def review_node_collect_tool_evidence(
    state: ReviewState,
    *,
    chat_model,
    toolbox,
    tool_system_prompt: str,
) -> ReviewState:
    new_state = cast(ReviewState, dict(state))
    new_state["tool_evidence"] = ""
    if toolbox is None or chat_model is None:
        return new_state
    if not bool(state.get("use_retrieval_context", True)):
        return new_state
    if not hasattr(chat_model, "bind_tools"):
        return new_state

    tools, tools_by_name = build_review_langchain_tools(
        toolbox,
        retriever_code=state.get("retriever_code"),
        retriever_docs=state.get("retriever_docs"),
        debug_callback=state.get("debug_callback"),
    )
    if not tools:
        return new_state

    try:
        outputs = run_review_tool_phase(
            chat_model=chat_model,
            tools=tools,
            tools_by_name=tools_by_name,
            system_prompt=tool_system_prompt,
            body_text=_build_body_text(state),
        )
    except Exception as exc:
        logger.warning("Review rag tool phase failed: %s", exc)
        return new_state

    new_state["tool_evidence"] = outputs.get("tool_evidence", "") or ""
    return new_state


def review_node_collect_obligation_context(
    state: ReviewState,
    *,
    toolbox,
) -> ReviewState:
    new_state = cast(ReviewState, dict(state))
    new_state["obligation_context"] = ""
    if toolbox is None:
        return new_state
    if not bool(state.get("use_retrieval_context", True)):
        return new_state
    if not getattr(toolbox, "has", lambda _name: False)("rag_search"):
        return new_state

    sections: list[str] = []
    obligations = _select_review_rag_obligations(state)
    if str(state.get("context", "") or "").strip():
        obligations = [
            obligation
            for obligation in obligations
            if obligation != "callers/reachability"
        ]

    for obligation in obligations:
        query = _build_obligation_rag_query(state, obligation)
        try:
            result = toolbox.rag_search(
                query,
                retriever_code=state.get("retriever_code"),
                retriever_docs=state.get("retriever_docs"),
            )
        except Exception as exc:
            logger.warning(
                "Review obligation rag_search failed for %s: %s", obligation, exc
            )
            continue

        _emit_review_debug(
            state.get("debug_callback"),
            "tool_call",
            tool_name="obligation_rag_search",
            tool_args={"obligation": obligation, "query": query},
            tool_output=result,
        )

        result_text = str(result or "")
        if not _rag_result_has_signal(result_text):
            continue
        sections.append(
            "\n".join(
                [
                    "[OBLIGATION_RAG]",
                    f"obligation={obligation}",
                    "[QUESTION]",
                    _REVIEW_RAG_OBLIGATIONS[obligation],
                    "[RAG_RESULT]",
                    _clip_review_rag_text(result_text, _REVIEW_RAG_RESULT_CHARS),
                ]
            )
        )

    if sections:
        new_state["obligation_context"] = _clip_review_rag_text(
            "\n\n".join(sections),
            _REVIEW_OBLIGATION_CONTEXT_CHARS,
        )
    return new_state


def review_node_collect_project_context(
    state: ReviewState,
    *,
    toolbox,
) -> ReviewState:
    return review_node_collect_obligation_context(state, toolbox=toolbox)


def review_node_llm(
    state: ReviewState,
    structured_node,
    fallback_node=None,
) -> ReviewState:
    payload = {
        "system_prompt": state.get("system_prompt") or "",
        "body_text": _build_body_text(state),
    }
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

        general_prompts = self.plugin_config.get("general_prompts", {})
        self.report_prompt = general_prompts.get("security_review_report", "")
        self.hardware_cwe_guidance = general_prompts.get("hardware_cwe_guidance", "")
        self.review_rag_evidence_guidance = general_prompts.get(
            "review_rag_evidence_guidance",
            DEFAULT_REVIEW_RAG_EVIDENCE_GUIDANCE,
        )
        self.review_rag_tool_prompt = general_prompts.get(
            "review_rag_tool_prompt",
            DEFAULT_REVIEW_RAG_TOOL_PROMPT,
        )

        self._review_chat_model = None
        self._structured_review_node = None
        self._fallback_review_node = None
        self._structured_review_node = self._create_structured_review_runnable()
        if self._structured_review_node is None and self._fallback_review_node is None:
            raise RuntimeError(
                "Unable to create review runnable; OpenAI-based provider required."
            )
        self._app_cache: dict[tuple[int, str], Any] = {}

    def _create_structured_review_runnable(self):
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
        graph.add_node("retrieve", review_node_retrieve)
        graph.add_node(
            "build_prompt",
            partial(
                review_node_build_prompt,
                language_prompts=language_prompts,
                default_prompt_key=default_prompt_key,
                report_prompt=self.report_prompt,
                custom_prompt_text=self.custom_prompt_text,
                custom_guidance_precedence=self.custom_guidance_precedence,
                schema_prompt_section=self._schema_prompt_section,
                hardware_cwe_guidance=self.hardware_cwe_guidance,
                tool_guidance=self.review_rag_evidence_guidance,
            ),
        )
        graph.add_node(
            "collect_tool_evidence",
            partial(
                review_node_collect_tool_evidence,
                chat_model=self._review_chat_model,
                toolbox=self.toolbox,
                tool_system_prompt=self.review_rag_tool_prompt,
            ),
        )
        graph.add_node(
            "collect_obligation_context",
            partial(
                review_node_collect_obligation_context,
                toolbox=self.toolbox,
            ),
        )
        graph.add_node(
            "review",
            partial(
                review_node_llm,
                structured_node=self._structured_review_node,
                fallback_node=self._fallback_review_node,
            ),
        )
        graph.add_node("parse", review_node_parse)

        graph.set_entry_point("retrieve")
        graph.add_edge("retrieve", "build_prompt")
        graph.add_edge("build_prompt", "collect_obligation_context")
        graph.add_edge("collect_obligation_context", "collect_tool_evidence")
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

        chunks = split_snippet(snippet, self.max_token_length)
        accumulated: list[dict] = []
        app = self._build_app(language_prompts, default_prompt_key)
        for chunk in chunks:
            out = app.invoke(
                {
                    "file_path": file_path,
                    "snippet": chunk,
                    "retriever_code": retriever_code,
                    "retriever_docs": retriever_docs,
                    "relative_file": relative_file,
                    "mode": mode,
                    "original_file": original_file,
                    "use_retrieval_context": use_retrieval_context,
                    "debug_callback": request.get("debug_callback"),
                }
            )
            chunk_reviews = out.get("parsed_reviews", []) or []
            if chunk_reviews:
                accumulated.extend(chunk_reviews)

        file_display = relative_file if relative_file else file_path
        if not accumulated:
            return {
                "file": file_display,
                "file_path": file_path,
                "reviews": [],
            }
        return {
            "file": file_display,
            "file_path": file_path,
            "reviews": accumulated,
        }
