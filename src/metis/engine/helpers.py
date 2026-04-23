# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import logging
import os
import re

from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate

logger = logging.getLogger("metis")

_SYMBOL_RE = re.compile(
    r"\b(?!(?:if|for|while|switch|catch|return|sizeof)\b)([A-Za-z_][A-Za-z0-9_:~]*)\s*\([^;{}]*\)\s*(?:const\s*)?(?:noexcept\s*)?(?:->\s*[^{]+)?\{"
)
_TYPE_RE = re.compile(r"\b(?:class|struct|enum)\s+([A-Za-z_][A-Za-z0-9_:]*)")


def summarize_changes(llm_provider, file_path, issues, summary_prompt, callbacks=None):
    try:
        kwargs = {}
        if callbacks is not None:
            kwargs["callbacks"] = callbacks
        chat = llm_provider.get_chat_model(**kwargs)
        prompt_tmpl = ChatPromptTemplate.from_messages(
            [("system", "{system}"), ("user", "{input}")]
        )
        chain = prompt_tmpl | chat | StrOutputParser()
        return chain.invoke(
            {"system": summary_prompt or "", "input": issues or ""}
        ).strip()
    except Exception as e:
        logger.error(f"Error summarizing changes for {file_path}: {e}")
        return ""


def prepare_nodes_iter(
    code_docs,
    doc_docs,
    get_plugin_for_extension,
    get_splitter_cached,
    doc_splitter,
):
    """
    Generator that prepares nodes for code and docs
    """
    nodes_code = []
    nodes_docs = []

    for d in code_docs:
        ext = os.path.splitext(d.id_)[1].lower()
        plugin = get_plugin_for_extension(ext)
        if plugin:
            try:
                splitter = get_splitter_cached(plugin)
                parsed_nodes = splitter.get_nodes_from_documents([d])
                annotate_code_nodes(parsed_nodes, d)
                nodes_code.extend(parsed_nodes)
            except Exception as e:
                name = plugin.get_name() if hasattr(plugin, "get_name") else "unknown"
                logger.warning(
                    f"Could not parse code with language {name} for file {d.id_} (ext {ext}): {e}"
                )
        # yield regardless of success
        yield None

    for d in doc_docs:
        try:
            nodes_docs.extend(doc_splitter.get_nodes_from_documents([d]))
        except Exception as e:
            logger.warning(f"Could not parse docs for file {d.id_}: {e}")
        finally:
            yield None

    return nodes_code, nodes_docs


def _content_from(obj):
    get_content = getattr(obj, "get_content", None)
    if callable(get_content):
        try:
            return str(get_content())
        except TypeError:
            pass
    return str(getattr(obj, "text", "") or getattr(obj, "page_content", "") or "")


def _find_chunk_span(
    source_text: str, chunk_text: str, start_at: int
) -> tuple[int, int]:
    normalized_chunk = str(chunk_text or "").strip()
    if not normalized_chunk:
        return -1, -1

    start = source_text.find(normalized_chunk, start_at)
    if start < 0:
        start = source_text.find(normalized_chunk)
    if start < 0:
        return -1, -1
    return start, start + len(normalized_chunk)


def _line_number_at(text: str, offset: int) -> int:
    if offset < 0:
        return 0
    return text.count("\n", 0, offset) + 1


def _extract_enclosing_symbol(chunk_text: str) -> str:
    match = _SYMBOL_RE.search(chunk_text)
    if match:
        return match.group(1)
    match = _TYPE_RE.search(chunk_text)
    if match:
        return match.group(1)
    return ""


def annotate_code_nodes(nodes, document):
    """Attach file/line/symbol metadata to code chunks before indexing."""
    source_text = _content_from(document)
    source = str(getattr(document, "id_", "") or getattr(document, "doc_id", "") or "")
    cursor = 0

    for node in nodes:
        chunk_text = _content_from(node)
        start, end = _find_chunk_span(source_text, chunk_text, cursor)
        if end >= 0:
            cursor = end

        metadata = dict(getattr(node, "metadata", {}) or {})
        if source:
            metadata.setdefault("file_path", source)
            metadata.setdefault("source", source)
            metadata.setdefault("doc_id", source)
        if start >= 0:
            metadata.setdefault("start_line", _line_number_at(source_text, start))
            metadata.setdefault("line", metadata["start_line"])
            metadata.setdefault(
                "end_line", _line_number_at(source_text, max(start, end - 1))
            )
        symbol = _extract_enclosing_symbol(chunk_text)
        if symbol:
            metadata.setdefault("enclosing_symbol", symbol)
        node.metadata = metadata

    return nodes


def apply_custom_guidance(base_prompt, custom_guidance, precedence_note):
    """Prepend precedence note and custom guidance to a base prompt.

    If custom_guidance is not set, returns base_prompt unchanged. The format is:
    [precedence_note]\n\nCustom Guidance:\n{custom_guidance}\n\n{base_prompt}
    """
    if not custom_guidance:
        return base_prompt
    guidance_block = f"Custom Guidance:\n{custom_guidance.strip()}"
    if precedence_note:
        return f"{precedence_note.strip()}\n\n{guidance_block}\n\n{base_prompt}"
    return f"{guidance_block}\n\n{base_prompt}"
