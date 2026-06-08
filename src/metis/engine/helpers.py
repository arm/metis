# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import logging
import os

from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate

from metis.engine.source import SourceMap
from metis.engine.source.anchor import KIND_CHUNK

logger = logging.getLogger("metis")


def annotate_chunk_anchors(doc, chunks):
    """Attach a CodeAnchor-derived metadata block to each chunk of ``doc``."""
    doc_text = getattr(doc, "text", None)
    if doc_text is None and hasattr(doc, "get_content"):
        doc_text = doc.get_content()
    if not doc_text:
        return chunks
    smap = SourceMap.for_text(getattr(doc, "id_", "") or "", doc_text)
    for node in chunks:
        chunk_text = getattr(node, "text", None)
        if chunk_text is None and hasattr(node, "get_content"):
            chunk_text = node.get_content()
        if not chunk_text:
            continue
        anchor = smap.resolve_snippet(chunk_text)
        if anchor is None:
            continue
        meta = getattr(node, "metadata", None)
        if meta is None:
            meta = {}
            try:
                node.metadata = meta
            except Exception:
                continue
        meta["start_line"] = anchor.start_line
        meta["end_line"] = anchor.end_line
        if anchor.symbol:
            meta["symbol"] = anchor.symbol
        meta["anchor_id"] = anchor.stable_id()
        meta["anchor_kind"] = KIND_CHUNK
    return chunks


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
                annotate_chunk_anchors(d, parsed_nodes)
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
