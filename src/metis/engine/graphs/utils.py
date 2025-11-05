# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import logging
from metis.engine.helpers import apply_custom_guidance

logger = logging.getLogger("metis")


def retrieve_text(retriever, query):
    """Retrieve context using a retriever with get_relevant_documents."""
    try:
        docs = retriever.get_relevant_documents(query)
        return "\n\n".join(getattr(d, "page_content", str(d)) for d in (docs or []))
    except Exception as e:
        logger.warning(f"Error retrieving context: {e}")
        return ""


def synthesize_context(code_text, doc_text):
    """
    Compose the retrieval context used in prompts.
    Only includes retrieved code/docs text, not the retrieval question itself.
    """
    parts = []
    if code_text:
        parts.append(code_text)
    if doc_text:
        parts.append(doc_text)
    return "\n\n".join(p for p in parts if p)


def build_review_system_prompt(
    language_prompts,
    default_prompt_key,
    report_prompt,
    custom_prompt_text,
    custom_guidance_precedence,
    schema_prompt_section,
):
    """Compose the system prompt for a review in a single place."""
    base = (
        f"{language_prompts[default_prompt_key]} \n "
        f"{language_prompts['security_review_checks']} \n {report_prompt}"
    )
    placeholder = "[[REVIEW_SCHEMA_FIELDS]]"

    # Fail early here since REVIEW_SCHEMA_FIELDS are required for having a structured output
    if placeholder not in base:
        raise ValueError(
            "Schema prompt placeholder missing from review prompt template"
        )

    base = base.replace(placeholder, schema_prompt_section)
    return apply_custom_guidance(
        base, custom_prompt_text, custom_guidance_precedence or ""
    )
