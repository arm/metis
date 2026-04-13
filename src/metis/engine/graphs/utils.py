# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import logging
import re
from typing import Annotated, Literal, get_args, get_origin

from metis.engine.helpers import apply_custom_guidance
from .schemas import ReviewIssueModel

logger = logging.getLogger("metis")

_RELEVANT_CONTEXT_PLACEHOLDER_VALUES = {
    "[[RELEVANT_CONTEXT_INPUT_CHANGES]]": (
        "2. RELEVANT_CONTEXT - information about what these changes do."
    ),
    "[[RELEVANT_CONTEXT_INPUT_RTL]]": (
        "2. RELEVANT_CONTEXT - information about what these changes do "
        "(e.g., interface intent, security assumptions)."
    ),
    "[[RELEVANT_CONTEXT_INPUT_MODULE_PACKAGE]]": (
        "2. RELEVANT_CONTEXT - information about what this "
        "module/package/interface does and how it is used"
    ),
    "[[RELEVANT_CONTEXT_INPUT_MODULE]]": (
        "2. RELEVANT_CONTEXT - information about what this module does "
        "and how it is used"
    ),
    "[[RELEVANT_CONTEXT_INPUT_TD]]": (
        "2) RELEVANT_CONTEXT — notes about target, subtarget features, "
        "expected semantics, and patches."
    ),
    "[[RELEVANT_CONTEXT_INPUT_TERRAFORM]]": (
        "2) RELEVANT_CONTEXT – Short notes explaining intent, environment "
        "(e.g., prod/stage),\n"
        "           cloud(s) targeted, and any linked modules or policies "
        "that inform how changes behave."
    ),
    "[[RELEVANT_CONTEXT_ADDITIONAL_DETAILS]]": (
        "RELEVANT_CONTEXT: Additional details or commentary on the snippet."
    ),
    "[[RELEVANT_CONTEXT]]": "- If it is empty, ignore it.",
    "[[RELEVANT_CONTEXT_UNINDENTED]]": "If it is empty, ignore it.",
    "[[RELEVANT_CONTEXT_TWO_SPACE]]": "- If it is empty, ignore it.",
    "[[RELEVANT_CONTEXT_NAMED]]": ("- If RELEVANT_CONTEXT is empty, ignore it."),
    "[[RELEVANT_CONTEXT_ASSERTION_GUIDANCE]]": (
        '- Assertions: ensure security properties are not "simulation-only" '
        "crutches when RELEVANT_CONTEXT expects enforcement in RTL."
    ),
    "[[RELEVANT_CONTEXT_FILE_EVIDENCE_SUFFIX]]": " and RELEVANT_CONTEXT",
    "[[RELEVANT_CONTEXT_PATCH_EVIDENCE_SUFFIX]]": ", RELEVANT_CONTEXT",
    "[[RELEVANT_CONTEXT_CHANGES_PROVIDED_SUFFIX]]": " or context",
    "[[RELEVANT_CONTEXT_CODE_PROVIDED_SUFFIX]]": " and context",
    "[[RELEVANT_CONTEXT_TD_PROVIDED_SUFFIX]]": " or provided context",
    "[[RELEVANT_CONTEXT_PATCH_JUSTIFICATION_SUFFIX]]": ", and RELEVANT_CONTEXT",
    "[[RELEVANT_CONTEXT_SNIPPET_VALIDATION_SUFFIX]]": " and RELEVANT_CONTEXT",
    "[[RELEVANT_CONTEXT_INTERNAL_ONLY_SUFFIX]]": " in RELEVANT_CONTEXT",
    "[[RELEVANT_CONTEXT_TERRAFORM_ORIGINAL_PREFIX]]": "RELEVANT_CONTEXT/",
    "[[ORIGINAL_FILE_INDEX_DOT]]": "3.",
    "[[ORIGINAL_FILE_INDEX_PAREN]]": "3)",
}


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


def _build_review_prompt_without_context(text: str) -> str:
    cleaned = (text or "").replace("[[ORIGINAL_FILE_INDEX_DOT]]", "2.")
    cleaned = cleaned.replace("[[ORIGINAL_FILE_INDEX_PAREN]]", "2)")
    if "RELEVANT_CONTEXT" in cleaned:
        cleaned = re.sub(
            r",\s*RELEVANT_CONTEXT,\s*\n\s*and ORIGINAL_FILE",
            " and ORIGINAL_FILE",
            cleaned,
        )
        cleaned = cleaned.replace(
            ", ORIGINAL_FILE, and RELEVANT_CONTEXT",
            " and ORIGINAL_FILE",
        )
        cleaned = cleaned.replace(
            ", RELEVANT_CONTEXT, and ORIGINAL_FILE",
            " and ORIGINAL_FILE",
        )
        cleaned = cleaned.replace(" and RELEVANT_CONTEXT", "")
        cleaned = cleaned.replace(" or context provided", " provided")
        cleaned = cleaned.replace(" and context provided", " provided")
        cleaned = cleaned.replace(" or provided context", "")
        cleaned = cleaned.replace(" in RELEVANT_CONTEXT", "")
        cleaned = cleaned.replace("RELEVANT_CONTEXT/", "")
        cleaned = re.sub(
            r"^\s*2[\.\)]\s+RELEVANT_CONTEXT\s+[-–—].*\n?",
            "",
            cleaned,
            flags=re.MULTILINE,
        )
        cleaned = re.sub(
            r"^(\s*)3([\.\)])\s+ORIGINAL_FILE",
            r"\g<1>2\2 ORIGINAL_FILE",
            cleaned,
            flags=re.MULTILINE,
        )
        cleaned = re.sub(
            r"^\s*- If RELEVANT_CONTEXT is empty, ignore it\.\n?",
            "",
            cleaned,
            flags=re.MULTILINE,
        )
        cleaned = re.sub(
            r"^\s*- If it is empty, ignore it\.\n?",
            "",
            cleaned,
            flags=re.MULTILINE,
        )
        cleaned = re.sub(
            r"^\s*If it is empty, ignore it\.\n?",
            "",
            cleaned,
            flags=re.MULTILINE,
        )
        cleaned = re.sub(
            r"^\s*RELEVANT_CONTEXT: Additional details or commentary on the snippet\.\n?",
            "",
            cleaned,
            flags=re.MULTILINE,
        )
        cleaned = re.sub(
            r'^\s*- Assertions: ensure security properties are not "simulation-only" crutches when RELEVANT_CONTEXT expects enforcement in RTL\.\n?',
            "",
            cleaned,
            flags=re.MULTILINE,
        )
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    return cleaned.strip()


def _replace_relevant_context_placeholders(
    text: str,
    *,
    include_relevant_context: bool,
) -> str:
    updated = text
    for placeholder, value in _RELEVANT_CONTEXT_PLACEHOLDER_VALUES.items():
        replacement = value if include_relevant_context else ""
        if placeholder == "[[ORIGINAL_FILE_INDEX_DOT]]":
            replacement = "3." if include_relevant_context else "2."
        elif placeholder == "[[ORIGINAL_FILE_INDEX_PAREN]]":
            replacement = "3)" if include_relevant_context else "2)"
        updated = updated.replace(
            placeholder,
            replacement,
        )
    return updated


def _is_string_field(annotation):
    if annotation is str:
        return True
    if isinstance(annotation, type) and issubclass(annotation, str):
        return True
    origin = get_origin(annotation)
    if origin is None:
        return False
    if origin is str:
        return True
    if origin is Literal:
        return all(isinstance(arg, str) for arg in get_args(annotation))
    if origin is Annotated:
        base, *_ = get_args(annotation)
        return _is_string_field(base)
    return False


_REQUIRED_REVIEW_STR_FIELDS = tuple(
    name
    for name, field in ReviewIssueModel.model_fields.items()
    if _is_string_field(field.annotation)
)


def sanitize_review_payload(payload):
    """
    Normalize review entries so that required keys always exist.
    Missing string fields become empty strings and confidence defaults to 0.0.
    """
    reviews = payload.get("reviews")
    if not isinstance(reviews, list):
        return []

    sanitized: list[dict] = []
    for idx, review in enumerate(reviews):
        if not isinstance(review, dict):
            logger.debug(
                "Structured review entry %s is not a dict; normalizing to empty fields",
                idx,
            )
            empty_entry = {field: "" for field in _REQUIRED_REVIEW_STR_FIELDS}
            empty_entry["confidence"] = 0.0
            empty_entry["issue"] = str(review)
            sanitized.append(empty_entry)
            continue

        normalized = dict(review)
        for field in _REQUIRED_REVIEW_STR_FIELDS:
            value = normalized.get(field)
            if isinstance(value, str):
                normalized[field] = value.strip()
            elif value is None:
                normalized[field] = ""
            else:
                normalized[field] = str(value).strip()

        confidence_raw = normalized.get("confidence")
        confidence_value = None
        if isinstance(confidence_raw, (int, float)):
            confidence_value = float(confidence_raw)
        elif isinstance(confidence_raw, str):
            try:
                confidence_value = float(confidence_raw.strip())
            except ValueError:
                confidence_value = None
        normalized["confidence"] = (
            confidence_value if confidence_value is not None else 0.0
        )

        # Ensure required keys exist even if review provided none of them
        for field in _REQUIRED_REVIEW_STR_FIELDS:
            if field not in normalized or normalized[field] is None:
                normalized[field] = ""

        sanitized.append(normalized)

    return sanitized


def build_review_system_prompt(
    language_prompts,
    default_prompt_key,
    report_prompt,
    custom_prompt_text,
    custom_guidance_precedence,
    schema_prompt_section,
    hardware_cwe_guidance="",
    include_relevant_context=True,
):
    """Compose the system prompt for a review in a single place."""
    base = (
        f"{language_prompts[default_prompt_key]} \n "
        f"{language_prompts['security_review_checks']} \n {report_prompt}"
    )
    schema_placeholder = "[[REVIEW_SCHEMA_FIELDS]]"
    hardware_placeholder = "[[HARDWARE_CWE_GUIDANCE]]"

    # Fail early here since REVIEW_SCHEMA_FIELDS are required for having a structured output
    if schema_placeholder not in base:
        raise ValueError(
            "Schema prompt placeholder missing from review prompt template"
        )

    base = base.replace(schema_placeholder, schema_prompt_section)

    if hardware_placeholder in base:
        if not hardware_cwe_guidance:
            raise ValueError(
                "Hardware CWE guidance placeholder found but guidance text is empty"
            )
        base = base.replace(hardware_placeholder, hardware_cwe_guidance)
    base = _replace_relevant_context_placeholders(
        base,
        include_relevant_context=include_relevant_context,
    )
    base = apply_custom_guidance(
        base, custom_prompt_text, custom_guidance_precedence or ""
    )
    if not include_relevant_context:
        return _build_review_prompt_without_context(base)
    return base
