# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import logging
import json
import jsonschema
from importlib.resources import files as _res_files, as_file as _as_file
from metis.engine.helpers import apply_custom_guidance
from pathlib import Path

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
):
    """Compose the system prompt for a review in a single place."""
    base = (
        f"{language_prompts[default_prompt_key]} \n "
        f"{language_prompts['security_review_checks']} \n {report_prompt}"
    )
    return apply_custom_guidance(
        base, custom_prompt_text, custom_guidance_precedence or ""
    )


def _load_json_resource(filename, anchor, override_path=None):
    """
    Load a JSON file, preferring:
    1) explicit override_path if provided
    2) current working directory (filename)
    3) packaged resource under the given anchor module
    """
    if override_path:
        p = Path(override_path)
        if not p.is_file():
            raise FileNotFoundError(f"JSON not found: {p}")
        with p.open("r", encoding="utf-8") as f:
            return json.load(f)

    cwd_p = Path.cwd() / filename
    if cwd_p.is_file():
        with cwd_p.open("r", encoding="utf-8") as f:
            return json.load(f)

    resource = _res_files(anchor) / filename
    if not resource.is_file():
        raise FileNotFoundError(f"No {filename} found in CWD or package resources")
    with _as_file(resource) as real_path:
        with open(real_path, "r", encoding="utf-8") as f:
            return json.load(f)


def get_review_schema(override_path=None):
    return _load_json_resource("review.schema.json", "metis.schemas", override_path)


def validate_json_schema(obj, schema) -> bool:
    try:
        jsonschema.validate(instance=obj, schema=schema)
        return True
    except Exception:
        return False
