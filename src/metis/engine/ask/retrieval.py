# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import logging
from typing import Any

from metis.vector_store.retrievers import document_text

logger = logging.getLogger("metis")


def retrieve_text(retriever: Any, query: str) -> str:
    """Retrieve context using a retriever with get_relevant_documents."""
    try:
        docs = retriever.get_relevant_documents(query)
        return "\n\n".join(
            text for document in (docs or ()) if (text := document_text(document))
        )
    except Exception as exc:
        logger.warning("Error retrieving context: %s", exc)
        return ""


def synthesize_context(code_text: str, doc_text: str) -> str:
    """Compose retrieved code and document text for an Ask request."""
    return "\n\n".join(part for part in (code_text, doc_text) if part)
