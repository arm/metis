# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from typing import Any, Dict, Optional, TypedDict, Required, NotRequired


class ReviewRequest(TypedDict):
    # Required fields
    file_path: Required[str]
    snippet: Required[str]
    retriever_code: Required[Any]
    retriever_docs: Required[Any]
    context_prompt: Required[str]
    language_prompts: Required[Dict[str, str]]

    # Optional fields
    default_prompt_key: NotRequired[str]
    relative_file: NotRequired[Optional[str]]
    # Explicit mode: 'file' or 'patch'
    mode: NotRequired[str]
    # Optional original file contents for patch mode
    original_file: NotRequired[Optional[str]]


class AskRequest(TypedDict):
    # Required fields
    question: Required[str]
    retriever_code: Required[Any]
    retriever_docs: Required[Any]


class ReviewState(TypedDict, total=False):
    # Input
    file_path: str
    snippet: str
    retriever_code: Any
    retriever_docs: Any
    context_prompt: str
    relative_file: Optional[str]
    mode: str
    original_file: Optional[str]
    # Derived
    context: str
    system_prompt: str
    parsed_reviews: list[dict]


class AskState(TypedDict, total=False):
    # Input
    question: str
    retriever_code: Any
    retriever_docs: Any
    # Derived
    context: str
    code: str
    docs: str
    answer: str
