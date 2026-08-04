# SPDX-FileCopyrightText: Copyright 2025-2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from typing import Any
from typing_extensions import Required
from typing_extensions import TypedDict


class AskRequest(TypedDict):
    question: Required[str]
    retriever_code: Required[Any]
    retriever_docs: Required[Any]


class AskState(TypedDict, total=False):
    question: str
    retriever_code: Any
    retriever_docs: Any
    context: str
    code: str
    docs: str
    answer: str
