# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class JsonPromptRequest:
    model: str
    system_prompt: str
    user_prompt: str
    variables: dict[str, Any]
    parse: Callable[[Any], Any]
    logger: Any
    label: str
    batch_size: int
    invalid_message: str
    final_keep_message: str
    max_tokens: int | None = None
    temperature: float | None = None
    response_model: type | None = None
    reasoning_effort: str | None = None
    chat_model_kwargs: dict[str, Any] | None = None
    model_tools: tuple[Any, ...] = ()
    max_tool_rounds: int | None = None
    on_output_limit: Callable[[], None] | None = None
    max_input_tokens: int | None = None
    on_tool_result: Callable[[str, dict[str, Any], str], None] | None = None
    on_tool_error: Callable[[], None] | None = None
