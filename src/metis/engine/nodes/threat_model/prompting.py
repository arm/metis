# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from pydantic import BaseModel

from metis.engine.llm_runner import rendered_prompt_token_count
from metis.engine.prompt_catalog import get_engine_prompts

from .parsing import parse_records

logger = logging.getLogger("metis")
_PROMPTS = get_engine_prompts(
    "threat_context",
    required=(
        "source_distillation_system",
        "source_distillation_user",
        "source_reduction_system",
        "source_reduction_user",
        "history_distillation_system",
        "history_distillation_user",
    ),
)


def prompt_fits(config, key: str, variables: dict[str, Any]) -> bool:
    llm_provider = config.llm_provider
    model = config.llama_query_model
    return (
        rendered_prompt_token_count(
            lambda value: llm_provider.count_tokens(value, model=model),
            system_prompt=_PROMPTS[f"{key}_system"],
            user_prompt=_PROMPTS[f"{key}_user"],
            variables=variables,
        )
        <= config.max_token_length
    )


def invoke_prompt(
    config,
    key: str,
    variables: dict[str, Any],
    response_model: type[BaseModel],
    *,
    label: str,
    batch_size: int,
    invalid_message: str,
    final_keep_message: str,
    invoke: Callable[..., Any],
):
    return invoke(
        config.llm_provider,
        config.usage_runtime,
        model=config.llama_query_model,
        system_prompt=_PROMPTS[f"{key}_system"],
        user_prompt=_PROMPTS[f"{key}_user"],
        variables=variables,
        parse=lambda raw: parse_records(raw, response_model=response_model),
        logger=logger,
        label=label,
        batch_size=batch_size,
        invalid_message=invalid_message,
        final_keep_message=final_keep_message,
        response_model=response_model,
        max_input_tokens=int(config.max_token_length),
        chat_model_kwargs=config.chat_model_kwargs,
    )
