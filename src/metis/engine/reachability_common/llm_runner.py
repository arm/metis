# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Shared LLM invocation helper for reachability analysis passes."""

from __future__ import annotations

from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate


def _chat_model_kwargs(usage_runtime, *, reasoning_effort=None):
    kwargs = usage_runtime.hooks.chat_model_kwargs()
    if reasoning_effort and str(reasoning_effort).lower() not in {
        "none",
        "off",
        "false",
        "default",
    }:
        kwargs["reasoning_effort"] = reasoning_effort
    return kwargs


def invoke_reachability_prompt(
    llm_provider,
    usage_runtime,
    *,
    model,
    max_tokens,
    system_prompt,
    user_prompt,
    variables,
    reasoning_effort=None,
    temperature=0.1,
):
    kwargs = _chat_model_kwargs(usage_runtime, reasoning_effort=reasoning_effort)
    chat = llm_provider.get_chat_model(
        model=model,
        max_tokens=max_tokens,
        temperature=temperature,
        **kwargs,
    )
    prompt = ChatPromptTemplate.from_messages(
        [("system", system_prompt), ("user", user_prompt)]
    )
    return (prompt | chat | StrOutputParser()).invoke(variables).strip()
