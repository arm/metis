# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from langchain_core.messages import SystemMessage
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate


def _chat_model_kwargs(
    usage_runtime=None, *, reasoning_effort=None, chat_model_kwargs=None
):
    kwargs = {}
    if usage_runtime is not None:
        kwargs.update(usage_runtime.hooks.chat_model_kwargs())
    if chat_model_kwargs:
        kwargs.update(chat_model_kwargs)
    if (
        reasoning_effort
        and str(reasoning_effort).lower() not in "none off false default".split()
    ):
        kwargs["reasoning_effort"] = reasoning_effort
    return kwargs


def invoke_langchain_json_prompt_with_retry(
    llm_provider,
    usage_runtime=None,
    *,
    model,
    system_prompt,
    user_prompt,
    variables,
    parse,
    logger,
    label,
    batch_size,
    invalid_message,
    final_keep_message,
    max_tokens=None,
    temperature=None,
    response_model=None,
    reasoning_effort=None,
    chat_model_kwargs=None,
):
    last_failure = "unknown failure"
    for attempt in range(2):
        try:
            params = {"model": model}
            if max_tokens is not None:
                params["max_tokens"] = max_tokens
            if temperature is not None:
                params["temperature"] = temperature
            params.update(
                _chat_model_kwargs(
                    usage_runtime,
                    reasoning_effort=reasoning_effort,
                    chat_model_kwargs=chat_model_kwargs,
                )
            )
            chat = llm_provider.get_chat_model(**params)
            prompt = ChatPromptTemplate.from_messages(
                [SystemMessage(content=system_prompt), ("user", user_prompt)]
            )
            parsed = None
            structured_output = getattr(chat, "with_structured_output", None)
            if response_model is not None and callable(structured_output):
                try:
                    parsed = parse(
                        (
                            prompt
                            | structured_output(
                                response_model, method="function_calling"
                            )
                        ).invoke(variables)
                    )
                except Exception as exc:
                    last_failure = f"structured validation failed: {exc}"
            if parsed is None:
                parsed = parse((prompt | chat | StrOutputParser()).invoke(variables))
            if parsed is not None:
                return parsed
            last_failure = invalid_message
        except Exception as exc:
            last_failure = str(exc)
        if attempt == 0:
            logger.warning(
                "%s failed for %d candidates; retrying once: %s",
                label,
                batch_size,
                last_failure,
            )
    logger.warning(
        "%s failed for %d candidates; %s: %s",
        label,
        batch_size,
        final_keep_message,
        last_failure,
    )
    return None
