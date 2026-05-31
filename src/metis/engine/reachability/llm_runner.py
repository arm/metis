# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0


from langchain_core.messages import SystemMessage
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate


def _chat_model_kwargs(usage_runtime, *, reasoning_effort=None):
    kwargs = usage_runtime.hooks.chat_model_kwargs()
    if (
        reasoning_effort
        and str(reasoning_effort).lower() not in "none off false default".split()
    ):
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
    response_model,
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
    structured_model = chat.with_structured_output(
        response_model, method="function_calling"
    )
    return (prompt | structured_model).invoke(variables)


def reachability_response_payload(raw):
    if hasattr(raw, "model_dump"):
        return raw.model_dump()
    if isinstance(raw, dict):
        return raw
    return {}


def invoke_json_prompt_with_retry(
    llm_provider,
    usage_runtime,
    *,
    model,
    max_tokens,
    temperature,
    system_prompt,
    user_prompt,
    variables,
    parse,
    logger,
    label,
    batch_size,
    invalid_message,
    final_keep_message,
    response_model=None,
    reasoning_effort=None,
):
    last_failure = "unknown failure"
    for attempt in range(2):
        try:
            chat = llm_provider.get_chat_model(
                model=model,
                max_tokens=max_tokens,
                temperature=temperature,
                **_chat_model_kwargs(usage_runtime, reasoning_effort=reasoning_effort),
            )
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
