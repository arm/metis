# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from unittest.mock import Mock
from unittest.mock import patch

import pytest
import yaml

pytest.importorskip("langchain_aws")

from botocore.stub import Stubber

from langchain_core.callbacks.base import BaseCallbackHandler
from llama_index.core.callbacks import CallbackManager

from metis.configuration import load_runtime_config

from metis.providers.bedrock import BedrockEmbeddingProvider
from metis.providers.bedrock import BedrockProvider
from metis.providers.bedrock import _credential_kwargs
from metis.providers.embedding_adapter import LangChainEmbeddingAdapter


def _chat_config(**overrides):
    config = {
        "region": "us-east-1",
        "model": "us.anthropic.claude-opus-4-8",
    }
    config.update(overrides)
    return config


def _embedding_config(**overrides):
    config = {
        "region": "us-east-1",
        "code_embedding_model": "amazon.titan-embed-text-v2:0",
        "docs_embedding_model": "amazon.titan-embed-text-v2:0",
    }
    config.update(overrides)
    return config


@patch("metis.providers.bedrock.ChatBedrockConverse")
def test_chat_model_uses_configured_model_and_region(mock_chat):
    provider = BedrockProvider(_chat_config())

    provider.get_chat_model(max_tokens=256)

    kwargs = mock_chat.call_args.kwargs
    assert kwargs["model"] == "us.anthropic.claude-opus-4-8"
    assert kwargs["region_name"] == "us-east-1"
    assert kwargs["max_tokens"] == 256
    assert "credentials_profile_name" not in kwargs
    assert "aws_access_key_id" not in kwargs


@patch("metis.providers.bedrock.ChatBedrockConverse")
def test_chat_model_passes_explicit_aws_credentials(mock_chat):
    provider = BedrockProvider(
        _chat_config(
            aws_access_key_id="AKIA",
            aws_secret_access_key="secret",
            aws_session_token="token",
        )
    )

    provider.get_chat_model()

    kwargs = mock_chat.call_args.kwargs
    assert kwargs["aws_access_key_id"] == "AKIA"
    assert kwargs["aws_secret_access_key"] == "secret"
    assert kwargs["aws_session_token"] == "token"


@patch("metis.providers.bedrock.ChatBedrockConverse")
def test_chat_model_uses_profile_when_no_explicit_keys(mock_chat):
    provider = BedrockProvider(_chat_config(aws_profile="myprofile"))

    provider.get_chat_model()

    kwargs = mock_chat.call_args.kwargs
    assert kwargs["credentials_profile_name"] == "myprofile"
    assert "aws_access_key_id" not in kwargs


@patch("metis.providers.bedrock.ChatBedrockConverse")
def test_chat_model_allows_runtime_overrides_and_callbacks(mock_chat):
    provider = BedrockProvider(_chat_config())
    callback = Mock(spec=BaseCallbackHandler)

    provider.get_chat_model(
        model="anthropic.claude-haiku-4-5-v1:0",
        callbacks=[callback],
        max_tokens=128,
    )

    kwargs = mock_chat.call_args.kwargs
    assert kwargs["model"] == "anthropic.claude-haiku-4-5-v1:0"
    assert kwargs["callbacks"] == [callback]
    assert kwargs["max_tokens"] == 128


@patch("metis.providers.bedrock.BedrockEmbeddings")
def test_embedding_adapter_wraps_bedrock_embeddings(mock_embed):
    provider = BedrockEmbeddingProvider(_embedding_config())
    callback_manager = CallbackManager([])

    code = provider.get_embed_model_code(callback_manager=callback_manager)
    docs = provider.get_embed_model_docs()

    assert isinstance(code, LangChainEmbeddingAdapter)
    assert code.model_name == "amazon.titan-embed-text-v2:0"
    assert code.callback_manager is callback_manager
    assert isinstance(docs, LangChainEmbeddingAdapter)
    embed_kwargs = mock_embed.call_args_list[0].kwargs
    assert embed_kwargs["model_id"] == "amazon.titan-embed-text-v2:0"
    assert embed_kwargs["region_name"] == "us-east-1"


def test_credential_kwargs_omit_explicit_keys_when_unset():
    kwargs = _credential_kwargs(
        {
            "region": "us-east-1",
            "aws_access_key_id": "",
            "aws_secret_access_key": "",
            "aws_session_token": "",
        }
    )

    assert kwargs == {"region_name": "us-east-1"}


def test_provider_raises_on_missing_region():
    with pytest.raises(ValueError, match="region"):
        BedrockProvider(_chat_config(region=""))


@pytest.mark.parametrize(
    ("provider_effort", "query_effort"),
    [(None, None), ("high", None), ("high", "low")],
)
def test_reasoning_configuration_reaches_converse(
    tmp_path, provider_effort, query_effort
):
    config_path = tmp_path / "metis.yaml"
    config_path.write_text(
        yaml.safe_dump(
            {
                "llm_provider": _chat_config(
                    name="bedrock",
                    reasoning_effort=provider_effort,
                    aws_access_key_id="test-key",
                    aws_secret_access_key="test-secret",
                ),
                "query": {"max_tokens": 128, "reasoning_effort": query_effort},
            }
        ),
        encoding="utf-8",
    )
    runtime = load_runtime_config(config_path)
    model = BedrockProvider(runtime["llm_provider"]).get_chat_model(
        **runtime["chat_model_kwargs"]
    )
    expected_params = {
        "modelId": "us.anthropic.claude-opus-4-8",
        "messages": [{"role": "user", "content": [{"text": "Reply with ok."}]}],
        "system": [],
        "inferenceConfig": {"maxTokens": 128},
    }
    effort = query_effort or provider_effort
    if effort is not None:
        expected_params["additionalModelRequestFields"] = {
            "thinking": {"type": "adaptive"},
            "output_config": {"effort": effort},
        }
    try:
        with Stubber(model.client) as stubber:
            stubber.add_response(
                "converse",
                {
                    "output": {
                        "message": {"role": "assistant", "content": [{"text": "ok"}]}
                    },
                    "stopReason": "end_turn",
                    "usage": {"inputTokens": 1, "outputTokens": 1, "totalTokens": 2},
                    "metrics": {"latencyMs": 1},
                },
                expected_params,
            )
            response = model.invoke("Reply with ok.")
            assert response.content == "ok"
            stubber.assert_no_pending_responses()
    finally:
        model.client.close()
        model.bedrock_client.close()


def test_chat_model_rejects_invalid_reasoning_effort():
    provider = BedrockProvider(
        _chat_config(
            aws_access_key_id="test-key",
            aws_secret_access_key="test-secret",
        )
    )
    with pytest.raises(ValueError, match="reasoning_effort"):
        provider.get_chat_model(reasoning_effort="invalid")


def test_chat_model_warns_when_model_does_not_support_reasoning_effort():
    provider = BedrockProvider(
        _chat_config(
            model="us.anthropic.claude-3-5-sonnet-20241022-v2:0",
            aws_access_key_id="test-key",
            aws_secret_access_key="test-secret",
        )
    )
    with pytest.warns(UserWarning, match="reasoning_effort is not supported"):
        model = provider.get_chat_model(reasoning_effort="high")
    model.client.close()
    model.bedrock_client.close()
