# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.providers.bedrock_mantle import BedrockMantleProvider
from metis.providers.bedrock_mantle import ChatBedrockMantle


def _config(**overrides):
    config = {
        "embedding_api_key": "embedding-key",
        "model": "anthropic.claude-example",
        "llama_query_model": "anthropic.claude-example",
        "llama_query_temperature": 0.2,
        "llama_query_max_tokens": 256,
        "aws_profile": "example-profile",
        "aws_region": "example-region",
        "code_embedding_model": "text-embedding-3-large",
        "docs_embedding_model": "text-embedding-3-small",
    }
    config.update(overrides)
    return config


def test_chat_model_uses_generic_bedrock_mantle_configuration():
    provider = BedrockMantleProvider(_config())

    llm = provider.get_chat_model()

    assert isinstance(llm, ChatBedrockMantle)
    assert llm.model == "anthropic.claude-example"
    assert llm.max_tokens == 256
    assert llm.temperature is None
    assert llm.aws_profile == "example-profile"
    assert llm.aws_region == "example-region"


def test_chat_model_can_opt_in_to_temperature():
    provider = BedrockMantleProvider(_config(supports_temperature=True))

    llm = provider.get_chat_model()

    assert llm.temperature == 0.2


def test_chat_model_drops_explicit_temperature_when_not_supported():
    provider = BedrockMantleProvider(_config())

    llm = provider.get_chat_model(temperature=0.1)

    assert llm.temperature is None


def test_chat_model_does_not_default_to_a_specific_region():
    provider = BedrockMantleProvider(_config(aws_region=None))

    llm = provider.get_chat_model()

    assert llm.aws_region is None


def test_chat_model_passes_explicit_aws_credentials():
    provider = BedrockMantleProvider(
        _config(
            aws_access_key_id="AKIA",
            aws_secret_access_key="secret",
            aws_session_token="token",
        )
    )

    llm = provider.get_chat_model()

    assert llm.aws_access_key == "AKIA"
    assert llm.aws_secret_key == "secret"
    assert llm.aws_session_token == "token"
    params = llm._bedrock_client_params()
    assert params["aws_access_key"] == "AKIA"
    assert params["aws_secret_key"] == "secret"
    assert params["aws_session_token"] == "token"


def test_chat_model_omits_explicit_credentials_when_unset():
    provider = BedrockMantleProvider(
        _config(aws_access_key_id="", aws_secret_access_key="")
    )

    llm = provider.get_chat_model()

    assert llm.aws_access_key is None
    params = llm._bedrock_client_params()
    assert "aws_access_key" not in params
    assert "aws_secret_key" not in params
