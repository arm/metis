# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import asyncio
import json

import pytest

pytest.importorskip("langchain_anthropic")
pytest.importorskip("anthropic")
pytest.importorskip("langchain_aws")

import httpx2 as httpx
from langchain_aws import ChatAnthropicMantle
from langchain_core.messages import HumanMessage

from metis.providers.bedrock_mantle import BedrockMantleProvider
from metis.providers.bedrock_mantle import ChatBedrockMantle


def _config(**overrides):
    config = {
        "model": "anthropic.claude-example",
        "aws_profile": "example-profile",
        "aws_region": "example-region",
    }
    config.update(overrides)
    return config


def test_chat_model_uses_generic_bedrock_mantle_configuration():
    provider = BedrockMantleProvider(_config())

    llm = provider.get_chat_model()

    assert isinstance(llm, ChatBedrockMantle)
    assert isinstance(llm, ChatAnthropicMantle)
    assert llm.model == "anthropic.claude-example"
    assert llm.aws_profile == "example-profile"
    assert llm.aws_region == "example-region"


def test_chat_model_does_not_default_to_a_specific_region():
    provider = BedrockMantleProvider(_config(aws_region=None))

    llm = provider.get_chat_model()

    assert llm.aws_region is None


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("profile", [None, "example-profile"])
def test_native_transport_preserves_connection_and_authentication(
    tmp_path, monkeypatch, asynchronous, profile
):
    credentials = tmp_path / "credentials"
    credentials.write_text(
        "[example-profile]\naws_access_key_id = profile-key\n"
        "aws_secret_access_key = profile-secret\n"
    )
    aws_config = tmp_path / "config"
    aws_config.write_text("")
    environment = {
        "AWS_SHARED_CREDENTIALS_FILE": str(credentials),
        "AWS_CONFIG_FILE": str(aws_config),
        "AWS_EC2_METADATA_DISABLED": "true",
        "AWS_ACCESS_KEY_ID": "environment-key",
        "AWS_SECRET_ACCESS_KEY": "environment-secret",
        "AWS_SESSION_TOKEN": "environment-session",
        "AWS_BEARER_TOKEN_BEDROCK": "environment-bearer",
        "ANTHROPIC_API_KEY": "unrelated-api-key",
        "ANTHROPIC_API_URL": "https://unrelated.invalid",
        "ANTHROPIC_BASE_URL": "https://unrelated.invalid",
        "ANTHROPIC_BEDROCK_MANTLE_BASE_URL": "https://environment.invalid/anthropic",
    }
    for key, value in environment.items():
        monkeypatch.setenv(key, value)
    requests = []

    def respond(request):
        requests.append(request)
        return httpx.Response(
            200,
            request=request,
            json={
                "id": "msg-test",
                "type": "message",
                "role": "assistant",
                "model": "anthropic.claude-example",
                "content": [{"type": "text", "text": "ok"}],
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 1, "output_tokens": 1},
            },
        )

    transport = httpx.MockTransport(respond)
    if asynchronous:

        async def send(_client, request, **_kwargs):
            return await transport.handle_async_request(request)

        monkeypatch.setattr(httpx.AsyncClient, "send", send)
    else:
        monkeypatch.setattr(
            httpx.Client,
            "send",
            lambda _client, request, **_kwargs: transport.handle_request(request),
        )
    endpoint = "https://configured.invalid/anthropic" if profile else None
    model = BedrockMantleProvider(
        _config(
            aws_profile=profile,
            base_url=endpoint,
            default_headers={"x-metis-test": "kept"},
        )
    ).get_chat_model(max_tokens=128, max_retries=0, timeout=7)
    messages = [HumanMessage(content="Reply with ok.")]
    if asynchronous:

        async def invoke():
            async with model._async_client:
                return await model.ainvoke(messages)

        response = asyncio.run(invoke())
    else:
        with model._client:
            response = model.invoke(messages)

    assert response.content == "ok"
    assert len(requests) == 1
    request = requests[0]
    assert (
        str(request.url)
        == (endpoint or environment["ANTHROPIC_BEDROCK_MANTLE_BASE_URL"])
        + "/v1/messages"
    )
    assert request.headers["x-metis-test"] == "kept"
    if profile:
        assert "Credential=profile-key/" in request.headers["Authorization"]
    else:
        assert request.headers["Authorization"] == "Bearer environment-bearer"
    assert request.extensions["timeout"]["read"] == 7
    payload = json.loads(request.content)
    assert payload["model"] == "anthropic.claude-example"
    assert payload["max_tokens"] == 128
    assert "temperature" not in payload
