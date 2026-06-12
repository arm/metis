# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import pytest

pytest.importorskip("langchain_anthropic")
pytest.importorskip("anthropic")

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
    assert llm.model == "anthropic.claude-example"
    assert llm.aws_profile == "example-profile"
    assert llm.aws_region == "example-region"


def test_chat_model_does_not_default_to_a_specific_region():
    provider = BedrockMantleProvider(_config(aws_region=None))

    llm = provider.get_chat_model()

    assert llm.aws_region is None
