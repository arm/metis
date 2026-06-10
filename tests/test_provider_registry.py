# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.providers.registry import get_provider


def test_registry_loads_anthropic_provider():
    provider_cls = get_provider("anthropic")

    assert provider_cls.__name__ == "AnthropicProvider"
    assert provider_cls.__module__ == "metis.providers.anthropic"


def test_registry_loads_gemini_provider():
    provider_cls = get_provider("gemini")

    assert provider_cls.__name__ == "GeminiProvider"
    assert provider_cls.__module__ == "metis.providers.gemini"


def test_registry_loads_bedrock_mantle_provider():
    provider_cls = get_provider("bedrock_mantle")

    assert provider_cls.__name__ == "BedrockMantleProvider"
    assert provider_cls.__module__ == "metis.providers.bedrock_mantle"
