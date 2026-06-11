# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import importlib.util

import pytest

from metis.providers.registry import _LOADERS, get_provider


@pytest.mark.parametrize(
    ("name", "dotted_path", "module"),
    [
        ("anthropic", "metis.providers.anthropic:AnthropicProvider", "langchain_anthropic"),
        ("bedrock", "metis.providers.bedrock:BedrockProvider", "langchain_aws"),
        ("bedrock_mantle", "metis.providers.bedrock_mantle:BedrockMantleProvider", "anthropic"),
        ("gemini", "metis.providers.gemini:GeminiProvider", "langchain_google_genai"),
    ],
)
def test_registry_loads_optional_provider(name, dotted_path, module):
    assert _LOADERS[name] == dotted_path

    if importlib.util.find_spec(module) is None:
        with pytest.raises(ModuleNotFoundError, match="required dependencies"):
            get_provider(name)
    else:
        provider_cls = get_provider(name)
        assert provider_cls.__module__ == dotted_path.split(":", 1)[0]
        assert provider_cls.__name__ == dotted_path.split(":", 1)[1]
