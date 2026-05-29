# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.providers.registry import get_provider


def test_registry_loads_anthropic_provider():
    provider_cls = get_provider("anthropic")

    assert provider_cls.__name__ == "AnthropicProvider"
    assert provider_cls.__module__ == "metis.providers.anthropic"
