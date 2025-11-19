# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.providers.openai_compatible import OpenAICompatibleProvider
from metis.providers.registry import register_provider

import logging

logger = logging.getLogger(__name__)


class OpenAIProvider(OpenAICompatibleProvider):
    def __init__(self, config):
        super().__init__(config)
        if not self.api_key:
            raise ValueError(
                "OPENAI_API_KEY environment variable is required for OpenAI provider but not set."
            )


register_provider("openai", OpenAIProvider)
