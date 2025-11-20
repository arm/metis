# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import logging

from metis.providers.openai_compatible import OpenAICompatibleProvider
from metis.providers.registry import register_provider


logger = logging.getLogger(__name__)


class VLLMProvider(OpenAICompatibleProvider):

    def __init__(self, config):
        super().__init__(config)
        if not self.base_url:
            raise ValueError(
                "vLLM provider requires 'openai_api_base' to be configured"
            )
        if not self.query_model:
            raise ValueError("vLLM provider requires a default query model")

        if not self.api_key:
            logger.debug("vLLM provider running without API key")


register_provider("vllm", VLLMProvider)
