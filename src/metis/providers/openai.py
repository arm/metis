# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.providers.openai_compatible import OpenAICompatibleProvider
from metis.providers.registry import register_provider

import logging

logger = logging.getLogger(__name__)


class OpenAIProvider(OpenAICompatibleProvider):
    pass


register_provider("openai", OpenAIProvider)
