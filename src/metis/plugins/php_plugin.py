# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.plugins.base import ConfigBackedLanguagePlugin


class PHPPlugin(ConfigBackedLanguagePlugin):
    """Language plugin providing PHP-specific splitter and prompts."""

    NAME = "php"
