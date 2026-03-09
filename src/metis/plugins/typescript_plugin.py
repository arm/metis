# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.plugins.base import ConfigBackedLanguagePlugin


class TypeScriptPlugin(ConfigBackedLanguagePlugin):
    """Language plugin providing TypeScript-specific splitter and prompts."""

    NAME = "typescript"
    DEFAULT_EXTENSIONS = [".ts", ".tsx"]
