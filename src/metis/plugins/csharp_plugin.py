# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.plugins.base import ConfigBackedLanguagePlugin


class CSharpPlugin(ConfigBackedLanguagePlugin):
    """Language plugin providing C#-specific splitter and prompts."""

    NAME = "csharp"
