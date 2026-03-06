# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.plugins.base import ConfigBackedLanguagePlugin


class PHPPlugin(ConfigBackedLanguagePlugin):
    """Language plugin providing PHP-specific splitter and prompts."""

    NAME = "php"
    DEFAULT_EXTENSIONS = [
        ".php",
        ".phps",
        ".phtm",
        ".phtml",
        ".phpt",
        ".pht",
        ".php2",
        ".php3",
        ".php4",
        ".php5",
        ".php6",
        ".php7",
        ".php8",
    ]
