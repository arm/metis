# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.plugins.base import ConfigBackedLanguagePlugin


class DefaultLanguagePlugin(ConfigBackedLanguagePlugin):
    """Review source without a dedicated language plugin."""

    NAME = "default"

    def can_handle(self, extension: str) -> bool:
        return True

    def get_splitter(self):
        raise NotImplementedError("Default language plugin does not support indexing")
