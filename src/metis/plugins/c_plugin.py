# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.plugins.base import ConfigBackedLanguagePlugin


class CPlugin(ConfigBackedLanguagePlugin):
    NAME = "c"

    def supports_reachability_review(self) -> bool:
        return True
