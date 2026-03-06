# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.plugins.base import ConfigBackedLanguagePlugin


class CPlugin(ConfigBackedLanguagePlugin):
    NAME = "c"
    DEFAULT_EXTENSIONS = [".c", ".h", ".cc"]

    def get_triage_analyzer_factory(self):
        from metis.engine.analysis.c_family_analyzer import (
            build_c_family_analyzer_factory,
        )

        return build_c_family_analyzer_factory(
            "c",
            supported_extensions=self.get_supported_extensions(),
        )
