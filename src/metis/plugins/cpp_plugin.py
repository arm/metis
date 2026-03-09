# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.plugins.base import ConfigBackedLanguagePlugin


class CppPlugin(ConfigBackedLanguagePlugin):
    NAME = "cpp"
    DEFAULT_EXTENSIONS = [".cpp", ".hpp"]

    def get_triage_analyzer_factory(self):
        from metis.engine.analysis.c_family_analyzer import (
            build_c_family_analyzer_factory,
        )

        return build_c_family_analyzer_factory(
            "cpp",
            supported_extensions=self.get_supported_extensions(),
        )
