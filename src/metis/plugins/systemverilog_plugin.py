# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.plugins.base import ConfigBackedLanguagePlugin, build_code_splitter


class SystemVerilogPlugin(ConfigBackedLanguagePlugin):
    """Language plugin providing SystemVerilog-specific splitter and prompts."""

    NAME = "systemverilog"
    DEFAULT_EXTENSIONS = [".sv", ".svh"]

    def get_splitter(self):
        splitting_cfg = self._plugin_section().get("splitting", {})
        # Use the Verilog tree-sitter grammar; prompts remain SystemVerilog-specific.
        return build_code_splitter("verilog", splitting_cfg)
