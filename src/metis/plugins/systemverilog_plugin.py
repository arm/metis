# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from llama_index.core.node_parser import CodeSplitter

from metis.plugins.base import ConfigBackedLanguagePlugin


class SystemVerilogPlugin(ConfigBackedLanguagePlugin):
    """Language plugin providing SystemVerilog-specific splitter and prompts."""

    NAME = "systemverilog"
    DEFAULT_EXTENSIONS = [".sv", ".svh"]

    def get_splitter(self):
        splitting_cfg = self._plugin_section().get("splitting", {})
        return CodeSplitter(
            # Use the Verilog tree-sitter grammar; prompts remain SystemVerilog-specific.
            language="verilog",
            chunk_lines=splitting_cfg.get("chunk_lines"),
            chunk_lines_overlap=splitting_cfg.get("chunk_lines_overlap"),
            max_chars=splitting_cfg.get("max_chars"),
        )
