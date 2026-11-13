# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from llama_index.core.node_parser import SentenceSplitter

from metis.plugins.base import ConfigBackedLanguagePlugin
from metis.plugins.base import build_code_splitter


class AArch64AssemblyPlugin(ConfigBackedLanguagePlugin):
    """Language plugin providing AArch64 assembly-specific prompts."""

    NAME = "aarch64_assembly"

    def get_splitter(self):
        splitting_cfg = self._plugin_section().get("splitting", {})
        chunk_lines = splitting_cfg.get("chunk_lines") or 60
        chunk_lines_overlap = splitting_cfg.get("chunk_lines_overlap") or 20
        max_chars = splitting_cfg.get("max_chars") or 2500

        try:
            return build_code_splitter(
                "asm",
                {
                    "chunk_lines": chunk_lines,
                    "chunk_lines_overlap": chunk_lines_overlap,
                    "max_chars": max_chars,
                },
            )
        except Exception:
            return SentenceSplitter(
                chunk_size=max_chars,
                chunk_overlap=chunk_lines_overlap,
            )
