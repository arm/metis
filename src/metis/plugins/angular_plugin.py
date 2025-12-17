# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from llama_index.core.node_parser import CodeSplitter

from metis.plugins.base import BaseLanguagePlugin


class AngularPlugin(BaseLanguagePlugin):
    """Language plugin providing Angular-specific splitter and prompts."""

    def __init__(self, plugin_config):
        self.plugin_config = plugin_config

    def get_name(self) -> str:
        return "angular"

    def can_handle(self, extension: str) -> bool:
        supported = self.get_supported_extensions()
        return extension.lower() in supported

    def get_supported_extensions(self) -> list[str]:
        exts = (
            self.plugin_config.get("plugins", {})
            .get(self.get_name(), {})
            .get("supported_extensions", [".ts"])
        )
        return [e.lower() for e in exts]

    def get_splitter(self):
        splitting_cfg = (
            self.plugin_config.get("plugins", {})
            .get(self.get_name(), {})
            .get("splitting", {})
        )
        # Angular is TypeScript-based
        return CodeSplitter(
            language="typescript",
            chunk_lines=splitting_cfg.get("chunk_lines"),
            chunk_lines_overlap=splitting_cfg.get("chunk_lines_overlap"),
            max_chars=splitting_cfg.get("max_chars"),
        )

    def get_prompts(self) -> dict:
        return (
            self.plugin_config.get("plugins", {})
            .get(self.get_name(), {})
            .get("prompts", {})
        )
