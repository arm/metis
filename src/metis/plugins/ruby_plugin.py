# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from llama_index.core.node_parser import CodeSplitter

from metis.plugins.base import BaseLanguagePlugin


class RubyPlugin(BaseLanguagePlugin):
    def __init__(self, plugin_config):
        self.plugin_config = plugin_config

    def get_name(self):
        return "ruby"

    def can_handle(self, extension):
        supported = self.get_supported_extensions()
        return extension.lower() in supported

    def get_supported_extensions(self):
        return (
            self.plugin_config.get("plugins", {})
            .get(self.get_name(), {})
            .get("supported_extensions", [".rb"])
        )

    def get_splitter(self):
        splitting_cfg = (
            self.plugin_config.get("plugins", {})
            .get(self.get_name(), {})
            .get("splitting", {})
        )
        return CodeSplitter(
            language=self.get_name(),
            chunk_lines=splitting_cfg["chunk_lines"],
            chunk_lines_overlap=splitting_cfg["chunk_lines_overlap"],
            max_chars=splitting_cfg["max_chars"],
        )

    def get_prompts(self):
        return (
            self.plugin_config.get("plugins", {})
            .get(self.get_name(), {})
            .get("prompts", {})
        )
