# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from abc import ABC, abstractmethod

from llama_index.core.node_parser import CodeSplitter


class BaseLanguagePlugin(ABC):
    @abstractmethod
    def get_name(self) -> str:
        """Return the name of the plugin."""
        pass

    @abstractmethod
    def can_handle(self, extension: str) -> bool:
        """Return True if this plugin can handle the file extension."""
        pass

    @abstractmethod
    def get_splitter(self):
        """Return a splitter instance for code."""
        pass

    @abstractmethod
    def get_prompts(self) -> dict:
        """Return a dictionary of language-specific prompts."""
        pass

    @abstractmethod
    def get_supported_extensions(self) -> list:
        """Return a list of file extensions supported by this language."""
        pass

    def get_triage_analyzer_factory(self):
        """Return optional factory(codebase_path) -> analyzer used by triage."""
        language = str(self.get_name() or "").strip().lower()
        if not language:
            return None
        from metis.engine.analysis.generic_treesitter_analyzer import (
            build_generic_treesitter_analyzer_factory,
        )

        supported_extensions = [
            str(ext).lower() for ext in self.get_supported_extensions()
        ]
        return build_generic_treesitter_analyzer_factory(
            language,
            supported_extensions=supported_extensions,
        )


class ConfigBackedLanguagePlugin(BaseLanguagePlugin):
    NAME = ""
    DEFAULT_EXTENSIONS: list[str] = []

    def __init__(self, plugin_config):
        self.plugin_config = plugin_config

    def get_name(self) -> str:
        return self.NAME

    def _plugin_section(self) -> dict:
        return self.plugin_config.get("plugins", {}).get(self.get_name(), {})

    def can_handle(self, extension: str) -> bool:
        return str(extension or "").lower() in self.get_supported_extensions()

    def get_supported_extensions(self) -> list:
        configured = self._plugin_section().get(
            "supported_extensions", self.DEFAULT_EXTENSIONS
        )
        return [str(ext).lower() for ext in configured]

    def get_splitter(self):
        splitting_cfg = self._plugin_section().get("splitting", {})
        return CodeSplitter(
            language=self.get_name(),
            chunk_lines=splitting_cfg.get("chunk_lines"),
            chunk_lines_overlap=splitting_cfg.get("chunk_lines_overlap"),
            max_chars=splitting_cfg.get("max_chars"),
        )

    def get_prompts(self) -> dict:
        return self._plugin_section().get("prompts", {})
