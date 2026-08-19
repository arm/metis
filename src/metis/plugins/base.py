# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from abc import ABC, abstractmethod
from collections.abc import Mapping
from typing import Any

from llama_index.core.node_parser import CodeSplitter


def build_code_splitter(
    language: str,
    splitting_cfg: Mapping[str, Any],
) -> CodeSplitter:
    """Build a CodeSplitter with a parser compatible with llama-index."""
    from tree_sitter import Parser
    import tree_sitter_language_pack

    kwargs: dict[str, Any] = {
        "language": language,
        "parser": Parser(tree_sitter_language_pack.get_language(language)),
    }
    for key in ("chunk_lines", "chunk_lines_overlap", "max_chars"):
        if splitting_cfg.get(key) is not None:
            kwargs[key] = splitting_cfg[key]
    return CodeSplitter(**kwargs)


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


class ConfigBackedLanguagePlugin(BaseLanguagePlugin):
    NAME = ""

    def __init__(
        self,
        plugin_config: Mapping[str, Any],
        *,
        name: str | None = None,
    ) -> None:
        self.plugin_config = plugin_config
        self._name = name or self.NAME
        if not self._name:
            raise ValueError("Language plugin name is required")

    def get_name(self) -> str:
        return self._name

    def _plugin_section(self) -> dict[str, Any]:
        return self.plugin_config.get("plugins", {}).get(self.get_name(), {})

    def can_handle(self, extension: str) -> bool:
        return str(extension or "").lower() in self.get_supported_extensions()

    def get_supported_extensions(self) -> list[str]:
        configured = self._plugin_section().get("supported_extensions", [])
        return [str(ext).lower() for ext in configured]

    def get_splitter(self) -> CodeSplitter:
        splitting_cfg = self._plugin_section().get("splitting", {})
        return build_code_splitter(self.get_name(), splitting_cfg)

    def get_prompts(self) -> dict[str, Any]:
        return self._plugin_section().get("prompts", {})
