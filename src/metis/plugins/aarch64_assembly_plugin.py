# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from llama_index.core.node_parser import CodeSplitter, SentenceSplitter

from metis.plugins.base import ConfigBackedLanguagePlugin


class _AsmNodeAdapter:
    def __init__(self, node):
        self._node = node

    @property
    def children(self):
        return [
            _AsmNodeAdapter(self._node.child(index))
            for index in range(self._node.child_count())
        ]

    @property
    def type(self):
        return self._node.kind()

    @property
    def start_byte(self):
        return self._node.start_byte()

    @property
    def end_byte(self):
        return self._node.end_byte()


class _AsmTreeAdapter:
    def __init__(self, tree):
        self._tree = tree

    @property
    def root_node(self):
        return _AsmNodeAdapter(self._tree.root_node())


class _AsmParserAdapter:
    """Adapt py-tree-sitter style parsers to the interface CodeSplitter expects."""

    def __init__(self, parser):
        self._parser = parser

    def parse(self, source):
        if isinstance(source, bytes):
            source = source.decode("utf-8", errors="ignore")
        return _AsmTreeAdapter(self._parser.parse(source))


class AArch64AssemblyPlugin(ConfigBackedLanguagePlugin):
    """Language plugin providing AArch64 assembly-specific prompts."""

    NAME = "aarch64_assembly"

    def get_triage_analyzer_factory(self):
        return None

    def get_splitter(self):
        splitting_cfg = self._plugin_section().get("splitting", {})
        chunk_lines = splitting_cfg.get("chunk_lines") or 60
        chunk_lines_overlap = splitting_cfg.get("chunk_lines_overlap") or 20
        max_chars = splitting_cfg.get("max_chars") or 2500

        try:
            from tree_sitter_language_pack import get_parser

            return CodeSplitter(
                language="asm",
                chunk_lines=chunk_lines,
                chunk_lines_overlap=chunk_lines_overlap,
                max_chars=max_chars,
                parser=_AsmParserAdapter(get_parser("asm")),
            )
        except Exception:
            return SentenceSplitter(
                chunk_size=max_chars,
                chunk_overlap=chunk_lines_overlap,
            )
