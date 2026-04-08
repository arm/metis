# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import logging
import os

import pathspec
from llama_index.core.node_parser import SentenceSplitter

from .runtime import EngineConfig, EngineState

logger = logging.getLogger("metis")


class EngineRepository:
    def __init__(self, config: EngineConfig, state: EngineState):
        self._config = config
        self._state = state

    def get_plugin_for_extension(self, extension):
        return self._config.ext_plugin_map.get(extension.lower())

    def get_all_supported_code_extensions(self):
        return sorted(self._config.code_exts)

    def get_splitter_cached(self, plugin):
        key = plugin.get_name()
        if key in self._state.splitter_cache:
            return self._state.splitter_cache[key]
        splitter = plugin.get_splitter()
        self._state.splitter_cache[key] = splitter
        return splitter

    def get_doc_splitter(self):
        if self._state.doc_splitter is None:
            self._state.doc_splitter = SentenceSplitter(
                chunk_size=self._config.doc_chunk_size,
                chunk_overlap=self._config.doc_chunk_overlap,
            )
        return self._state.doc_splitter

    def rel_to_base(self, path):
        base_path = os.path.abspath(self._config.codebase_path)
        return base_path, os.path.relpath(path, base_path)

    def load_metisignore(self) -> pathspec.GitIgnoreSpec | None:
        try:
            if not self._config.metisignore_file:
                logger.info("No MetisIgnore file provided")
                return None
            with open(self._config.metisignore_file, "r") as f:
                spec = pathspec.GitIgnoreSpec.from_lines(f)
                logger.info(f"MetisIgnore file loaded: {self._config.metisignore_file}")
            return spec
        except FileNotFoundError:
            logger.info(f"MetisIgnore file not loaded {self._config.metisignore_file}")
            return None

    def get_code_files(self):
        base_path = os.path.abspath(self._config.codebase_path)
        metisignore_spec = self.load_metisignore()
        include_spec = None
        if self._config.review_code_include_paths:
            include_spec = pathspec.GitIgnoreSpec.from_lines(
                self._config.review_code_include_paths
            )
        exclude_spec = None
        if self._config.review_code_exclude_paths:
            exclude_spec = pathspec.GitIgnoreSpec.from_lines(
                self._config.review_code_exclude_paths
            )
        file_list = []
        for root, _, files in os.walk(base_path):
            for file in files:
                full_path = os.path.join(root, file)
                ext = os.path.splitext(file)[1].lower()
                if ext not in self._config.code_exts:
                    continue
                rel_path = os.path.relpath(full_path, base_path)
                if metisignore_spec and metisignore_spec.match_file(rel_path):
                    continue
                if include_spec and not include_spec.match_file(rel_path):
                    continue
                if exclude_spec and exclude_spec.match_file(rel_path):
                    continue
                file_list.append(full_path)
        return file_list
