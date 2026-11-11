# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import logging
import os
from threading import Lock

import pathspec
from llama_index.core.node_parser import SentenceSplitter

from .runtime import EngineConfig, EngineState

logger = logging.getLogger("metis")


def _matches_suffix_pattern(name: str, pattern: str) -> bool:
    if "*" not in pattern:
        return name.endswith(pattern)
    if pattern.count("*") != 1 or not pattern.endswith("*"):
        return False
    return pattern[:-1] in name


class EngineRepository:
    def __init__(self, config: EngineConfig, state: EngineState):
        self._config = config
        self._state = state
        self._metisignore_loaded = False
        self._metisignore_spec: pathspec.GitIgnoreSpec | None = None
        self._metisignore_lock = Lock()
        self._review_path_specs: dict[
            str, tuple[tuple[str, ...], pathspec.GitIgnoreSpec]
        ] = {}
        self._review_path_lock = Lock()

    def get_plugin_for_extension(self, extension):
        registry = self._config.language_registry
        if registry is not None:
            return registry.get_plugin_for_extension(extension)
        return self._config.ext_plugin_map.get(extension.lower())

    def get_plugin_for_path(self, path: str):
        registry = self._config.language_registry
        if registry is not None:
            return registry.get_plugin_for_path(path)
        ext = os.path.splitext(path)[1].lower()
        plugin = self.get_plugin_for_extension(ext)
        if plugin is not None:
            return plugin

        name = os.path.basename(path).lower()
        for pattern, plugin in self._config.ext_pattern_plugin_map:
            if _matches_suffix_pattern(name, pattern):
                return plugin
        return None

    def get_language_name_for_path(self, path: str) -> str | None:
        registry = self._config.language_registry
        if registry is not None:
            return registry.language_name_for_path(path)
        plugin = self.get_plugin_for_path(path)
        if plugin is None:
            return None
        return str(getattr(plugin, "get_name", lambda: "")() or "").lower() or None

    def has_language_file_role(self, path: str, role: str) -> bool:
        registry = self._config.language_registry
        if registry is None:
            return False
        manifest = registry.get_manifest_for_path(path)
        if manifest is None:
            return False
        extension = os.path.splitext(str(path or ""))[1].lower()
        role_extensions = getattr(manifest, f"{role}_extensions", ())
        return extension in role_extensions

    def supports_reachability_file(self, path: str) -> bool:
        registry = self._config.language_registry
        if registry is not None:
            return registry.supports_reachability_file(path)
        plugin = self.get_plugin_for_path(path)
        supports = getattr(plugin, "supports_reachability_review", None)
        return bool(callable(supports) and supports())

    def get_all_supported_code_extensions(self):
        registry = self._config.language_registry
        if registry is not None:
            return registry.supported_code_extensions()
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

    def resolve_metisignore_path(self) -> str | None:
        metisignore_file = self._config.metisignore_file
        if not metisignore_file:
            return None
        if os.path.isabs(metisignore_file):
            return metisignore_file
        return os.path.abspath(
            os.path.join(self._config.codebase_path, metisignore_file)
        )

    def normalize_match_path(self, path: str) -> str:
        base_path = os.path.abspath(self._config.codebase_path)
        if os.path.isabs(path):
            abs_path = os.path.abspath(path)
            try:
                if os.path.commonpath([base_path, abs_path]) == base_path:
                    return os.path.relpath(abs_path, base_path)
            except ValueError:
                return os.path.normpath(path)
        return os.path.normpath(path)

    def is_metisignored(
        self, path: str, spec: pathspec.GitIgnoreSpec | None = None
    ) -> bool:
        if spec is None:
            spec = self.load_metisignore()
        return bool(spec and spec.match_file(self.normalize_match_path(path)))

    def load_metisignore(self) -> pathspec.GitIgnoreSpec | None:
        if self._metisignore_loaded:
            return self._metisignore_spec
        with self._metisignore_lock:
            if self._metisignore_loaded:
                return self._metisignore_spec
            metisignore_path = self.resolve_metisignore_path()
            try:
                if not metisignore_path:
                    logger.debug("No MetisIgnore file provided")
                else:
                    with open(metisignore_path, "r") as metisignore_file:
                        self._metisignore_spec = pathspec.GitIgnoreSpec.from_lines(
                            metisignore_file, backend="simple"
                        )
                    logger.info(f"MetisIgnore file loaded: {metisignore_path}")
            except FileNotFoundError:
                logger.debug(f"MetisIgnore file not loaded {metisignore_path}")
            self._metisignore_loaded = True
            return self._metisignore_spec

    def get_code_files(
        self, *, include_suffixed_sources: bool = False, dir_path: str | None = None
    ):
        base_path = os.path.abspath(self._config.codebase_path)
        if dir_path:
            base_path = os.path.join(base_path, dir_path)
        metisignore_spec = self.load_metisignore()
        include_spec = None
        if self._config.review_code_include_paths:
            include_spec = self._review_path_spec(
                "include", self._config.review_code_include_paths
            )
        exclude_spec = None
        if self._config.review_code_exclude_paths:
            exclude_spec = self._review_path_spec(
                "exclude", self._config.review_code_exclude_paths
            )
        file_list = []
        for root, _, files in os.walk(base_path):
            for file in files:
                full_path = os.path.join(root, file)
                if include_suffixed_sources:
                    if self.get_language_name_for_path(full_path) is None:
                        continue
                elif (
                    os.path.splitext(file)[1].lower()
                    not in self.get_all_supported_code_extensions()
                ):
                    continue
                rel_path = self.normalize_match_path(full_path)
                if metisignore_spec and metisignore_spec.match_file(rel_path):
                    continue
                if include_spec and not include_spec.match_file(rel_path):
                    continue
                if exclude_spec and exclude_spec.match_file(rel_path):
                    continue
                file_list.append(full_path)
        return file_list

    def _review_path_spec(self, kind: str, paths: list[str]) -> pathspec.GitIgnoreSpec:
        patterns = tuple(paths)
        with self._review_path_lock:
            cached = self._review_path_specs.get(kind)
            if cached is None or cached[0] != patterns:
                cached = (
                    patterns,
                    pathspec.GitIgnoreSpec.from_lines(patterns, backend="simple"),
                )
                self._review_path_specs[kind] = cached
            return cached[1]
