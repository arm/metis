# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import logging
import os
from threading import Lock

import pathspec
from llama_index.core.node_parser import SentenceSplitter

from metis.utils import resolve_path_within_root

from .runtime import EngineConfig
from .runtime import EngineState
from .source import ProfiledSourceArtifact
from .source import SourceView

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
        self._profiled_source: ProfiledSourceArtifact | None = None

    def install_profiled_source(self, artifact: ProfiledSourceArtifact) -> None:
        self._profiled_source = artifact

    @property
    def profiled_source_fingerprint(self) -> str | None:
        artifact = self._profiled_source
        return artifact.reference.fingerprint if artifact is not None else None

    def source_view_for_path(self, path: str) -> SourceView | None:
        artifact = self._profiled_source
        if (
            artifact is None
            or self.get_language_name_for_path(path) not in artifact.languages
        ):
            return None
        view = artifact.view_for_path(self._config.codebase_path, path)
        if view is not None:
            try:
                current = resolve_path_within_root(
                    self._config.codebase_path,
                    path,
                ).read_bytes()
            except OSError as exc:
                raise RuntimeError(
                    f"Unable to verify profiled source {path!r}"
                ) from exc
            if current != view.raw:
                raise RuntimeError(
                    f"Profiled source changed after initialization: {path}"
                )
            return view
        return SourceView(b"", b"")

    def source_profile_applies_to_path(self, path: str) -> bool:
        artifact = self._profiled_source
        return (
            artifact is not None
            and self.get_language_name_for_path(path) in artifact.languages
        )

    def analysis_source_for_path(self, path: str) -> bytes | None:
        if self.source_view_for_path(path) is None:
            return None
        artifact = self._profiled_source
        assert artifact is not None
        return artifact.analysis_for_path(self._config.codebase_path, path) or b""

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

    def get_codegraph_registration(self, path: str) -> str | None:
        registry = self._config.language_registry
        if registry is None:
            return None
        return registry.codegraph_registration_for_path(path)

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
                            metisignore_file
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
        file_list = []
        for root, _, files in os.walk(base_path):
            for file in files:
                full_path = os.path.join(root, file)
                if not self.is_code_file_selected(
                    full_path,
                    include_suffixed_sources=include_suffixed_sources,
                    metisignore_spec=metisignore_spec,
                ):
                    continue
                file_list.append(full_path)
        return file_list

    def is_code_file_selected(
        self,
        path: str,
        *,
        include_suffixed_sources: bool = False,
        metisignore_spec: pathspec.GitIgnoreSpec | None = None,
    ) -> bool:
        base_path = os.path.abspath(self._config.codebase_path)
        full_path = (
            os.path.abspath(path)
            if os.path.isabs(path)
            else os.path.abspath(os.path.join(base_path, path))
        )
        try:
            if os.path.commonpath((base_path, full_path)) != base_path:
                return False
        except ValueError:
            return False
        if not os.path.isfile(full_path):
            return False
        if include_suffixed_sources:
            if self.get_language_name_for_path(full_path) is None:
                return False
        elif (
            os.path.splitext(full_path)[1].lower()
            not in self.get_all_supported_code_extensions()
        ):
            return False
        if metisignore_spec is None:
            metisignore_spec = self.load_metisignore()
        rel_path = self.normalize_match_path(full_path)
        if metisignore_spec and metisignore_spec.match_file(rel_path):
            return False
        include_paths = self._config.review_code_include_paths
        if include_paths and not pathspec.GitIgnoreSpec.from_lines(
            include_paths
        ).match_file(rel_path):
            return False
        exclude_paths = self._config.review_code_exclude_paths
        return not (
            exclude_paths
            and pathspec.GitIgnoreSpec.from_lines(exclude_paths).match_file(rel_path)
        )
