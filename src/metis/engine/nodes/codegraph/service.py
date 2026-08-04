# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
from collections.abc import Callable
from collections.abc import Iterable
from collections.abc import Mapping
from typing import TYPE_CHECKING

from metis.engine.codegraph import CodeGraph
from metis.engine.codegraph import CodeGraphDiagnostic
from metis.engine.codegraph import CodeGraphProvider
from metis.engine.codegraph import CodeGraphProviderContext
from metis.engine.codegraph import CodeGraphProviderFactory
from metis.engine.codegraph import CodeGraphReference
from metis.engine.codegraph import CodeGraphResult
from metis.version import __version__ as METIS_VERSION

from .annotations import annotate_graph
from .annotations import CodeGraphConfiguration
from .progress import CODEGRAPH_DONE
from .progress import CODEGRAPH_PROGRESS
from .progress import CODEGRAPH_START
from .provider import normalize_provider_name
from .semantics import CodeGraphSemanticsCatalog
from .store import SQLiteCodeGraphStore

if TYPE_CHECKING:
    from metis.engine.repository import EngineRepository
    from metis.engine.runtime import EngineConfig

logger = logging.getLogger(__name__)


class CodeGraphService:
    def __init__(
        self,
        config: EngineConfig,
        repository: EngineRepository,
        provider_factories: Mapping[str, CodeGraphProviderFactory],
        *,
        annotation_settings: CodeGraphConfiguration | None = None,
        semantics: CodeGraphSemanticsCatalog | None = None,
    ) -> None:
        self._config = config
        self._repository = repository
        self._provider_context = CodeGraphProviderContext(
            get_language_name_for_path=repository.get_language_name_for_path,
            has_language_file_role=repository.has_language_file_role,
        )
        self._provider_factories = {
            normalize_provider_name(name): factory
            for name, factory in provider_factories.items()
        }
        self._providers: dict[str, CodeGraphProvider] = {}
        self._provider_locks: dict[str, threading.Lock] = {}
        self._annotation_settings = annotation_settings or CodeGraphConfiguration()
        self._semantics = semantics or CodeGraphSemanticsCatalog()
        self._store: SQLiteCodeGraphStore | None = None
        self._materialize_condition = threading.Condition()
        self._materialize_active = False
        self._materialize_generation = 0
        self._last_materialization: CodeGraphReference | None = None
        self._lock = threading.RLock()

    def materialize(
        self,
        *,
        progress_callback: Callable[[dict[str, object]], None] | None = None,
        diagnostic_callback: Callable[[CodeGraphDiagnostic], None] | None = None,
    ) -> CodeGraphReference:
        with self._materialize_condition:
            while self._materialize_active:
                generation = self._materialize_generation
                self._materialize_condition.wait_for(
                    lambda: self._materialize_generation > generation
                )
                completed = self._last_materialization
                if completed is not None:
                    _replay_diagnostics(completed, diagnostic_callback)
                    return completed
            self._materialize_active = True
        try:
            completed = self._materialize(
                progress_callback=progress_callback,
                diagnostic_callback=diagnostic_callback,
            )
        except Exception:
            self._finish_materialization(None)
            raise
        self._finish_materialization(completed)
        return completed

    def _finish_materialization(
        self,
        reference: CodeGraphReference | None,
    ) -> None:
        with self._materialize_condition:
            self._last_materialization = reference
            self._materialize_generation += 1
            self._materialize_active = False
            self._materialize_condition.notify_all()

    def _materialize(
        self,
        *,
        progress_callback: Callable[[dict[str, object]], None] | None,
        diagnostic_callback: Callable[[CodeGraphDiagnostic], None] | None,
    ) -> CodeGraphReference:
        selected_files = tuple(
            sorted(
                dict.fromkeys(
                    str(path)
                    for path in self._repository.get_code_files(
                        include_suffixed_sources=True
                    )
                    if self.supports_file(str(path))
                )
            )
        )
        fingerprint = self._fingerprint(selected_files)
        store = self._store_instance()
        reference = store.reference_for_fingerprint(
            fingerprint,
            codebase_path=self._config.codebase_path,
        )
        if reference is not None and not reference.failed_files:
            _replay_diagnostics(reference, diagnostic_callback)
            return reference
        built = self._build(
            selected_files,
            progress_callback=progress_callback,
            diagnostic_callback=diagnostic_callback,
        )
        semantics_failed_files, semantics_diagnostics = annotate_graph(
            built.graph,
            semantics_for_path={
                node.file_path: self._semantics_registration_name(node.file_path)
                for node in built.graph.nodes.values()
            },
            semantics=self._semantics,
            annotation_settings=self._annotation_settings,
            progress_callback=progress_callback,
        )
        for diagnostic in semantics_diagnostics:
            if diagnostic_callback is not None:
                diagnostic_callback(diagnostic)
        return store.save(
            fingerprint=fingerprint,
            producer_version=METIS_VERSION,
            graph=built.graph,
            processed_files=built.processed_files,
            failed_files=tuple(
                dict.fromkeys((*built.failed_files, *semantics_failed_files))
            ),
            diagnostics=(*built.diagnostics, *semantics_diagnostics),
        )

    def load(self, reference: CodeGraphReference) -> CodeGraph:
        return self._store_instance().load(
            reference,
            codebase_path=self._config.codebase_path,
        )

    def _store_instance(self) -> SQLiteCodeGraphStore:
        with self._lock:
            if self._store is None:
                self._store = SQLiteCodeGraphStore(self._config.codebase_path)
            return self._store

    def _build(
        self,
        selected_files: tuple[str, ...],
        *,
        progress_callback: Callable[[dict[str, object]], None] | None,
        diagnostic_callback: Callable[[CodeGraphDiagnostic], None] | None,
    ) -> CodeGraphResult:
        provider_files = self._provider_files(selected_files)
        graph = CodeGraph()
        diagnostics: list[CodeGraphDiagnostic] = []
        processed_files: list[str] = []
        failed_files: list[str] = []
        total_files = sum(len(paths) for paths in provider_files.values())
        if progress_callback is not None:
            progress_callback({"event": CODEGRAPH_START, "total": total_files})
        completed_files = 0
        for provider_name in sorted(provider_files):
            requested_files = tuple(provider_files[provider_name])

            def report_provider_progress(event: dict[str, object]) -> None:
                if progress_callback is None:
                    return
                translated = dict(event)
                if translated.get("event") == CODEGRAPH_PROGRESS:
                    translated["completed"] = completed_files + int(
                        translated.get("completed") or 0
                    )
                    translated["total"] = total_files
                    translated["provider"] = provider_name
                progress_callback(translated)

            provider_error: RuntimeError | None = None
            try:
                provider = self._provider(provider_name)
            except ValueError:
                raise
            except RuntimeError as exc:
                provider = None
                provider_error = exc
            if provider is None:
                failed_files.extend(requested_files)
                provider_diagnostics = tuple(
                    CodeGraphDiagnostic(path, str(provider_error))
                    for path in requested_files
                )
                diagnostics.extend(provider_diagnostics)
                if diagnostic_callback is not None:
                    for diagnostic in provider_diagnostics:
                        diagnostic_callback(diagnostic)
                completed_files += len(requested_files)
                continue
            try:
                with self._provider_lock(provider_name):
                    result = self._build_provider_graph(
                        provider_name,
                        provider,
                        requested_files,
                        report_provider_progress,
                    )
                graph.merge(result.graph)
            except (RuntimeError, ValueError) as exc:
                failed_files.extend(requested_files)
                provider_diagnostics = tuple(
                    CodeGraphDiagnostic(path, str(exc)) for path in requested_files
                )
                diagnostics.extend(provider_diagnostics)
                if diagnostic_callback is not None:
                    for diagnostic in provider_diagnostics:
                        diagnostic_callback(diagnostic)
                else:
                    logger.warning("%s", exc)
                completed_files += len(requested_files)
                continue
            processed_files.extend(result.processed_files)
            failed_files.extend(result.failed_files)
            for diagnostic in result.diagnostics:
                diagnostics.append(diagnostic)
                if diagnostic_callback is not None:
                    diagnostic_callback(diagnostic)
                else:
                    logger.warning("%s: %s", diagnostic.file_path, diagnostic.message)
            completed_files += len(requested_files)

        processed_file_tuple = tuple(processed_files)
        try:
            graph.validate_for_files(
                processed_file_tuple,
                codebase_path=self._config.codebase_path,
            )
        except ValueError as exc:
            raise RuntimeError(f"Composed CodeGraph is invalid: {exc}") from exc
        if progress_callback is not None:
            progress_callback(
                {
                    "event": CODEGRAPH_DONE,
                    "nodes": graph.node_count(),
                    "edges": graph.edge_count(),
                    "globals": len(graph.get_globals()),
                    "errors": [diagnostic.message for diagnostic in diagnostics],
                }
            )
        built = CodeGraphResult(
            graph=graph.copy(),
            processed_files=processed_file_tuple,
            diagnostics=tuple(diagnostics),
            failed_files=tuple(failed_files),
        )
        return built

    def supports_file(self, path: str) -> bool:
        provider_name = self._registration_name(path)
        if provider_name is None:
            return False
        return provider_name in self._provider_factories

    def supports_semantics(self, path: str) -> bool:
        return self._semantics.has(self._registration_name(path))

    def _fingerprint(
        self,
        files: tuple[str, ...],
    ) -> str:
        entries: list[dict[str, object]] = []
        for path in sorted(files):
            absolute = (
                path
                if os.path.isabs(path)
                else os.path.join(self._config.codebase_path, path)
            )
            identity = os.path.normcase(os.path.abspath(absolute))
            content_identity = _file_identity(identity)
            provider_name = self._registration_name(path)
            semantics_name = self._semantics_registration_name(path)
            entries.append(
                {
                    "identity": identity,
                    "content": content_identity,
                    "provider": provider_name,
                    "provider_identity": self._provider_identity(provider_name),
                    "semantics": semantics_name,
                    "semantics_identity": self._semantics.cache_identity(
                        semantics_name
                    ),
                }
            )
        payload = {
            "selected_files": entries,
            "annotation_settings": self._annotation_settings.model_dump(mode="json"),
            "producer_version": METIS_VERSION,
        }
        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def _provider_identity(self, name: str | None) -> str:
        if name is None:
            return ""
        factory = self._provider_factories.get(normalize_provider_name(name))
        if factory is None:
            return ""
        identity = getattr(factory, "__metis_cache_identity__", None)
        if identity is not None:
            return str(identity)
        factory_type = type(factory)
        module = getattr(factory, "__module__", factory_type.__module__)
        name = getattr(factory, "__qualname__", factory_type.__qualname__)
        return f"{module}:{name}"

    def _provider_files(self, files: Iterable[str]) -> dict[str, list[str]]:
        grouped: dict[object, tuple[str, list[str]]] = {}
        for path in files:
            provider_name = self._registration_name(path)
            if provider_name is None:
                continue
            _, provider_files = grouped.setdefault(
                self._provider_group(provider_name),
                (provider_name, []),
            )
            provider_files.append(path)
        return {
            provider_name: provider_files
            for provider_name, provider_files in grouped.values()
        }

    def _registration_name(self, path: str) -> str | None:
        name = self._repository.get_codegraph_registration(path)
        return normalize_provider_name(name) if name is not None else None

    def _semantics_registration_name(self, path: str) -> str | None:
        name = self._registration_name(path)
        return name if self._semantics.contains(name) else None

    def _provider_group(self, name: str) -> tuple[str, str | int]:
        factory = self._provider_factories.get(name)
        if factory is None:
            return ("registration", name)
        identity = getattr(factory, "__metis_cache_identity__", None)
        if identity is not None:
            return ("entry_point", str(identity))
        return ("factory", id(factory))

    def _provider(self, provider_name: str) -> CodeGraphProvider:
        key = normalize_provider_name(provider_name)
        with self._lock:
            provider = self._providers.get(key)
            if provider is not None:
                return provider
            try:
                factory = self._provider_factories[key]
            except KeyError as exc:
                raise ValueError(f"Unknown CodeGraph provider: {key!r}") from exc
            try:
                provider = factory(self._provider_context)
            except Exception as exc:
                raise RuntimeError(
                    f"CodeGraph provider {key!r} failed to initialize: {exc}"
                ) from exc
            if not callable(getattr(provider, "build_graph", None)):
                raise RuntimeError(
                    f"CodeGraph provider {key!r} has no build_graph method"
                )
            self._providers[key] = provider
            return provider

    def _provider_lock(self, provider_name: str) -> threading.Lock:
        with self._lock:
            return self._provider_locks.setdefault(provider_name, threading.Lock())

    def _build_provider_graph(
        self,
        provider_name: str,
        provider: CodeGraphProvider,
        requested_files: tuple[str, ...],
        progress_callback: Callable[[dict[str, object]], None],
    ) -> CodeGraphResult:
        try:
            result = provider.build_graph(
                codebase_path=self._config.codebase_path,
                files=requested_files,
                progress_callback=progress_callback,
            )
        except Exception as exc:
            raise RuntimeError(
                f"CodeGraph provider {provider_name!r} failed: {exc}"
            ) from exc
        if (
            not isinstance(result, CodeGraphResult)
            or not isinstance(result.graph, CodeGraph)
            or not isinstance(result.processed_files, tuple)
            or not all(isinstance(path, str) for path in result.processed_files)
            or not isinstance(result.diagnostics, tuple)
            or not isinstance(result.failed_files, tuple)
            or not all(isinstance(path, str) for path in result.failed_files)
        ):
            raise RuntimeError(
                f"CodeGraph provider {provider_name!r} returned an invalid result"
            )
        if any(
            not isinstance(diagnostic, CodeGraphDiagnostic)
            or diagnostic.severity not in {"warning", "error"}
            for diagnostic in result.diagnostics
        ):
            raise RuntimeError(
                f"CodeGraph provider {provider_name!r} returned an invalid diagnostic"
            )
        errors = [
            diagnostic
            for diagnostic in result.diagnostics
            if diagnostic.severity == "error"
        ]
        processed = set(result.processed_files)
        failed = set(result.failed_files)
        requested = set(requested_files)
        if processed & failed or processed | failed != requested:
            raise RuntimeError(
                f"CodeGraph provider {provider_name!r} returned invalid file coverage"
            )
        error_files = {diagnostic.file_path for diagnostic in errors}
        if error_files != failed:
            raise RuntimeError(
                f"CodeGraph provider {provider_name!r} returned invalid failure "
                "diagnostics"
            )
        try:
            result.graph.validate_for_files(
                result.processed_files,
                codebase_path=self._config.codebase_path,
            )
        except ValueError as exc:
            raise RuntimeError(
                f"CodeGraph provider {provider_name!r} returned an invalid graph: {exc}"
            ) from exc
        return result


def _replay_diagnostics(
    reference: CodeGraphReference,
    callback: Callable[[CodeGraphDiagnostic], None] | None,
) -> None:
    if callback is not None:
        for diagnostic in reference.diagnostics:
            callback(diagnostic)


def _file_identity(path: str) -> dict[str, object]:
    try:
        with open(path, "rb") as source:
            return {"sha256": hashlib.file_digest(source, "sha256").hexdigest()}
    except OSError as exc:
        return {"error": type(exc).__name__, "errno": exc.errno}
