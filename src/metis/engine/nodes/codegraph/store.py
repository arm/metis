# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import os
import sqlite3
import threading
from dataclasses import dataclass

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import TypeAdapter

from metis.engine.codegraph import CodeGraph
from metis.engine.codegraph import CodeGraphDiagnostic
from metis.engine.codegraph import CodeGraphReference
from metis.engine.codegraph import FunctionNode
from metis.engine.codegraph import GlobalConstruct


class _GraphEnvelope(BaseModel):
    nodes: tuple[FunctionNode, ...]
    globals: tuple[GlobalConstruct, ...]
    public_declarations: dict[str, tuple[str, ...]]

    model_config = ConfigDict(extra="forbid", frozen=True)


_DIAGNOSTICS = TypeAdapter(tuple[CodeGraphDiagnostic, ...])


@dataclass(frozen=True, slots=True)
class StoredCodeGraph:
    reference: CodeGraphReference
    graph: CodeGraph


class SQLiteCodeGraphStore:
    def __init__(self, codebase_path: str) -> None:
        self.location = os.path.abspath(
            os.path.join(codebase_path, ".metis", "codegraph.sqlite3")
        )
        self._lock = threading.RLock()
        self._initialize()

    def current(self, *, codebase_path: str) -> StoredCodeGraph | None:
        with self._lock:
            try:
                with sqlite3.connect(self.location) as connection:
                    row = connection.execute(
                        """
                        SELECT revision, fingerprint, producer_version,
                               processed_files, failed_files, diagnostics, graph
                        FROM canonical_codegraph WHERE singleton = 1
                        """
                    ).fetchone()
            except sqlite3.Error as exc:
                raise RuntimeError(
                    f"Unable to read CodeGraph store {self.location!r}: {exc}"
                ) from exc
        return (
            self._decode(row, codebase_path=codebase_path) if row is not None else None
        )

    def reference_for_fingerprint(
        self,
        fingerprint: str,
        *,
        codebase_path: str,
    ) -> CodeGraphReference | None:
        with self._lock:
            try:
                with sqlite3.connect(self.location) as connection:
                    row = connection.execute(
                        """
                        SELECT revision, fingerprint, producer_version,
                               processed_files, failed_files, diagnostics, graph
                        FROM canonical_codegraph
                        WHERE singleton = 1 AND fingerprint = ?
                        """,
                        (fingerprint,),
                    ).fetchone()
            except sqlite3.Error as exc:
                raise RuntimeError(
                    f"Unable to read CodeGraph store {self.location!r}: {exc}"
                ) from exc
        if row is None:
            return None
        try:
            return self._decode(row, codebase_path=codebase_path).reference
        except RuntimeError:
            return None

    def save(
        self,
        *,
        fingerprint: str,
        producer_version: str,
        graph: CodeGraph,
        processed_files: tuple[str, ...],
        failed_files: tuple[str, ...],
        diagnostics: tuple[CodeGraphDiagnostic, ...],
    ) -> CodeGraphReference:
        graph_json = _graph_json(graph)
        processed_json = _json(list(processed_files))
        failed_json = _json(list(failed_files))
        diagnostics_json = _json(
            [
                {
                    "file_path": item.file_path,
                    "message": item.message,
                    "severity": item.severity,
                }
                for item in diagnostics
            ]
        )
        with self._lock:
            try:
                with sqlite3.connect(self.location) as connection:
                    connection.execute("BEGIN IMMEDIATE")
                    current = connection.execute(
                        """
                        SELECT revision, fingerprint, producer_version,
                               processed_files, failed_files, diagnostics, graph
                        FROM canonical_codegraph WHERE singleton = 1
                        """
                    ).fetchone()
                    unchanged = current is not None and (
                        current[1],
                        current[2],
                        current[3],
                        current[4],
                        current[5],
                        current[6],
                    ) == (
                        fingerprint,
                        producer_version,
                        processed_json,
                        failed_json,
                        diagnostics_json,
                        graph_json,
                    )
                    if unchanged:
                        connection.commit()
                        return _reference_from_values(
                            current[0],
                            current[1],
                            current[2],
                            current[4],
                            current[5],
                        )
                    revision = 1 if current is None else int(current[0]) + 1
                    connection.execute(
                        """
                        INSERT INTO canonical_codegraph (
                            singleton, revision, fingerprint, producer_version,
                            processed_files, failed_files, diagnostics, graph
                        ) VALUES (1, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(singleton) DO UPDATE SET
                            revision = excluded.revision,
                            fingerprint = excluded.fingerprint,
                            producer_version = excluded.producer_version,
                            processed_files = excluded.processed_files,
                            failed_files = excluded.failed_files,
                            diagnostics = excluded.diagnostics,
                            graph = excluded.graph
                        """,
                        (
                            revision,
                            fingerprint,
                            producer_version,
                            processed_json,
                            failed_json,
                            diagnostics_json,
                            graph_json,
                        ),
                    )
                    connection.commit()
            except sqlite3.Error as exc:
                raise RuntimeError(
                    f"Unable to persist CodeGraph store {self.location!r}: {exc}"
                ) from exc
        reference = CodeGraphReference(
            revision=revision,
            fingerprint=fingerprint,
            producer_version=producer_version,
            failed_files=failed_files,
            diagnostics=diagnostics,
        )
        return reference

    def load(
        self,
        reference: CodeGraphReference,
        *,
        codebase_path: str,
    ) -> CodeGraph:
        current = self.current(codebase_path=codebase_path)
        if current is None:
            raise ValueError("CodeGraph reference does not exist")
        if current.reference != reference:
            raise ValueError("CodeGraph reference is not the current canonical graph")
        return current.graph

    def _initialize(self) -> None:
        directory = os.path.dirname(self.location)
        try:
            os.makedirs(directory, exist_ok=True)
            with sqlite3.connect(self.location) as connection:
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS canonical_codegraph (
                        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                        revision INTEGER NOT NULL,
                        fingerprint TEXT NOT NULL,
                        producer_version TEXT NOT NULL,
                        processed_files TEXT NOT NULL,
                        failed_files TEXT NOT NULL,
                        diagnostics TEXT NOT NULL,
                        graph TEXT NOT NULL
                    )
                    """
                )
                connection.commit()
        except (OSError, sqlite3.Error) as exc:
            raise RuntimeError(
                f"Unable to initialize CodeGraph store {self.location!r}: {exc}"
            ) from exc

    def _decode(
        self,
        row: tuple[object, ...],
        *,
        codebase_path: str,
    ) -> StoredCodeGraph:
        (
            revision,
            fingerprint,
            version,
            processed_raw,
            failed_raw,
            diagnostics_raw,
            graph_raw,
        ) = row
        try:
            processed = tuple(json.loads(str(processed_raw)))
            graph = _graph_from_json(str(graph_raw))
            graph.validate_for_files(processed, codebase_path=codebase_path)
            reference = _reference_from_values(
                revision,
                fingerprint,
                version,
                failed_raw,
                diagnostics_raw,
            )
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                f"Stored CodeGraph at {self.location!r} is invalid: {exc}"
            ) from exc
        return StoredCodeGraph(reference, graph)


def _json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _reference_from_values(
    revision: object,
    fingerprint: object,
    producer_version: object,
    failed_raw: object,
    diagnostics_raw: object,
) -> CodeGraphReference:
    diagnostics = _DIAGNOSTICS.validate_python(
        json.loads(str(diagnostics_raw)),
        extra="forbid",
    )
    return CodeGraphReference(
        revision=revision,
        fingerprint=fingerprint,
        producer_version=producer_version,
        failed_files=tuple(json.loads(str(failed_raw))),
        diagnostics=diagnostics,
    )


def _graph_json(graph: CodeGraph) -> str:
    return _GraphEnvelope(
        nodes=tuple(graph.nodes.values()),
        globals=tuple(graph.globals.values()),
        public_declarations={
            name: tuple(locations)
            for name, locations in graph.public_declarations.items()
        },
    ).model_dump_json()


def _graph_from_json(raw: str) -> CodeGraph:
    payload = _GraphEnvelope.model_validate_json(raw, strict=True, extra="forbid")
    graph = CodeGraph()
    for item in payload.nodes:
        graph.add_node(item)
    for item in payload.globals:
        graph.add_global(item)
    graph.add_public_declarations(
        {
            name: list(locations)
            for name, locations in payload.public_declarations.items()
        }
    )
    return graph
