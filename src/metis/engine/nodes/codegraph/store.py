# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import os
import sqlite3
import threading
from collections.abc import Iterable
from collections.abc import Iterator
from contextlib import closing
from dataclasses import dataclass
from typing import Any

from pydantic import TypeAdapter

from metis.engine.codegraph import CodeGraph
from metis.engine.codegraph import CodeGraphDiagnostic
from metis.engine.codegraph import CodeGraphReference
from metis.engine.codegraph import FunctionNode
from metis.engine.codegraph import GlobalConstruct

_STORE_SCHEMA_VERSION = 2
_FUNCTION_NODE = TypeAdapter(FunctionNode)
_GLOBAL_CONSTRUCT = TypeAdapter(GlobalConstruct)
_DIAGNOSTIC = TypeAdapter(CodeGraphDiagnostic)


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

    def reference_for_fingerprint(
        self,
        fingerprint: str,
        *,
        codebase_path: str,
    ) -> CodeGraphReference | None:
        with self._lock:
            try:
                with closing(_connect(self.location)) as connection:
                    latest = None
                    for row in connection.execute(
                        """
                        SELECT revision
                        FROM canonical_codegraph
                        WHERE fingerprint = ?
                        ORDER BY revision DESC
                        """,
                        (fingerprint,),
                    ):
                        try:
                            stored = _read_stored_graph(
                                connection,
                                codebase_path=codebase_path,
                                revision=int(row[0]),
                            )
                        except RuntimeError:
                            continue
                        if stored is not None:
                            if not stored.reference.failed_files:
                                return stored.reference
                            if latest is None:
                                latest = stored.reference
            except sqlite3.Error as exc:
                raise RuntimeError(
                    f"Unable to read CodeGraph store {self.location!r}: {exc}"
                ) from exc
        return latest

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
        records = _graph_records(
            graph,
            processed_files=processed_files,
            failed_files=failed_files,
            diagnostics=diagnostics,
        )
        content_hash = _records_hash(records)
        with self._lock:
            try:
                with closing(_connect(self.location)) as connection:
                    connection.execute("BEGIN IMMEDIATE")
                    cursor = connection.execute(
                        """
                        INSERT INTO canonical_codegraph (
                            fingerprint, producer_version, content_hash
                        ) VALUES (?, ?, ?)
                        """,
                        (fingerprint, producer_version, content_hash),
                    )
                    revision = int(cursor.lastrowid)
                    connection.executemany(
                        """
                        INSERT INTO codegraph_records(
                            graph_revision, position, kind, identity, payload
                        ) VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            (revision, position, kind, identity, payload)
                            for position, (kind, identity, payload) in enumerate(
                                _graph_records(
                                    graph,
                                    processed_files=processed_files,
                                    failed_files=failed_files,
                                    diagnostics=diagnostics,
                                )
                            )
                        ),
                    )
                    reference = CodeGraphReference(
                        revision=revision,
                        fingerprint=fingerprint,
                        producer_version=producer_version,
                        failed_files=failed_files,
                        diagnostics=diagnostics,
                    )
                    connection.commit()
            except sqlite3.Error as exc:
                raise RuntimeError(
                    f"Unable to persist CodeGraph store {self.location!r}: {exc}"
                ) from exc
        return reference

    def load(
        self,
        reference: CodeGraphReference,
        *,
        codebase_path: str,
    ) -> CodeGraph:
        with self._lock:
            try:
                with closing(_connect(self.location)) as connection:
                    stored = _read_stored_graph(
                        connection,
                        codebase_path=codebase_path,
                        revision=reference.revision,
                    )
            except sqlite3.Error as exc:
                raise RuntimeError(
                    f"Unable to read CodeGraph store {self.location!r}: {exc}"
                ) from exc
        if stored is None or stored.reference != reference:
            raise ValueError("CodeGraph reference does not exist")
        return stored.graph

    def _initialize(self) -> None:
        directory = os.path.dirname(self.location)
        try:
            os.makedirs(directory, exist_ok=True)
            with closing(_connect(self.location)) as connection:
                connection.execute("PRAGMA foreign_keys = OFF")
                with connection:
                    connection.execute("BEGIN IMMEDIATE")
                    current_version = int(
                        connection.execute("PRAGMA user_version").fetchone()[0]
                    )
                    if current_version > _STORE_SCHEMA_VERSION:
                        raise RuntimeError(
                            f"CodeGraph store {self.location!r} uses a newer schema "
                            f"({current_version}); this version supports {_STORE_SCHEMA_VERSION}"
                        )
                    if current_version != _STORE_SCHEMA_VERSION:
                        _drop_store_tables(connection)
                    _create_store_tables(connection)
                    _retain_graph_revisions(connection)
                    connection.execute(
                        "CREATE INDEX IF NOT EXISTS codegraph_by_fingerprint "
                        "ON canonical_codegraph(fingerprint, revision)"
                    )
                    connection.execute(f"PRAGMA user_version = {_STORE_SCHEMA_VERSION}")
                connection.execute("PRAGMA foreign_keys = ON")
        except (OSError, sqlite3.Error) as exc:
            raise RuntimeError(
                f"Unable to initialize CodeGraph store {self.location!r}: {exc}"
            ) from exc


def _read_stored_graph(
    connection: sqlite3.Connection,
    *,
    codebase_path: str,
    revision: int,
) -> StoredCodeGraph | None:
    if revision > 2**63 - 1:
        return None
    metadata = connection.execute(
        """
        SELECT revision, fingerprint, producer_version, content_hash
        FROM canonical_codegraph WHERE revision = ?
        """,
        (revision,),
    ).fetchone()
    if metadata is None:
        return None
    try:
        reference = _reference_from_connection(connection, metadata)
        graph, processed_files = _graph_from_records(
            _stored_records(
                connection,
                revision=revision,
                expected_hash=str(metadata[3]),
            )
        )
        graph.validate_for_files(processed_files, codebase_path=codebase_path)
    except (TypeError, ValueError) as exc:
        database = connection.execute("PRAGMA database_list").fetchone()[2]
        raise RuntimeError(
            f"Stored CodeGraph at {database!r} is invalid: {exc}"
        ) from exc
    return StoredCodeGraph(reference, graph)


def _reference_from_connection(
    connection: sqlite3.Connection,
    metadata: tuple[object, ...],
) -> CodeGraphReference:
    revision = int(metadata[0])
    failed_files: list[str] = []
    diagnostics: list[CodeGraphDiagnostic] = []
    for kind, identity, payload in connection.execute(
        """
        SELECT kind, identity, payload FROM codegraph_records
        WHERE graph_revision = ? AND kind IN ('failed', 'diagnostic')
        ORDER BY position
        """,
        (revision,),
    ):
        if kind == "failed":
            failed_files.append(str(identity))
        else:
            diagnostics.append(
                _DIAGNOSTIC.validate_json(payload, strict=True, extra="forbid")
            )
    return CodeGraphReference(
        revision=revision,
        fingerprint=str(metadata[1]),
        producer_version=str(metadata[2]),
        failed_files=tuple(failed_files),
        diagnostics=tuple(diagnostics),
    )


def _graph_from_records(
    records: Iterable[tuple[str, str, bytes]],
) -> tuple[CodeGraph, tuple[str, ...]]:
    graph = CodeGraph()
    processed_files: list[str] = []
    declarations: dict[str, list[str]] = {}
    for kind, identity, payload in records:
        if kind == "node":
            node = _FUNCTION_NODE.validate_json(payload, strict=True, extra="forbid")
            if node.unique_name != identity:
                raise ValueError(
                    "Stored CodeGraph node identity does not match its row"
                )
            graph.add_node(node)
        elif kind == "global":
            construct = _GLOBAL_CONSTRUCT.validate_json(
                payload,
                strict=True,
                extra="forbid",
            )
            if construct.unique_name != identity:
                raise ValueError(
                    "Stored CodeGraph global identity does not match its row"
                )
            graph.add_global(construct)
        elif kind == "declaration":
            declarations.setdefault(str(identity), []).append(
                bytes(payload).decode("utf-8")
            )
        elif kind == "processed":
            processed_files.append(str(identity))
    graph.add_public_declarations(declarations)
    return graph, tuple(processed_files)


def _graph_records(
    graph: CodeGraph,
    *,
    processed_files: tuple[str, ...],
    failed_files: tuple[str, ...],
    diagnostics: tuple[CodeGraphDiagnostic, ...],
) -> Iterator[tuple[str, str, bytes]]:
    for unique_name, node in graph.nodes.items():
        yield "node", unique_name, _FUNCTION_NODE.dump_json(node)
    for unique_name, construct in graph.globals.items():
        yield "global", unique_name, _GLOBAL_CONSTRUCT.dump_json(construct)
    for name, locations in graph.public_declarations.items():
        for location in locations or ("",):
            yield "declaration", name, location.encode("utf-8")
    for path in processed_files:
        yield "processed", path, b""
    for path in failed_files:
        yield "failed", path, b""
    for diagnostic in diagnostics:
        yield "diagnostic", "", _DIAGNOSTIC.dump_json(diagnostic)


def _records_hash(records: Iterable[tuple[str, str, bytes]]) -> str:
    digest = hashlib.sha256()
    for kind, identity, payload in records:
        _update_hash(digest, kind, identity, payload)
    return digest.hexdigest()


def _stored_records(
    connection: sqlite3.Connection,
    *,
    revision: int,
    expected_hash: str,
) -> Iterator[tuple[str, str, bytes]]:
    digest = hashlib.sha256()
    for kind, identity, payload in connection.execute(
        """
        SELECT kind, identity, payload FROM codegraph_records
        WHERE graph_revision = ? ORDER BY position
        """,
        (revision,),
    ):
        record = str(kind), str(identity), bytes(payload)
        _update_hash(digest, *record)
        yield record
    if digest.hexdigest() != expected_hash:
        raise ValueError("Stored CodeGraph records are incomplete or modified")


def _update_hash(
    digest: Any,
    kind: str,
    identity: str,
    payload: bytes,
) -> None:
    for value in (kind.encode("utf-8"), identity.encode("utf-8"), payload):
        digest.update(len(value).to_bytes(8, "big"))
        digest.update(value)


def _drop_store_tables(connection: sqlite3.Connection) -> None:
    for table in (
        "codegraph_records",
        "codegraph_diagnostics",
        "codegraph_failed_files",
        "codegraph_processed_files",
        "codegraph_public_declarations",
        "codegraph_globals",
        "codegraph_nodes",
        "canonical_codegraph",
    ):
        connection.execute(f"DROP TABLE IF EXISTS {table}")


def _create_store_tables(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS canonical_codegraph (
            revision INTEGER PRIMARY KEY AUTOINCREMENT,
            fingerprint TEXT NOT NULL,
            producer_version TEXT NOT NULL,
            content_hash TEXT NOT NULL
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS codegraph_records (
            graph_revision INTEGER NOT NULL REFERENCES canonical_codegraph(revision)
                ON DELETE CASCADE,
            position INTEGER NOT NULL,
            kind TEXT NOT NULL CHECK (
                kind IN (
                    'node', 'global', 'declaration',
                    'processed', 'failed', 'diagnostic'
                )
            ),
            identity TEXT NOT NULL,
            payload BLOB NOT NULL,
            PRIMARY KEY (graph_revision, position)
        )
        """
    )
    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS codegraph_records_by_kind
        ON codegraph_records(graph_revision, kind, position);
        """
    )


def _retain_graph_revisions(connection: sqlite3.Connection) -> None:
    # The v2 record format is unchanged; remove its old one-revision constraint.
    if not any(
        row[2] for row in connection.execute("PRAGMA index_list(canonical_codegraph)")
    ):
        return
    connection.execute(
        """
        CREATE TABLE canonical_codegraph_revisions (
            revision INTEGER PRIMARY KEY AUTOINCREMENT,
            fingerprint TEXT NOT NULL,
            producer_version TEXT NOT NULL,
            content_hash TEXT NOT NULL
        )
        """
    )
    connection.execute(
        """
        INSERT INTO canonical_codegraph_revisions
        SELECT revision, fingerprint, producer_version, content_hash
        FROM canonical_codegraph
        """
    )
    connection.execute("DROP TABLE canonical_codegraph")
    connection.execute(
        "ALTER TABLE canonical_codegraph_revisions RENAME TO canonical_codegraph"
    )


def _connect(location: str) -> sqlite3.Connection:
    connection = sqlite3.connect(location)
    connection.execute("PRAGMA foreign_keys = ON")
    return connection
