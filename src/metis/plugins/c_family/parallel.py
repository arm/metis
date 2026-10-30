# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Node-scheduled C-family parsing through a process pool."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from concurrent.futures import CancelledError
from functools import partial
from multiprocessing import get_context
from pathlib import Path
from threading import Event
from threading import Lock
from time import monotonic
from typing import TYPE_CHECKING
import os
import signal

from metis.engine.concurrency import _cancellation_checkpoint

if TYPE_CHECKING:
    from multiprocessing.pool import Pool
    from metis.engine.codegraph import CodeGraphProviderContext
    from .codegraph import ParsedFileGraph

_BATCH_TIMEOUT_SECONDS = 300
_FileEntry = tuple[str, str, str | None, frozenset[str], bytes | None]


def _init_worker() -> None:
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, signal.SIG_DFL)


def parse_files_in_parallel(
    codebase_path: str, files: tuple[str, ...], context: CodeGraphProviderContext
) -> dict[str, ParsedFileGraph] | None:
    execution = context.get_jobs() if context.get_jobs is not None else None
    if execution is None or execution[1] == 1:
        return None
    jobs, max_workers = execution
    if len({os.path.dirname(path) for path in files}) < 2:
        return None
    from .codegraph import ParsedFileGraph

    folders: dict[str, list[_FileEntry]] = defaultdict(list)
    weights: dict[str, int] = defaultdict(int)
    result: dict[str, ParsedFileGraph] = {}
    for path in files:
        _cancellation_checkpoint()
        relative = os.path.relpath(
            os.path.join(codebase_path, path), codebase_path
        ).replace("\\", "/")
        try:
            language = context.get_language_name_for_path(relative)
            roles = frozenset(
                role
                for role in ("source", "header")
                if context.has_language_file_role(relative, role)
            )
            source = (
                context.source_for_path(path)
                if context.source_for_path is not None
                else None
            )
        except CancelledError:
            raise
        except Exception as exc:
            result[path] = ParsedFileGraph(errors=[f"{type(exc).__name__}: {exc}"])
            continue
        folder = os.path.dirname(path)
        folders[folder].append((path, relative, language, roles, source))
        try:
            weights[folder] += (Path(codebase_path) / path).stat().st_size
        except OSError:
            pass
    if not folders:
        return result
    count = min(max_workers, len(folders))
    batches: list[list[_FileEntry]] = [[] for _ in range(count)]
    totals = [0] * count
    for folder in sorted(folders, key=lambda key: (-weights[key], key)):
        index = min(range(count), key=lambda i: (totals[i], len(batches[i])))
        batches[index].extend(folders[folder])
        totals[index] += weights[folder]

    _cancellation_checkpoint()
    pool = get_context("spawn").Pool(
        processes=count,
        maxtasksperchild=1,
        initializer=_init_worker,
    )
    shutdown_lock = Lock()
    closed = Event()

    def stop_pool() -> None:
        with shutdown_lock:
            if not closed.is_set():
                closed.set()
                pool.terminate()
                pool.join()

    try:
        results = jobs.run(
            tuple(tuple(batch) for batch in batches if batch),
            partial(
                _parse_batch,
                codebase_path=codebase_path,
                pool=pool,
                stop_pool=stop_pool,
                pool_closed=closed,
            ),
            label=None,
            result_key=lambda batch: batch[0][0],
        )
        result.update(
            (path, parsed) for batch in results for path, parsed in batch.items()
        )
        return result
    finally:
        stop_pool()


def _parse_batch(
    entries: tuple[_FileEntry, ...],
    *,
    codebase_path: str,
    pool: Pool,
    stop_pool: Callable[[], None],
    pool_closed: Event,
) -> dict[str, ParsedFileGraph]:
    from .codegraph import ParsedFileGraph

    try:
        pending = pool.apply_async(_parse_files, (codebase_path, entries))
        deadline = monotonic() + _BATCH_TIMEOUT_SECONDS
        while not pending.ready():
            _cancellation_checkpoint()
            if pool_closed.is_set():
                raise RuntimeError("Parser pool stopped")
            if monotonic() >= deadline:
                raise TimeoutError("Parser batch exceeded 300 seconds")
            pending.wait(timeout=0.1)
        _cancellation_checkpoint()
        parsed = pending.get()
        if (
            not isinstance(parsed, dict)
            or parsed.keys() != {entry[0] for entry in entries}
            or not all(isinstance(item, ParsedFileGraph) for item in parsed.values())
        ):
            raise ValueError("Parser pool returned invalid file results")
        return parsed
    except CancelledError:
        stop_pool()
        raise
    except Exception as exc:
        stop_pool()
        return {
            entry[0]: ParsedFileGraph(errors=[f"{type(exc).__name__}: {exc}"])
            for entry in entries
        }
    except BaseException:
        stop_pool()
        raise


def _parse_files(
    codebase_path: str, entries: tuple[_FileEntry, ...]
) -> dict[str, ParsedFileGraph]:
    from metis.engine.codegraph import CodeGraphProviderContext
    from .codegraph import CFamilyTreeSitterExtractor
    from .codegraph import ParsedFileGraph

    metadata = {}
    for path, relative, *facts in entries:
        metadata[path] = metadata[relative] = facts
    context = CodeGraphProviderContext(
        get_language_name_for_path=lambda path: metadata[path][0],
        has_language_file_role=lambda path, role: role in metadata[path][1],
        source_for_path=lambda path: metadata[path][2],
    )
    extractor = CFamilyTreeSitterExtractor(context)
    result = {}
    for path, *_rest in entries:
        try:
            result[path] = extractor.parse_file(
                codebase_path=codebase_path, file_path=path
            )
        except CancelledError:
            raise
        except Exception as exc:
            result[path] = ParsedFileGraph(errors=[f"{type(exc).__name__}: {exc}"])
    return result
