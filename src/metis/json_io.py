# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import math
import os
import re
import stat
import tempfile
import heapq
import sys
from collections.abc import Iterable
from collections.abc import Iterator
from collections import deque
from contextlib import closing
from contextlib import contextmanager
from contextlib import AbstractContextManager
from contextlib import nullcontext
from dataclasses import dataclass
from decimal import Decimal
from decimal import InvalidOperation
from pathlib import Path
from typing import Any
from typing import TextIO
from threading import Condition
from threading import Event
from threading import Thread
from threading import current_thread

from ijson import backend_name
from ijson import basic_parse
from ijson import get_backend
from ijson import JSONError
from ijson import ObjectBuilder
from ijson import sendable_list


def json_object_from_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("JSON contains a duplicate mapping key")
        value[key] = item
    return value


def parse_json_object(data: bytes) -> dict[str, Any]:
    if not isinstance(data, bytes):
        raise TypeError("JSON data must be bytes")
    if data.startswith(b"\xef\xbb\xbf"):
        raise ValueError("JSON must not contain a UTF-8 byte order mark")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("JSON must be valid UTF-8") from None

    def reject_constant(_value):
        raise ValueError("JSON contains a non-finite number")

    try:
        payload = json.loads(
            text,
            object_pairs_hook=json_object_from_pairs,
            parse_constant=reject_constant,
        )
    except (json.JSONDecodeError, RecursionError):
        raise ValueError("Input must contain exactly one valid JSON document") from None
    if not isinstance(payload, dict):
        raise ValueError("JSON payload must be an object")
    validate_json_tree(payload)
    return payload


def load_json_object_file(path: str | Path) -> dict[str, Any]:
    """Load a strict JSON object without file-size or collection-size caps."""
    return parse_json_object(Path(path).read_bytes())


def validate_json_tree(payload: object) -> None:
    if not isinstance(payload, (dict, list)):
        _validate_json_scalar(payload)
        return
    stack: list[tuple[Iterator[Any], int | None]] = [(iter((payload,)), None)]
    ancestors: set[int] = set()
    while stack:
        values, container_id = stack[-1]
        try:
            value = next(values)
        except StopIteration:
            stack.pop()
            if container_id is not None:
                ancestors.remove(container_id)
            continue
        if isinstance(value, dict):
            for key in value:
                if type(key) is not str:
                    raise ValueError("JSON mapping keys must be strings")
                _validate_string(key)
            children = iter(value.values())
        elif isinstance(value, list):
            children = iter(value)
        else:
            _validate_json_scalar(value)
            continue
        identity = id(value)
        if identity in ancestors:
            raise ValueError("JSON contains a recursive container")
        ancestors.add(identity)
        stack.append((children, identity))


def _validate_json_scalar(value: object) -> None:
    if type(value) is str:
        _validate_string(value)
    elif type(value) is float:
        if not math.isfinite(value):
            raise ValueError("JSON contains a non-finite number")
    elif value is not None and type(value) not in {bool, int}:
        raise ValueError("JSON payload must contain only JSON values")


def _validate_string(value: str) -> None:
    if not value.isascii() and re.search(r"[\ud800-\udfff]", value):
        raise ValueError("JSON strings must contain Unicode scalar values")


def write_json_atomic(
    path: str | Path,
    payload: object,
    *,
    indent: int,
    ensure_ascii: bool = True,
    allow_nan: bool = False,
    mode: int | None = None,
) -> None:
    with atomic_text_writer(path, mode=0o600 if mode is None else mode) as handle:
        json.dump(
            payload,
            handle,
            indent=indent,
            ensure_ascii=ensure_ascii,
            allow_nan=allow_nan,
        )


@contextmanager
def atomic_text_writer(
    path: str | Path,
    *,
    mode: int | None = None,
    newline: str | None = None,
    publication: AbstractContextManager[object] | None = None,
) -> Iterator[TextIO]:
    """Replace a text output only after its complete contents reach disk."""
    target = Path(path)
    target.parent.stat()
    target = target.parent.resolve() / target.name
    if mode is None:
        try:
            mode = stat.S_IMODE(target.stat().st_mode)
        except FileNotFoundError:
            pass
    with tempfile.TemporaryDirectory(
        dir=target.parent, prefix=".metis-", suffix=".tmp"
    ) as directory:
        temporary_directory = Path(directory)
        temporary_directory.chmod(0o700)
        temporary = temporary_directory / "report"
        with temporary.open("w", encoding="utf-8", newline=newline) as handle:
            yield handle
            handle.flush()
            os.fsync(handle.fileno())
        if mode is not None:
            temporary.chmod(mode)
        with publication if publication is not None else nullcontext():
            os.replace(temporary, target)


@dataclass(frozen=True, slots=True)
class JsonArray:
    """An iterable JSON array consumed once by write_json_stream_atomic."""

    items: Iterable[object]


def _write_json_events(output, events):
    encoder = json.JSONEncoder(ensure_ascii=True, allow_nan=False)
    counts = []
    after_key = False
    for event, value in events:
        if event in {"end_map", "end_array"}:
            count = counts.pop()
            if count:
                output.write("\n" + "    " * len(counts))
            output.write("}" if event == "end_map" else "]")
            continue
        if counts and not after_key:
            output.write(("," if counts[-1] else "") + "\n" + "    " * len(counts))
            counts[-1] += 1
        after_key = event == "map_key"
        if after_key:
            if type(value) is not str:
                raise ValueError("JSON mapping keys must be strings")
            _validate_string(value)
            output.write(encoder.encode(value) + ": ")
        elif event in {"start_map", "start_array"}:
            output.write("{" if event == "start_map" else "[")
            counts.append(0)
        else:
            validate_json_tree(value)
            output.write(
                json.dumps(value, ensure_ascii=True, allow_nan=False, indent=4).replace(
                    "\n", "\n" + "    " * len(counts)
                )
                if event == "record"
                else encoder.encode(value)
            )


def write_json_stream_atomic(
    path: str | Path,
    payload: object,
    *,
    publication: AbstractContextManager[object] | None = None,
) -> None:
    """Validate and publish JSON incrementally, including nested iterable arrays."""
    ancestors: set[int] = set()

    def events(value):
        if isinstance(value, (dict, list, tuple, JsonArray)):
            identity = id(value)
            if identity in ancestors:
                raise ValueError("JSON contains a recursive container")
            ancestors.add(identity)
            mapping = isinstance(value, dict)
            yield ("start_map" if mapping else "start_array"), None
            entries = (
                value.items()
                if mapping
                else value.items
                if isinstance(value, JsonArray)
                else value
            )
            for entry in entries:
                if mapping:
                    key, item = entry
                    yield "map_key", key
                else:
                    item = entry
                yield from events(item)
            yield ("end_map" if mapping else "end_array"), None
            ancestors.remove(identity)
        else:
            yield "value", value

    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with atomic_text_writer(
        target,
        mode=0o600,
        publication=publication,
    ) as output:
        _write_json_events(output, events(payload))


_JSON_JOURNAL_BUFFER_BYTES = 8 * 1024 * 1024


class JsonJournal:
    """Drain the current backlog without holding the producer lock during I/O."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._condition = Condition()
        self._queue: deque[bytes | Event | None] = deque()
        self._queued_bytes = 0
        self._output = os.fdopen(
            os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600),
            "wb",
            buffering=0,
        )
        self.count = 0
        self.size = 0
        self._error: BaseException | None = None
        self._closed = False
        self._finished = Event()
        self._writer = Thread(
            target=self._write,
            name="metis-json-writer",
        )
        try:
            self._writer.start()
        except BaseException:
            self._output.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, _exc_type, exception, _traceback):
        try:
            self.close()
        except BaseException as error:
            if exception is None:
                raise
            if error is not exception:
                exception.add_note(f"Closing JSON journal also failed: {error}")

    def _write(self) -> None:
        try:
            while True:
                with self._condition:
                    self._condition.wait_for(lambda: bool(self._queue))
                    batch = tuple(self._queue)
                    self._queue.clear()
                    self._queued_bytes = 0
                    self._condition.notify_all()
                data = b"".join(item for item in batch if isinstance(item, bytes))
                if data:
                    if self._output.write(data) != len(data):
                        raise OSError("Incomplete JSON journal write")
                for item in batch:
                    if isinstance(item, Event):
                        item.set()
                if batch[-1] is None:
                    return
                del batch, data, item
        except BaseException as error:
            with self._condition:
                self._error = error
                self._condition.notify_all()
        finally:
            self._finished.set()

    def flush(self) -> int:
        """Wait for accepted records and return their stable byte boundary."""
        completed = Event()
        with self._condition:
            if self._error is not None:
                raise self._error
            if self._closed:
                raise ValueError("JSON journal is closed")
            limit = self.size
            self._queue.append(completed)
            self._condition.notify()
        while not completed.wait(0.1):
            if self._error is not None:
                raise self._error
        if self._error is not None:
            raise self._error
        return limit

    def close(self) -> None:
        if current_thread() is self._writer:
            raise RuntimeError("A journal writer cannot close itself")
        with self._condition:
            if not self._closed:
                self._closed = True
                self._queue.append(None)
                self._condition.notify_all()
        self._finished.wait()
        self._writer.join()
        self._output.close()
        if self._error is not None:
            raise self._error

    def append(self, record: object) -> None:
        if not isinstance(record, dict):
            raise ValueError("JSON journal records must be objects")
        validate_json_tree(record)
        data = (
            json.dumps(
                record, ensure_ascii=True, allow_nan=False, separators=(",", ":")
            )
            + "\n"
        ).encode("ascii")
        size = sys.getsizeof(data)
        with self._condition:
            self._condition.wait_for(
                lambda: (
                    self._error is not None
                    or self._closed
                    or self._queued_bytes == 0
                    or self._queued_bytes + size <= _JSON_JOURNAL_BUFFER_BYTES
                )
            )
            if self._error is not None:
                raise self._error
            if self._closed:
                raise ValueError("JSON journal is closed")
            self._queue.append(data)
            self._queued_bytes += size
            self.count += 1
            self.size += len(data)
            self._condition.notify_all()

    @staticmethod
    def records(path: str | Path, *, limit: int | None = None, start: int = 0):
        with Path(path).open("rb") as source:
            source.seek(start)
            consumed = start
            while limit is None or consumed < limit:
                line = source.readline(-1 if limit is None else limit - consumed)
                if not line:
                    return
                consumed += len(line)
                yield parse_json_object(line)


@contextmanager
def sorted_json_records(
    records, *, key, directory: str | Path, check_cancelled=lambda: None
):
    """External merge sort with bounded chunks and at most 32 open input files."""
    with (
        tempfile.TemporaryDirectory(dir=directory, prefix="sort-") as temporary,
        closing(records) if getattr(records, "close", None) else nullcontext(),
    ):
        root = Path(temporary)
        runs = []
        chunk = []
        size = 0
        serial = 0

        def save(values):
            nonlocal serial
            path = root / f"{serial}.jsonl"
            serial += 1
            with path.open("w", encoding="ascii") as output:
                for value in values:
                    check_cancelled()
                    output.write(
                        json.dumps(
                            value,
                            ensure_ascii=True,
                            allow_nan=False,
                            separators=(",", ":"),
                        )
                        + "\n"
                    )
            return path

        def read_run(path):
            with path.open("rb") as source:
                for line in source:
                    yield json.loads(line)

        @contextmanager
        def merge_runs(paths):
            sources = [read_run(path) for path in paths]
            try:
                yield heapq.merge(*sources, key=key)
            finally:
                for source in sources:
                    source.close()

        for record in records:
            check_cancelled()
            validate_json_tree(record)
            chunk.append(record)
            size += len(json.dumps(record, ensure_ascii=True))
            if size >= 8 * 1024 * 1024 or len(chunk) >= 4096:
                runs.append(save(sorted(chunk, key=key)))
                chunk = []
                size = 0
        if chunk:
            runs.append(save(sorted(chunk, key=key)))
        while len(runs) > 32:
            merged = []
            for start in range(0, len(runs), 32):
                group = runs[start : start + 32]
                with merge_runs(group) as records:
                    merged.append(save(records))
                for path in group:
                    path.unlink()
            runs = merged
        with merge_runs(runs) as records:
            yield records


@dataclass(slots=True)
class _JsonContainer:
    path: tuple[str | int, ...]
    kind: str
    count: int = 0
    key: str | None = None
    keys: set[str] | None = None


class JsonSnapshot:
    """Validated input copy for sequential JSON reads and atomic rewrites."""

    def __init__(self, source: str | Path) -> None:
        self._temporary = tempfile.TemporaryDirectory(prefix="metis-json-")
        self.directory = Path(self._temporary.name)
        self.path = self.directory / "snapshot.json"
        self._parse = self._fallback_events if backend_name == "python" else basic_parse
        self._readers = set()
        digit_limit = sys.get_int_max_str_digits()
        trailing_digits = 0
        escape_tail = b""
        unpaired_surrogate = re.compile(
            rb"\\u[dD][89aAbB][0-9a-fA-F]{2}(?!\\u[dD][c-fC-F][0-9a-fA-F]{2})"
        )
        try:
            with Path(source).open("rb") as original, self.path.open("xb") as copied:
                before = os.fstat(original.fileno())
                while chunk := original.read(1024 * 1024):
                    if b"\x0b" in chunk or b"\x0c" in chunk:
                        raise ValueError("JSON contains an invalid control character")
                    escaped = escape_tail + chunk
                    if self._parse is basic_parse and any(
                        match.start() + 12 <= len(escaped)
                        for match in unpaired_surrogate.finditer(escaped)
                    ):
                        self._parse = self._fallback_events
                    escape_tail = escaped[-11:]
                    if digit_limit and self._parse is basic_parse:
                        for offset in range(0, len(chunk), digit_limit):
                            block = chunk[offset : offset + digit_limit]
                            leading_digits = len(block) - len(
                                block.lstrip(b"0123456789")
                            )
                            if trailing_digits + leading_digits > digit_limit:
                                self._parse = self._fallback_events
                                break
                            trailing_digits = (
                                trailing_digits + leading_digits
                                if leading_digits == len(block)
                                else len(block) - len(block.rstrip(b"0123456789"))
                            )
                    copied.write(chunk)
                after = os.fstat(original.fileno())
                if (before.st_size, before.st_mtime_ns) != (
                    after.st_size,
                    after.st_mtime_ns,
                ) or (
                    before.st_nlink == after.st_nlink
                    and before.st_ctime_ns != after.st_ctime_ns
                ):
                    raise ValueError("JSON input changed while taking its snapshot")
            if unpaired_surrogate.search(escape_tail):
                self._parse = self._fallback_events
            try:
                for _event in self.events(validate=True):
                    pass
            except InvalidOperation:
                self._parse = self._fallback_events
                for _event in self.events(validate=True):
                    pass
        except BaseException:
            self.close()
            raise

    def __enter__(self) -> JsonSnapshot:
        return self

    def __exit__(self, *_args) -> None:
        self.close()

    def close(self) -> None:
        for reader in tuple(self._readers):
            reader.close()
        self._readers.clear()
        self._temporary.cleanup()

    @contextmanager
    def _reader(self, path: Path | None = None, *, text: bool = False):
        path = self.path if path is None else path
        reader = path.open(encoding="utf-8") if text else path.open("rb")
        self._readers.add(reader)
        try:
            yield reader
        finally:
            reader.close()
            self._readers.discard(reader)

    def _fallback_events(self, source: TextIO, *, validate: bool):
        def chunks():
            quoted = escaped = False
            remainder = []
            while chunk := source.read(1024 * 1024):
                start = int(escaped)
                escaped = False
                boundary = 0
                for match in re.finditer(
                    r'\\.|"|[{}\[\],:\t\r\n ]+|[^\x20-\x7e\t\r\n]|\\$',
                    chunk[start:],
                    re.DOTALL,
                ):
                    token = match.group()
                    if token == '"':
                        quoted = not quoted
                        if not quoted:
                            boundary = start + match.end()
                    elif token == "\\":
                        escaped = True
                    elif not quoted and not token.startswith("\\"):
                        if token[0] not in "{}[],: \t\r\n":
                            raise ValueError("JSON contains invalid whitespace")
                        boundary = start + match.end()
                if boundary:
                    remainder.append(chunk[:boundary])
                    yield "".join(remainder) + " "
                    remainder = [chunk[boundary:]]
                else:
                    remainder.append(chunk)
            if remainder:
                yield "".join(remainder) + " "

        events = sendable_list()
        parser = get_backend("python").basic_parse_coro(events, use_float=True)
        decoder = json.JSONDecoder()
        separators = re.compile(r"[{}\[\],: \t\r\n]+")
        try:
            for chunk in chunks():
                if validate:
                    position = 0
                    while position < len(chunk):
                        separator = separators.match(chunk, position)
                        position = (
                            separator.end()
                            if separator is not None
                            else decoder.raw_decode(chunk, position)[1]
                        )
                parser.send(chunk.encode("utf-8"))
                yield from events
                events.clear()
            parser.close()
            yield from events
        finally:
            try:
                parser.close()
            except JSONError:
                pass

    def events(self, *, validate: bool = False):
        stack: list[_JsonContainer] = []
        fallback = self._parse is not basic_parse
        with self._reader(text=fallback) as source:
            try:
                parsed = (
                    self._parse(source, validate=validate)
                    if fallback
                    else self._parse(source, buf_size=1024 * 1024)
                )
                for event, value in parsed:
                    if event in {"end_map", "end_array"}:
                        path = stack.pop().path
                    elif event == "map_key":
                        parent = stack[-1]
                        path = parent.path
                        if parent.keys is not None:
                            if value in parent.keys:
                                raise ValueError(
                                    "JSON contains a duplicate mapping key"
                                )
                            parent.keys.add(value)
                        parent.key = value
                    else:
                        path = ()
                        if stack:
                            parent = stack[-1]
                            if parent.kind == "start_array":
                                path = (*parent.path, parent.count)
                                parent.count += 1
                            else:
                                path = (*parent.path, parent.key)
                        if event in {"start_map", "start_array"}:
                            stack.append(
                                _JsonContainer(
                                    path,
                                    event,
                                    keys=set()
                                    if validate and event == "start_map"
                                    else None,
                                )
                            )
                    if isinstance(value, Decimal):
                        if not value.is_finite():
                            raise InvalidOperation("JSON number exceeds Decimal range")
                        value = float(value)
                    if validate:
                        _validate_json_scalar(value)
                    yield path, event, value
            except (JSONError, UnicodeError, OverflowError) as exc:
                message = str(exc)
                if any(value in message for value in ("NaN", "Infinity")):
                    raise ValueError("JSON contains a non-finite number") from None
                raise ValueError(f"Invalid JSON input: {message[:200]}") from None

    def _walk(self, patterns, *, observe=None):
        builder = None
        selected = None
        with closing(self.events()) as events:
            for path, event, value in events:
                if observe is not None:
                    observe(path, event, value)
                if builder is not None:
                    builder.event(event, value)
                    if path == selected and event in {"end_map", "end_array"}:
                        yield path, "record", builder.value
                        builder = None
                elif event not in {"map_key", "end_map", "end_array"} and any(
                    len(path) == len(pattern)
                    and all(
                        actual == expected
                        if expected is not None
                        else type(actual) is int
                        for actual, expected in zip(path, pattern)
                    )
                    for pattern in patterns
                ):
                    if event in {"start_map", "start_array"}:
                        selected = path
                        builder = ObjectBuilder()
                        builder.event(event, value)
                    else:
                        yield path, "record", value
                else:
                    yield path, event, value

    def items(self, *patterns, observe=None):
        """Yield (path, value) for non-overlapping selected paths, one at a time."""
        with closing(self._walk(patterns, observe=observe)) as events:
            for path, event, value in events:
                if event == "record":
                    yield path, value

    def write(
        self,
        target: str | Path,
        *,
        at=None,
        transform=None,
        publication: AbstractContextManager[object] | None = None,
    ) -> None:
        """Stream the snapshot to a new file, optionally transforming selected values."""
        if (at is None) != (transform is None):
            raise ValueError("JSON transform requires both a path and a function")
        target = Path(target)
        target.parent.mkdir(parents=True, exist_ok=True)
        with atomic_text_writer(
            target,
            mode=0o600,
            publication=publication,
        ) as output:
            if transform is None:
                with self._reader() as source:
                    while chunk := source.read(1024 * 1024):
                        output.buffer.write(chunk)
            else:
                with closing(self._walk((at,))) as events:
                    _write_json_events(
                        output,
                        (
                            (
                                event,
                                transform(path, value) if event == "record" else value,
                            )
                            for path, event, value in events
                        ),
                    )
