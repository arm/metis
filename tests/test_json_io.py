# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import hashlib
import stat
import subprocess
import sys
import tracemalloc
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext
from decimal import InvalidOperation
from decimal import localcontext
from textwrap import dedent
from tempfile import TemporaryDirectory
from pathlib import Path
from threading import Event

import pytest
import metis.json_io as json_io

from metis.json_io import atomic_text_writer
from metis.json_io import write_json_atomic
from metis.json_io import JsonArray
from metis.json_io import JsonJournal
from metis.json_io import JsonSnapshot
from metis.json_io import load_json_object_file
from metis.json_io import write_json_stream_atomic


@pytest.mark.parametrize("invalid", [float("nan"), float("inf"), -float("inf")])
def test_write_json_atomic_preserves_target_and_cleans_temporary_file(
    tmp_path: Path,
    invalid: float,
) -> None:
    target = tmp_path / "result.json"
    write_json_atomic(
        target,
        {"text": "£"},
        indent=2,
        ensure_ascii=False,
        allow_nan=False,
        mode=0o600,
    )

    expected = target.read_text(encoding="utf-8")
    assert expected == '{\n  "text": "£"\n}'
    assert stat.S_IMODE(target.stat().st_mode) == 0o600

    with pytest.raises(ValueError):
        write_json_atomic(target, {"nested": [{"value": invalid}]}, indent=2)

    assert target.read_text(encoding="utf-8") == expected
    assert list(tmp_path.iterdir()) == [target]


@pytest.mark.parametrize("format_name", ["json", "text", "stream"])
@pytest.mark.parametrize(
    "operation", ["fsync", "directory_chmod", "file_chmod", "replace"]
)
def test_output_io_failure_keeps_previous_complete_report(
    monkeypatch, tmp_path, operation, format_name
):
    from metis import json_io

    target = tmp_path / "result.json"
    target.write_text('{"previous": true}', encoding="utf-8")
    target.chmod(0o640)

    def fail(*_args, **_kwargs):
        raise OSError(f"failed {operation}")

    if operation.endswith("chmod"):
        chmod = Path.chmod

        def fail_chmod(path, mode):
            if path.is_dir() == (operation == "directory_chmod"):
                fail()
            chmod(path, mode)

        monkeypatch.setattr(Path, "chmod", fail_chmod)
    else:
        monkeypatch.setattr(json_io.os, operation, fail)
    with pytest.raises(OSError, match=f"failed {operation}"):
        if format_name == "json":
            write_json_atomic(target, {"replacement": True}, indent=2)
        elif format_name == "stream":
            write_json_stream_atomic(target, {"replacement": JsonArray(iter([True]))})
        else:
            with atomic_text_writer(target) as handle:
                handle.write("replacement")

    assert target.read_text() == '{"previous": true}'
    assert stat.S_IMODE(target.stat().st_mode) == 0o640
    assert list(tmp_path.iterdir()) == [target]


@pytest.mark.parametrize("umask", [0o022, 0o002, 0o777])
def test_atomic_text_writer_preserves_creation_and_existing_modes(tmp_path, umask):
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            dedent("""
                import os
                from pathlib import Path
                import stat
                import sys
                from metis.json_io import atomic_text_writer, write_json_atomic

                root = Path(sys.argv[1])
                mask = int(sys.argv[2])
                os.umask(mask)
                target = root / "report.txt"
                with atomic_text_writer(target) as handle:
                    handle.write("complete")
                    temporary = Path(handle.name)
                    assert temporary.parent.parent == root
                    assert stat.S_IMODE(temporary.parent.stat().st_mode) == 0o700
                    assert not target.exists()
                assert stat.S_IMODE(target.stat().st_mode) == 0o666 & ~mask
                assert list(root.iterdir()) == [target]
                target.chmod(0o640)
                with atomic_text_writer(target) as handle:
                    handle.write("replacement")
                assert target.read_text() == "replacement"
                assert stat.S_IMODE(target.stat().st_mode) == 0o640
                private = root / "report.json"
                write_json_atomic(private, {}, indent=2)
                assert stat.S_IMODE(private.stat().st_mode) == 0o600
                assert set(root.iterdir()) == {target, private}
            """),
            str(tmp_path),
            str(umask),
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_atomic_text_writer_supports_valid_long_basenames(tmp_path):
    target = tmp_path / ("r" * 240 + ".txt")
    target.write_text("previous", encoding="utf-8")

    with atomic_text_writer(target) as handle:
        handle.write("replacement")

    assert target.read_text() == "replacement"
    assert list(tmp_path.iterdir()) == [target]


def test_atomic_text_writer_resolves_parent_without_following_output_symlink(tmp_path):
    parent = tmp_path / "reports"
    (parent / "nested").mkdir(parents=True)
    alias = tmp_path / "alias"
    alias.symlink_to(parent / "nested", target_is_directory=True)
    protected = tmp_path / "protected.txt"
    protected.write_text("untouched", encoding="utf-8")
    target = parent / "report.txt"
    target.symlink_to(protected)

    with atomic_text_writer(alias / ".." / "report.txt") as handle:
        handle.write("replacement")

    assert target.read_text() == "replacement"
    assert not target.is_symlink()
    assert protected.read_text() == "untouched"
    assert set(parent.iterdir()) == {parent / "nested", target}


@pytest.mark.parametrize("ancestor", ["missing", "file"])
def test_atomic_text_writer_rejects_invalid_parent_components(tmp_path, ancestor):
    (tmp_path / "file").write_text("not a directory", encoding="utf-8")
    target = tmp_path / "report.json"
    target.write_text("previous", encoding="utf-8")
    with pytest.raises(OSError):
        write_json_atomic(tmp_path / ancestor / ".." / target.name, {}, indent=2)
    assert target.read_text() == "previous"


def test_atomic_text_writer_cleans_up_after_interruption(tmp_path):
    target = tmp_path / "report.txt"
    target.write_text("previous", encoding="utf-8")

    with pytest.raises(KeyboardInterrupt):
        with atomic_text_writer(target) as handle:
            handle.write("partial replacement")
            raise KeyboardInterrupt

    assert target.read_text() == "previous"
    assert list(tmp_path.iterdir()) == [target]


@pytest.mark.parametrize("failure", [False, True])
def test_queued_journal_flushes_producers_and_propagates_writer_failure(
    tmp_path, monkeypatch, failure
):
    target = tmp_path / "report.json"
    target.write_text('{"previous":true}')
    writing, release, blocked = Event(), Event(), Event()
    batch_counts = []
    monkeypatch.setattr(json_io, "_JSON_JOURNAL_BUFFER_BYTES", 128 * 1024)

    with pytest.raises(OSError, match="Writer failed") if failure else nullcontext():
        with TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            with JsonJournal(directory / "records.jsonl") as journal:
                journal.append({"id": 0})
                journal.flush()
                write = journal._output.write

                def blocked_write(data):
                    batch_counts.append(len(data.splitlines()))
                    if not writing.is_set():
                        writing.set()
                        assert release.wait(10)
                        if failure:
                            write(data[: len(data) // 2])
                            raise OSError("Writer failed")
                    return write(data)

                monkeypatch.setattr(journal._output, "write", blocked_write)
                journal.append({"id": 1})
                assert writing.wait(10)

                def produce(index):
                    record = {"id": index}
                    if index == 1002:
                        record["payload"] = "x" * json_io._JSON_JOURNAL_BUFFER_BYTES
                        blocked.set()
                    journal.append(record)
                    record["id"] = "modified after enqueue"

                with ThreadPoolExecutor(max_workers=8) as producers:
                    pending = [
                        producers.submit(produce, index) for index in range(2, 1002)
                    ]
                    try:
                        for future in pending:
                            future.result(10)
                        assert len(journal._queue) == 1000
                        assert (
                            journal._queued_bytes < json_io._JSON_JOURNAL_BUFFER_BYTES
                        )
                        pending.append(producers.submit(produce, 1002))
                        assert blocked.wait(10)
                        assert not pending[-1].done()
                    finally:
                        release.set()
                    with pytest.raises(OSError) if failure else nullcontext():
                        pending[-1].result(10)
                write_json_stream_atomic(
                    target,
                    {
                        "records": JsonArray(
                            JsonJournal.records(journal.path, limit=journal.flush())
                        )
                    },
                )
                journal.append({"id": 1003})
            assert sum(1 for _ in JsonJournal.records(journal.path)) == 1004
    assert not journal._writer.is_alive()
    if failure:
        assert target.read_text() == '{"previous":true}'
        assert not journal.path.exists()
    else:
        assert sorted(
            record["id"] for record in load_json_object_file(target)["records"]
        ) == list(range(1003))
        assert 1000 in batch_counts
        assert not directory.exists()


@pytest.mark.parametrize("failure", [None, "cycle", "unicode"])
def test_streaming_writer_preserves_readable_state(tmp_path, failure):
    target = tmp_path / "report.json"
    target.write_text('{"previous":true}')
    with pytest.raises(ValueError) if failure else nullcontext():
        payload = {"events": JsonArray([{"nested": JsonArray([1, None])}])}
        if failure == "cycle":
            payload["invalid"] = payload
        elif failure == "unicode":
            payload["invalid"] = "\ud800"
        write_json_stream_atomic(target, payload)
    assert load_json_object_file(target) == (
        {"previous": True} if failure else {"events": [{"nested": [1, None]}]}
    )
    assert not list(tmp_path.glob(".metis-*.tmp"))


@pytest.mark.parametrize("backend", ["native", "extreme"])
def test_snapshot_strict_validation_never_replaces_output(tmp_path, backend):
    source, target = tmp_path / "in", tmp_path / "out"
    target.write_text('{"previous":true}')
    metadata = {
        "native": '"number":0',
        "extreme": '"number":1e-9223372036854775807',
    }[backend]
    invalid_values = [
        '"duplicate":1,"duplicate":2',
        '"x":NaN',
        '"x":1e309',
        '"x":-1e309',
        r'"\ud800":0',
        r'"x":"\ud800"',
        '"x":"\\udfff"',
        '"x":"\ud800"',
        '"x":"\x01"',
        '"x":+1',
        '"x":-.9',
        '"x":1.e2',
    ]
    documents = ["{" + metadata + "," + invalid + "}" for invalid in invalid_values]
    prefix = "{" + metadata + ',"padding":"'
    documents.extend(
        prefix + "x" * (1024 * 1024 - offset - len(prefix)) + r'\ud800"}'
        for offset in range(1, 12)
    )
    for whitespace in ("\x0b", "\x0c", "\x1f", "\u0085", "\u00a0", "\u2028", "\u3000"):
        document = "{" + metadata + ',"x":[]}'
        documents.extend(
            (
                whitespace + document,
                document.replace("[]", whitespace + "[]"),
                document + " " * (1024 * 1024) + whitespace,
            )
        )
    for document in documents:
        source.write_bytes(document.encode("utf-8", errors="surrogatepass"))
        with pytest.raises(ValueError):
            load_json_object_file(source)
        with pytest.raises(ValueError):
            with JsonSnapshot(source) as snapshot:
                snapshot.write(target)
        assert target.read_text() == '{"previous":true}'


@pytest.mark.parametrize("trap_invalid", [False, True])
def test_snapshot_preserves_valid_numbers_unicode_and_failed_transforms(
    tmp_path, trap_invalid
):
    source, target = tmp_path / "in", tmp_path / "out"
    limit = sys.get_int_max_str_digits() or 4300
    digits = "1" * (limit + 1)
    values = [
        "1e-9223372036854775807",
        "-0e+9223372036854775807",
        str(2**100),
        digits[:-1],
        "-1" + "0" * limit + "e-" + str(limit),
        "0." + "0" * limit + "1",
        '"\\"' + digits + '\\""',
        r'"\ud83d\udd0d"',
        r'"\\ud800"',
    ]
    prefix = '{"padding":"' + "x" * (1024 * 1024 - 40) + '","value":'
    documents = [prefix + value + "}" for value in values]
    prefix = '{"number":1e-9223372036854775807,"value":"'
    documents.extend(
        prefix
        + "x" * (1024 * 1024 - 1 - len(prefix))
        + escape
        + '\u00a0\u2028\\u000b\\u000c"}'
        for escape in ('\\"', "\\\\")
    )
    with localcontext() as context:
        context.traps[InvalidOperation] = trap_invalid
        for document in documents:
            source.write_text(document, encoding="utf-8")
            expected = load_json_object_file(source)
            with JsonSnapshot(source) as snapshot:
                assert list(snapshot.items(("value",))) == [
                    (("value",), expected["value"])
                ]
                snapshot.write(target)
                assert target.read_bytes() == source.read_bytes()
                with pytest.raises(ValueError):
                    snapshot.write(
                        target,
                        at=("value",),
                        transform=lambda _path, value: float("nan"),
                    )
                assert target.read_bytes() == source.read_bytes()
                snapshot.write(
                    target, at=("value",), transform=lambda _path, value: value
                )
            assert load_json_object_file(target) == expected


def test_snapshot_uses_available_ijson_backend(tmp_path, monkeypatch):
    monkeypatch.setenv("IJSON_BACKEND", "python")
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            "import ijson, pytest, sys; assert ijson.backend_name == 'python'; "
            "raise SystemExit(pytest.main(sys.argv[1:]))",
            __file__,
            "-q",
            "-k",
            "snapshot_strict_validation or snapshot_preserves_valid_numbers",
            "--basetemp",
            str(tmp_path / "python-backend"),
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


@pytest.mark.parametrize("digit_limit", [640, 4300, 0])
def test_oversized_integer_rejection_is_fast_and_does_not_crash(tmp_path, digit_limit):
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            dedent("""
            import sys
            import traceback
            from pathlib import Path
            from metis.json_io import JsonSnapshot
            from metis.json_io import load_json_object_file
            if sys.platform != "win32":
                import resource
                resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            limit = int(sys.argv[2])
            sys.set_int_max_str_digits(limit)
            source = Path(sys.argv[1]) / "in"
            number = "-1" + "0" * (4_000_000 if limit else 4300)
            source.write_text('{"number":' + number + ',"underflow":1e-9223372036854775807}')
            if limit:
                for read in (load_json_object_file, JsonSnapshot):
                    try:
                        read(source)
                    except ValueError as error:
                        assert len(str(error)) < 256
                        assert len("".join(traceback.format_exception(error))) < 4000
                    else:
                        raise AssertionError("Oversized integer accepted")
            else:
                with JsonSnapshot(source) as snapshot:
                    assert list(snapshot.items(())) == [((), load_json_object_file(source))]
        """),
            str(tmp_path),
            str(digit_limit),
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_large_fallback_snapshot_is_bounded(tmp_path):
    source = tmp_path / "in"
    record = '{"value":"' + "x" * 1011 + '"}'
    with source.open("w", newline="") as output:
        output.write('{\r\n"number":1e-9223372036854775807,"events":[\n')
        for index in range(20_000):
            output.write((",\r\n" if index else "") + record)
        output.write("\r]}\r\n")
    expected_size = source.stat().st_size
    with source.open("rb") as original:
        expected_digest = hashlib.file_digest(original, "sha256").hexdigest()
    tracemalloc.start()
    try:
        with JsonSnapshot(source) as snapshot:
            assert stat.S_IMODE(snapshot.directory.stat().st_mode) == 0o700
            assert [path.name for path in snapshot.directory.iterdir()] == [
                "snapshot.json"
            ]
            for count, (position, value) in enumerate(
                snapshot.items(("events", None)), 1
            ):
                assert position == ("events", count - 1) and value == {
                    "value": "x" * 1011
                }
            assert count == 20_000
            source.write_text("changed after snapshot")
            snapshot.write(source)
        assert tracemalloc.get_traced_memory()[1] < expected_size
    finally:
        tracemalloc.stop()
    with source.open("rb") as saved:
        assert hashlib.file_digest(saved, "sha256").hexdigest() == expected_digest
