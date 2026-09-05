# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import stat
import subprocess
import sys
from textwrap import dedent
from pathlib import Path

import pytest

from metis.json_io import atomic_text_writer
from metis.json_io import write_json_atomic


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


@pytest.mark.parametrize("format_name", ["json", "text"])
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


def test_atomic_text_writer_cleans_up_after_interruption(tmp_path):
    target = tmp_path / "report.txt"
    target.write_text("previous", encoding="utf-8")

    with pytest.raises(KeyboardInterrupt):
        with atomic_text_writer(target) as handle:
            handle.write("partial replacement")
            raise KeyboardInterrupt

    assert target.read_text() == "previous"
    assert list(tmp_path.iterdir()) == [target]
