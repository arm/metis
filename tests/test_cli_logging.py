# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""CLI logging configuration must fail before work and preserve usable handlers."""

import logging
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import warnings

import pytest

from metis.cli import entry
from metis.cli.utils import configure_logger
from metis.runlog import current_runlog


@pytest.fixture
def cli_logger(monkeypatch):
    logger = logging.Logger("cli-logging-test")
    monkeypatch.setattr(entry, "logger", logger)
    monkeypatch.setattr(logging, "captureWarnings", lambda _capture: None)
    for name in (
        "",
        "py.warnings",
        "httpx",
        "httpcore",
        "openai",
        "openai._base_client",
        "azure",
        "urllib3",
    ):
        affected = logging.getLogger(name)
        monkeypatch.setattr(affected, "level", affected.level)
        monkeypatch.setattr(affected, "propagate", affected.propagate)
    with warnings.catch_warnings():
        try:
            yield logger
        finally:
            for handler in logger.handlers[:]:
                logger.removeHandler(handler)
                handler.close()


@pytest.mark.parametrize(
    "arguments, message",
    [
        (["--log-level", "DEBIG"], "invalid choice"),
        (["--log-level", "20"], "invalid choice"),
        (["--log-level", ""], "invalid choice"),
        (["--log-level", " debug "], "invalid choice"),
        (
            ["--tools", "none"],
            "configure execution nodes and capability grants in YAML",
        ),
        (["--interactive", "--tools", "navigation,index"], "--tools has been removed"),
    ],
)
def test_invalid_cli_configuration_fails_before_resources(
    arguments, message, monkeypatch, capsys
):
    monkeypatch.setattr("sys.argv", ["metis", *arguments])
    monkeypatch.setattr(
        entry, "configure_logger", lambda *_args: pytest.fail("logging was configured")
    )
    monkeypatch.setattr(
        entry,
        "load_runtime_config",
        lambda **_kwargs: pytest.fail("runtime was loaded"),
    )
    with pytest.raises(SystemExit) as exc:
        entry.main()
    assert exc.value.code == 2
    assert message in capsys.readouterr().err


@pytest.mark.parametrize(
    "level, expected",
    [("debug", logging.DEBUG), ("warn", logging.WARNING), ("NOTSET", logging.NOTSET)],
)
def test_cli_normalizes_valid_logging_levels(level, expected, monkeypatch, cli_logger):
    monkeypatch.setattr("sys.argv", ["metis", "--log-level", level])

    def stop_after_logging(**_kwargs):
        assert cli_logger.level == expected
        raise OSError("inert stop before engine construction")

    monkeypatch.setattr(entry, "load_runtime_config", stop_after_logging)
    with pytest.raises(SystemExit) as exc:
        entry.main()
    assert exc.value.code == 1


def test_logger_replacement_is_transactional_and_closes_old_files(cli_logger, tmp_path):
    old_path = tmp_path / "old.log"
    configure_logger(cli_logger, SimpleNamespace(log_level="ERROR", log_file=old_path))
    old_handlers = cli_logger.handlers[:]
    old_stream = old_handlers[-1].stream

    with pytest.raises(IsADirectoryError):
        configure_logger(
            cli_logger, SimpleNamespace(log_level="DEBUG", log_file=tmp_path)
        )
    assert cli_logger.handlers == old_handlers
    assert cli_logger.level == logging.ERROR
    cli_logger.error("kept old destination")
    assert "kept old destination" in old_path.read_text()

    new_path = tmp_path / "new.log"
    configure_logger(cli_logger, SimpleNamespace(log_level="info", log_file=new_path))
    assert old_stream.closed
    assert old_handlers[-1].stream is None
    cli_logger.info("one new record")
    assert new_path.read_text().count("one new record") == 1
    assert "one new record" not in old_path.read_text()


def test_invalid_direct_logger_level_preserves_configuration(cli_logger, tmp_path):
    configure_logger(cli_logger, SimpleNamespace(log_level="ERROR", log_file=None))
    handlers = cli_logger.handlers[:]
    new_path = tmp_path / "must-not-exist.log"
    with pytest.raises(ValueError, match="level"):
        configure_logger(
            cli_logger, SimpleNamespace(log_level="DEBIG", log_file=new_path)
        )
    assert cli_logger.handlers == handlers
    assert not new_path.exists()


@pytest.mark.parametrize("destination", ["log-file-directory", "existing-trace"])
def test_logging_destination_error_is_reported_before_runtime(
    destination, cli_logger, tmp_path, monkeypatch, capsys
):
    trace = tmp_path / "prior.ndjson"
    trace.write_text("previous run")
    arguments = (
        ["--log-file", str(tmp_path)]
        if destination == "log-file-directory"
        else ["--log-workflow-debug-path", str(trace)]
    )
    monkeypatch.setattr("sys.argv", ["metis", *arguments])
    monkeypatch.setattr(
        entry,
        "load_runtime_config",
        lambda **_kwargs: pytest.fail("runtime was loaded"),
    )
    with pytest.raises(SystemExit) as exc:
        entry.main()
    assert exc.value.code == 1
    output = capsys.readouterr()
    assert "Error:" in output.out
    assert "Traceback" not in output.out + output.err
    assert trace.read_text() == "previous run"
    assert current_runlog() is None


@pytest.mark.parametrize(
    "option, value, exit_code",
    [
        ("--log-level", "DEBIG", 2),
        ("--tools", "none", 2),
        ("--log-file", ".", 1),
        ("--log-workflow-debug-path", "prior.ndjson", 1),
    ],
)
def test_cli_process_rejects_invalid_logging_or_legacy_flags(
    option, value, exit_code, tmp_path
):
    trace = tmp_path / "prior.ndjson"
    trace.write_text("previous run")
    completed = subprocess.run(
        [sys.executable, "-m", "metis", option, value],
        cwd=tmp_path,
        env={"PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")},
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert completed.returncode == exit_code
    output = completed.stdout + completed.stderr
    assert "error:" in output.lower()
    assert "Traceback" not in output
    assert trace.read_text() == "previous run"
    assert sorted(path.name for path in tmp_path.iterdir()) == ["prior.ndjson"]
