# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from contextlib import nullcontext
from types import SimpleNamespace

import pytest

from metis.cli import entry
from metis.cli import command_registry


@pytest.mark.parametrize(
    "cmd", ["review_file", "review_code", "review_patch", "triage"]
)
def test_prepare_command_runtime_allows_opt_in_no_index_for_supported_command(cmd):
    args = SimpleNamespace(ignore_index=False, quiet=True, codebase_path="src/metis")

    runtime = entry._prepare_command_runtime(  # type: ignore[attr-defined]
        cmd=cmd,
        cmd_args=["src/a.c", "--ignore-index"],
        args=args,
    )

    assert runtime is not None
    assert runtime.command_args == ["src/a.c"]
    assert runtime.use_retrieval_context is False


@pytest.mark.parametrize("cmd", ["ask", "update"])
def test_prepare_command_runtime_rejects_disallowed_inline_ignore_index(
    monkeypatch, cmd
):
    args = SimpleNamespace(ignore_index=False, quiet=True, codebase_path="src/metis")
    captured = []
    monkeypatch.setattr(
        command_registry,
        "print_console",
        lambda message, *_args, **_kwargs: captured.append(message),
    )

    runtime = entry._prepare_command_runtime(  # type: ignore[attr-defined]
        cmd=cmd,
        cmd_args=["why", "--ignore-index"],
        args=args,
    )

    assert runtime is None
    assert any(
        "--ignore-index can only be used" in str(message) for message in captured
    )


def test_execute_command_rejects_triage_flag_for_ask_before_index_gating(monkeypatch):
    args = SimpleNamespace(
        quiet=True,
        triage=True,
        output_file=None,
        ignore_index=True,
        non_interactive=True,
        codebase_path="src/metis",
    )
    captured = []
    monkeypatch.setattr(
        command_registry,
        "print_console",
        lambda message, *_args, **_kwargs: captured.append(str(message)),
    )

    result = entry.execute_command(
        SimpleNamespace(),
        "ask",
        ["hi"],
        args,
    )

    assert result is None
    assert any("--triage can only be used" in message for message in captured)
    assert not any("Index missing" in message for message in captured)


def test_execute_command_allows_interactive_triage_command_with_global_triage_flag(
    monkeypatch,
):
    args = SimpleNamespace(
        quiet=True,
        triage=True,
        output_file=None,
        ignore_index=False,
        non_interactive=False,
        codebase_path="src/metis",
        include_triaged=False,
    )
    calls = []
    engine = SimpleNamespace(
        usage_command=lambda *_args, **_kwargs: nullcontext("command"),
        finalize_usage_command=lambda _command: {
            "display_name": "triage",
            "summary": {},
            "cumulative": {},
        },
    )
    monkeypatch.setattr(entry, "determine_output_file", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(entry, "print_console", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(entry, "print_usage_summary", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        command_registry.CommandSpec,
        "invoke",
        lambda self, engine, cmd_args, args, runtime: calls.append(
            (runtime.command, cmd_args, runtime.use_retrieval_context)
        ),
    )

    result = entry.execute_command(engine, "triage", ["findings.sarif"], args)

    assert result is None
    assert calls == [("triage", ["findings.sarif"], True)]


def test_execute_command_allows_interactive_ask_with_global_triage_flag(monkeypatch):
    args = SimpleNamespace(
        quiet=True,
        triage=True,
        output_file=None,
        ignore_index=False,
        non_interactive=False,
        codebase_path="src/metis",
    )
    calls = []
    engine = SimpleNamespace(
        usage_command=lambda *_args, **_kwargs: nullcontext("command"),
        finalize_usage_command=lambda _command: {
            "display_name": "ask",
            "summary": {},
            "cumulative": {},
        },
    )

    monkeypatch.setattr(entry, "determine_output_file", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(entry, "print_console", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(entry, "print_usage_summary", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        command_registry.CommandSpec,
        "invoke",
        lambda self, engine, cmd_args, args, runtime: calls.append(
            (runtime.command, cmd_args, runtime.use_retrieval_context)
        ),
    )

    result = entry.execute_command(engine, "ask", ["hi"], args)

    assert result is None
    assert calls == [("ask", ["hi"], True)]


@pytest.mark.parametrize("cmd", ["ask", "update"])
def test_execute_command_rejects_ignore_index_flag_before_index_gating(
    monkeypatch, cmd
):
    args = SimpleNamespace(
        quiet=True,
        triage=False,
        output_file=None,
        ignore_index=True,
        codebase_path="src/metis",
    )
    captured = []
    monkeypatch.setattr(
        command_registry,
        "print_console",
        lambda message, *_args, **_kwargs: captured.append(str(message)),
    )

    result = entry.execute_command(
        SimpleNamespace(),
        cmd,
        ["hi"],
        args,
    )

    assert result is None
    assert any("--ignore-index can only be used" in message for message in captured)
    assert not any("Index missing" in message for message in captured)


@pytest.mark.parametrize("cmd", ["ask", "update"])
def test_execute_command_rejects_inline_ignore_index_flag_before_index_gating(
    monkeypatch, cmd
):
    args = SimpleNamespace(
        quiet=True,
        triage=False,
        output_file=None,
        ignore_index=False,
        codebase_path="src/metis",
    )
    captured = []
    monkeypatch.setattr(
        command_registry,
        "print_console",
        lambda message, *_args, **_kwargs: captured.append(str(message)),
    )

    result = entry.execute_command(
        SimpleNamespace(),
        cmd,
        ["hi", "--ignore-index"],
        args,
    )

    assert result is None
    assert any("--ignore-index can only be used" in message for message in captured)
    assert not any("Index missing" in message for message in captured)
