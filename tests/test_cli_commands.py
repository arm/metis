# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from metis.cli import commands
from metis.cli.command_runtime import CommandRuntime


@pytest.mark.parametrize(
    ("command", "mode", "filename"),
    [
        ("review_code", "code", None),
        ("review_patch", "patch", "change.diff"),
        ("review_file", "file", "a.c"),
    ],
)
def test_review_commands_route_through_graph(
    monkeypatch,
    tmp_path,
    command,
    mode,
    filename,
):
    calls = []

    class _Engine:
        def execute_review(self, mode, **kwargs):
            calls.append((mode, kwargs))
            return {
                "formats": ("sarif", "json", "html", "csv"),
                "findings": {"reviews": []},
                "sarif": {"version": "2.1.0", "runs": []},
            }

    args = SimpleNamespace(
        verbose=True,
        quiet=True,
        triage=False,
        output_file=None,
    )
    monkeypatch.setattr(
        commands,
        "with_spinner",
        lambda _message, func, *func_args, **func_kwargs: func(
            *func_args,
            **{k: v for k, v in func_kwargs.items() if k != "quiet"},
        ),
    )
    monkeypatch.setattr(
        commands, "_finalize_review_output", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(commands, "print_console", lambda *_args, **_kwargs: None)

    target = None
    if filename is not None:
        target_path = tmp_path / filename
        target_path.write_text("review input", encoding="utf-8")
        target = str(target_path)
    runtime = CommandRuntime(command=command, command_args=[target] if target else [])

    if command == "review_code":
        commands.run_review_code(_Engine(), args, runtime)
    elif command == "review_patch":
        commands.run_review(_Engine(), target, args, runtime)
    else:
        commands.run_file_review(_Engine(), target, args, runtime)

    assert calls[0][0] == mode
    assert calls[0][1]["target"] == target
    assert callable(calls[0][1]["callbacks"]["diagnostic_callback"])
    assert {path.rsplit(".", 1)[-1] for path in args.output_file} == {
        "sarif",
        "json",
        "html",
        "csv",
    }


def test_run_update_uses_indexing_domain_surface(monkeypatch, tmp_path):
    patch_file = tmp_path / "change.diff"
    patch_file.write_text("diff --git a/a.py b/a.py", encoding="utf-8")

    captured: list[str] = []

    class _IndexingDomain:
        def update_index(self, patch_text):
            captured.append(patch_text)

    engine = SimpleNamespace(indexing=_IndexingDomain())
    args = SimpleNamespace(quiet=True)

    monkeypatch.setattr(commands, "print_console", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        commands,
        "with_spinner",
        lambda _message, func, *func_args, **_func_kwargs: func(*func_args),
    )

    commands.run_update(
        engine,
        str(patch_file),
        args,
        CommandRuntime(
            command="update",
            command_args=[str(patch_file)],
        ),
    )

    assert captured == ["diff --git a/a.py b/a.py"]


def test_run_index_verbose_uses_indexing_domain_surface(monkeypatch):
    calls: list[str] = []

    class _IndexingDomain:
        def count_index_items(self):
            calls.append("count")
            return 2

        def index_prepare_nodes_iter(self):
            calls.append("prepare")
            yield None
            yield None

        def index_finalize_embeddings(self):
            calls.append("finalize")

    engine = SimpleNamespace(indexing=_IndexingDomain())

    monkeypatch.setattr(commands, "print_console", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        commands, "iterate_with_progress", lambda _total, iterable: list(iterable)
    )
    monkeypatch.setattr(
        commands, "with_timer", lambda _message, func, **_kwargs: func()
    )

    commands.run_index(engine, verbose=True, quiet=True)

    assert calls == ["count", "prepare", "finalize"]


def test_run_review_code_triggers_triage_when_global_flag_enabled(monkeypatch):
    calls = []
    codegraph = object()

    class _Engine:
        def execute_review(self, mode, **kwargs):
            calls.append((mode, kwargs))
            return {
                "formats": ("sarif", "json", "html", "csv"),
                "findings": {"reviews": []},
                "sarif": {"version": "2.1.0", "runs": []},
                "codegraph": codegraph,
            }

        def execute_triage(self, payload, **kwargs):
            calls.append(
                (
                    "triage",
                    kwargs["options"],
                    kwargs["codegraph"],
                )
            )
            return {"formats": ("sarif",), "sarif": payload}

    engine = _Engine()
    args = SimpleNamespace(
        verbose=False,
        quiet=True,
        triage=True,
        include_triaged=False,
        output_file=None,
    )
    runtime = CommandRuntime(
        command="review_code",
        command_args=[],
    )

    monkeypatch.setattr(commands, "print_console", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        commands,
        "with_spinner",
        lambda _message, func, *func_args, **func_kwargs: func(
            *func_args,
            **{k: v for k, v in func_kwargs.items() if k != "quiet"},
        ),
    )
    monkeypatch.setattr(
        commands, "pretty_print_reviews", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(commands, "save_output", lambda *_args, **_kwargs: None)

    commands.run_review_code(engine, args, runtime)

    assert calls[0][0] == "code"
    assert calls[0][1]["target"] is None
    assert callable(calls[0][1]["callbacks"]["diagnostic_callback"])
    assert calls[1] == ("triage", None, codegraph)


def test_review_command_honors_explicit_format_in_addition_to_graph_formats(
    monkeypatch,
):
    class _Engine:
        def execute_review(self, _mode, **_kwargs):
            return {
                "formats": ("sarif",),
                "findings": {"reviews": []},
                "sarif": {"version": "2.1.0", "runs": []},
            }

    args = SimpleNamespace(
        quiet=True,
        triage=False,
        output_file=["report.json"],
    )
    saved: list[str] = []

    def capture_output(_results, final_args, **_kwargs):
        saved.extend(final_args.output_file)

    monkeypatch.setattr(commands, "_finalize_review_output", capture_output)

    commands.run_review_code(
        _Engine(),
        args,
        CommandRuntime(command="review_code", command_args=[]),
    )

    assert {Path(path).suffix for path in saved} == {".json", ".sarif"}


def test_run_review_code_preserves_review_output_when_triage_fails(monkeypatch):
    saved = []

    class _Engine:
        def execute_review(self, _mode, **_kwargs):
            return {
                "formats": ("sarif", "json", "html", "csv"),
                "findings": {"reviews": []},
                "sarif": {"version": "2.1.0", "runs": [{"results": []}]},
            }

        def execute_triage(self, _payload, **_kwargs):
            raise RuntimeError("provider unavailable")

    args = SimpleNamespace(
        verbose=False,
        quiet=True,
        triage=True,
        include_triaged=False,
        output_file=None,
    )
    runtime = CommandRuntime(command="review_code", command_args=[])
    monkeypatch.setattr(
        commands,
        "with_spinner",
        lambda _message, func, *func_args, **func_kwargs: func(
            *func_args,
            **{k: v for k, v in func_kwargs.items() if k != "quiet"},
        ),
    )
    monkeypatch.setattr(commands, "print_console", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(commands, "pretty_print_reviews", lambda *_args: None)
    monkeypatch.setattr(
        commands,
        "save_output",
        lambda *_args, **kwargs: saved.append(kwargs["sarif_payload"]),
    )

    commands.run_review_code(_Engine(), args, runtime)

    assert saved == [{"version": "2.1.0", "runs": [{"results": []}]}]
