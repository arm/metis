# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from types import SimpleNamespace

from metis.cli import commands


def test_run_review_code_uses_review_domain_surface(monkeypatch):
    calls: list[str] = []

    class _ReviewDomain:
        def get_code_files(self):
            calls.append("get_code_files")
            return ["a.py"]

        def review_code(self):
            calls.append("review_code")
            yield {"file": "a.py", "reviews": []}

    engine = SimpleNamespace(review=_ReviewDomain())
    args = SimpleNamespace(verbose=True, quiet=True, triage=False, output_file=None)

    monkeypatch.setattr(commands, "print_console", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        commands, "iterate_with_progress", lambda _total, iterable: list(iterable)
    )
    monkeypatch.setattr(
        commands, "_finalize_review_output", lambda *_args, **_kwargs: None
    )

    commands.run_review_code(engine, args)

    assert calls == ["get_code_files", "review_code"]


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

    commands.run_update(engine, str(patch_file), args)

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
