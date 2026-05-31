# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from contextlib import nullcontext
import sys
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


def test_run_non_interactive_keeps_quiet_without_verbose():
    args = SimpleNamespace(
        command="triage data.sarif",
        verbose=False,
        quiet=True,
        log_level="DEBUG",
    )

    exit_code, farewell = entry.run_non_interactive(SimpleNamespace(), args)

    assert exit_code == 1
    assert farewell is None
    assert args.quiet is True


def test_main_version_does_not_require_runtime_config(monkeypatch, capsys):
    def fail_load_runtime_config(*_args, **_kwargs):
        raise AssertionError("runtime config should not be loaded for --version")

    monkeypatch.setattr(sys, "argv", ["metis", "--version"])
    monkeypatch.setattr(entry, "load_runtime_config", fail_load_runtime_config)

    entry.main()

    assert "Metis" in capsys.readouterr().out


def test_should_defer_embed_models_for_interactive_sessions():
    args = SimpleNamespace(
        non_interactive=False,
        command="",
        ignore_index=False,
        triage=False,
    )

    assert entry._should_defer_embed_models(args) is True  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("review_file src/a.c --ignore-index", True),
        ("review_code --ignore-index", True),
        ("triage findings.sarif --ignore-index", True),
        ("ask explain the project", False),
        ("index", False),
        ("ask explain --ignore-index", True),
        ("", True),
        ("unknown thing", True),
    ],
)
def test_should_defer_embed_models_for_noninteractive_commands(command, expected):
    args = SimpleNamespace(
        non_interactive=True,
        command=command,
        ignore_index=False,
        triage=False,
    )

    assert entry._should_defer_embed_models(args) is expected  # type: ignore[attr-defined]


def test_build_engine_skips_embedding_construction_for_no_index_scan(
    monkeypatch, tmp_path
):
    class ProviderWithoutEmbeddings:
        def __init__(self, _runtime):
            pass

        def get_embed_model_code(self, **_kwargs):
            raise AssertionError("code embeddings should be deferred")

        def get_embed_model_docs(self, **_kwargs):
            raise AssertionError("docs embeddings should be deferred")

    captured = {}

    def build_backend(_args, _runtime, embed_model_code, embed_model_docs):
        captured["backend_embed_model_code"] = embed_model_code
        captured["backend_embed_model_docs"] = embed_model_docs
        return SimpleNamespace(embed_model_code=None, embed_model_docs=None)

    class DummyEngine:
        def __init__(self, **kwargs):
            captured["engine_kwargs"] = kwargs

    args = SimpleNamespace(
        backend="chroma",
        chroma_dir=str(tmp_path / "chromadb"),
        codebase_path=str(tmp_path),
        custom_prompt=None,
        non_interactive=True,
        command="review_file src/a.c --ignore-index",
        ignore_index=False,
        triage=False,
    )
    runtime = {
        "llm_provider_name": "anthropic",
        "max_workers": 2,
        "max_token_length": 2048,
        "llama_query_model": "claude-opus-4-1-20250805",
        "similarity_top_k": 3,
        "response_mode": "compact",
    }

    monkeypatch.setattr(entry, "get_provider", lambda _name: ProviderWithoutEmbeddings)
    monkeypatch.setattr(entry, "build_chroma_backend", build_backend)
    monkeypatch.setattr(entry, "MetisEngine", DummyEngine)

    _engine, _backend = entry.build_engine(args, runtime)

    assert captured["backend_embed_model_code"] is None
    assert captured["backend_embed_model_docs"] is None
    assert captured["engine_kwargs"]["defer_embed_models"] is True
