# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from contextlib import nullcontext
import sys
from types import SimpleNamespace

import pytest

from metis.cli import entry
from metis.cli import command_registry


def test_configure_enabled_tools_defaults_to_navigation_when_unset():
    args = SimpleNamespace(tools=None)
    configure_enabled_tools = getattr(entry, "_configure_enabled_tools")

    configure_enabled_tools(args, {})

    assert args.enabled_tools == {"navigation"}


def test_configure_enabled_tools_uses_config_when_cli_absent():
    args = SimpleNamespace(tools=None)

    entry._configure_enabled_tools(  # type: ignore[attr-defined]
        args, {"enabled_tools": "index"}
    )

    assert args.enabled_tools == {"index"}


def test_configure_enabled_tools_prefers_cli_over_config():
    args = SimpleNamespace(tools="none")

    entry._configure_enabled_tools(  # type: ignore[attr-defined]
        args, {"enabled_tools": "index"}
    )

    assert args.enabled_tools == set()


@pytest.mark.parametrize(
    "cmd", ["review_file", "review_code", "review_patch", "triage"]
)
def test_prepare_command_runtime_disables_index_by_default_for_supported_command(cmd):
    args = SimpleNamespace(ignore_index=False, quiet=True)

    runtime = entry._prepare_command_runtime(  # type: ignore[attr-defined]
        cmd=cmd,
        cmd_args=["src/a.c"],
        args=args,
    )

    assert runtime is not None
    assert runtime.command_args == ["src/a.c"]


@pytest.mark.parametrize("cmd", ["ask", "update", "index"])
def test_prepare_command_runtime_rejects_required_index_by_default(monkeypatch, cmd):
    args = SimpleNamespace(
        ignore_index=False,
        quiet=True,
        codebase_path="src/metis",
    )
    captured = []
    monkeypatch.setattr(
        entry,
        "print_console",
        lambda message, *_args, **_kwargs: captured.append(str(message)),
    )

    runtime = entry._prepare_command_runtime(  # type: ignore[attr-defined]
        cmd=cmd,
        cmd_args=["why"],
        args=args,
    )

    assert runtime is None
    assert any("requires tool 'index'" in message for message in captured)


@pytest.mark.parametrize("cmd", ["ask", "update", "index"])
def test_prepare_command_runtime_rejects_required_index_when_tool_disabled(
    monkeypatch, cmd
):
    args = SimpleNamespace(
        enabled_tools=set(),
        ignore_index=False,
        quiet=True,
        codebase_path="src/metis",
    )
    captured = []
    monkeypatch.setattr(
        entry,
        "print_console",
        lambda message, *_args, **_kwargs: captured.append(str(message)),
    )

    runtime = entry._prepare_command_runtime(  # type: ignore[attr-defined]
        cmd=cmd,
        cmd_args=["why"],
        args=args,
    )

    assert runtime is None
    assert any("requires tool 'index'" in message for message in captured)


@pytest.mark.parametrize(
    "cmd",
    ["review_file", "review_code", "review_patch", "triage", "ask", "update", "index"],
)
def test_prepare_command_runtime_accepts_inline_ignore_index_as_noop(cmd):
    args = SimpleNamespace(
        enabled_tools={"index"},
        ignore_index=False,
        quiet=True,
    )

    runtime = entry._prepare_command_runtime(  # type: ignore[attr-defined]
        cmd=cmd,
        cmd_args=["target", "--ignore-index"],
        args=args,
    )

    assert runtime is not None
    assert runtime.command_args == ["target"]


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
            (runtime.command, cmd_args)
        ),
    )

    result = entry.execute_command(engine, "triage", ["findings.sarif"], args)

    assert result is None
    assert calls == [("triage", ["findings.sarif"])]


def test_execute_command_allows_interactive_ask_with_global_triage_flag(monkeypatch):
    args = SimpleNamespace(
        enabled_tools={"index"},
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
            (runtime.command, cmd_args)
        ),
    )

    result = entry.execute_command(engine, "ask", ["hi"], args)

    assert result is None
    assert calls == [("ask", ["hi"])]


@pytest.mark.parametrize(
    ("cmd", "cmd_args"),
    [("ask", ["hi"]), ("update", ["hi"])],
)
def test_execute_command_accepts_global_ignore_index_as_noop(
    monkeypatch, cmd, cmd_args
):
    args = SimpleNamespace(
        enabled_tools={"index"},
        quiet=True,
        triage=False,
        output_file=None,
        ignore_index=True,
        codebase_path="src/metis",
    )
    calls = []
    engine = SimpleNamespace(
        usage_command=lambda *_args, **_kwargs: nullcontext("command"),
        finalize_usage_command=lambda _command: {
            "display_name": cmd,
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
            (runtime.command, cmd_args)
        ),
    )

    result = entry.execute_command(engine, cmd, cmd_args, args)

    assert result is None
    assert calls == [(cmd, ["hi"])]


@pytest.mark.parametrize("cmd", ["ask", "update"])
def test_execute_command_accepts_inline_ignore_index_as_noop(monkeypatch, cmd):
    args = SimpleNamespace(
        enabled_tools={"index"},
        quiet=True,
        triage=False,
        output_file=None,
        ignore_index=False,
        codebase_path="src/metis",
    )
    calls = []
    engine = SimpleNamespace(
        usage_command=lambda *_args, **_kwargs: nullcontext("command"),
        finalize_usage_command=lambda _command: {
            "display_name": cmd,
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
            (runtime.command, cmd_args)
        ),
    )

    result = entry.execute_command(engine, cmd, ["hi", "--ignore-index"], args)

    assert result is None
    assert calls == [(cmd, ["hi"])]


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


def test_main_passes_config_path_to_runtime_loader(monkeypatch, tmp_path):
    config_path = tmp_path / "variant.yaml"
    config_path.write_text("llm_provider: {}\n", encoding="utf-8")
    captured = {}

    def fake_load_runtime_config(*, config_path=None, enable_psql=False):
        captured["config_path"] = config_path
        captured["enable_psql"] = enable_psql
        return {}

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "metis",
            "--config",
            str(config_path),
            "--non-interactive",
            "--command",
            "review_code",
        ],
    )
    monkeypatch.setattr(entry, "load_runtime_config", fake_load_runtime_config)
    monkeypatch.setattr(entry, "build_engine", lambda _args, _runtime: (None, None))
    monkeypatch.setattr(entry, "run_non_interactive", lambda _engine, _args: (0, None))
    monkeypatch.setattr(entry, "finalize_cli_session_and_close", lambda *_args: None)

    entry.main()

    assert captured == {"config_path": str(config_path), "enable_psql": False}


def test_build_engine_defers_embedding_model_construction(monkeypatch, tmp_path):
    class ChatProvider:
        def __init__(self, _runtime):
            pass

    class EmbeddingProvider:
        def __init__(self, _runtime):
            pass

        def get_embed_model_code(self, **_kwargs):
            raise AssertionError("code embeddings should be lazy")

        def get_embed_model_docs(self, **_kwargs):
            raise AssertionError("docs embeddings should be lazy")

    captured = {}

    def build_backend(_args, _runtime, embed_model_code, embed_model_docs):
        captured["embed_model_code"] = embed_model_code
        captured["embed_model_docs"] = embed_model_docs
        return SimpleNamespace(embed_model_code=None, embed_model_docs=None)

    class DummyEngine:
        def __init__(self, **kwargs):
            captured["engine_kwargs"] = kwargs

    args = SimpleNamespace(
        backend="chroma",
        chroma_dir=str(tmp_path / "chromadb"),
        codebase_path=str(tmp_path),
        custom_prompt=None,
        enabled_tools={"index"},
    )
    runtime = {
        "llm_provider_name": "anthropic",
        "llm_provider": {
            "api_key": "anthropic-key",
            "model": "claude-opus-4-1-20250805",
        },
        "embedding_provider_raw_config": {
            "api_key_env": "OPENAI_EMBEDDING_KEY",
            "name": "openai",
            "code_embedding_model": "text-embedding-3-large",
            "docs_embedding_model": "text-embedding-3-large",
        },
        "max_workers": 2,
        "max_token_length": 2048,
        "llama_query_model": "claude-opus-4-1-20250805",
        "similarity_top_k": 3,
        "response_mode": "compact",
    }
    monkeypatch.setenv("OPENAI_EMBEDDING_KEY", "embedding-key")

    monkeypatch.setattr(entry, "get_chat_provider", lambda _name: ChatProvider)
    monkeypatch.setattr(
        entry, "get_embedding_provider", lambda _name: EmbeddingProvider
    )
    monkeypatch.setattr(entry, "build_chroma_backend", build_backend)
    monkeypatch.setattr(entry, "MetisEngine", DummyEngine)

    _engine, _backend = entry.build_engine(args, runtime)

    assert captured["embed_model_code"] is None
    assert captured["embed_model_docs"] is None
    assert isinstance(
        captured["engine_kwargs"]["embedding_provider"], EmbeddingProvider
    )
    assert captured["engine_kwargs"]["usage_runtime"].codebase_path == str(tmp_path)


def test_build_engine_skips_embedding_provider_when_index_tool_disabled(
    monkeypatch, tmp_path
):
    class ChatProvider:
        def __init__(self, _runtime):
            pass

    class DummyEngine:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    captured = {}

    def build_backend(_args, _runtime, embed_model_code, embed_model_docs):
        captured["embed_model_code"] = embed_model_code
        captured["embed_model_docs"] = embed_model_docs
        return SimpleNamespace(embed_model_code=None, embed_model_docs=None)

    def fail_get_embedding_provider(_name):
        raise AssertionError("embedding provider should not be loaded")

    args = SimpleNamespace(
        backend="chroma",
        chroma_dir=str(tmp_path / "chromadb"),
        codebase_path=str(tmp_path),
        custom_prompt=None,
        enabled_tools=set(),
    )
    runtime = {
        "llm_provider_name": "anthropic",
        "llm_provider": {
            "api_key": "anthropic-key",
            "model": "claude-opus-4-1-20250805",
        },
        "embedding_provider_raw_config": {
            "name": "openai",
            "code_embedding_model": "text-embedding-3-large",
            "docs_embedding_model": "text-embedding-3-large",
        },
        "max_workers": 2,
        "max_token_length": 2048,
        "llama_query_model": "claude-opus-4-1-20250805",
        "similarity_top_k": 3,
        "response_mode": "compact",
    }

    monkeypatch.setattr(entry, "get_chat_provider", lambda _name: ChatProvider)
    monkeypatch.setattr(entry, "get_embedding_provider", fail_get_embedding_provider)
    monkeypatch.setattr(entry, "build_chroma_backend", build_backend)
    monkeypatch.setattr(entry, "MetisEngine", DummyEngine)

    engine, _backend = entry.build_engine(args, runtime)

    assert captured["embed_model_code"] is None
    assert captured["embed_model_docs"] is None
    assert engine.kwargs["embedding_provider"] is None


def test_build_engine_requires_embedding_config_when_index_tool_enabled(
    monkeypatch, tmp_path
):
    class ChatProvider:
        def __init__(self, _runtime):
            pass

    args = SimpleNamespace(
        backend="chroma",
        chroma_dir=str(tmp_path / "chromadb"),
        codebase_path=str(tmp_path),
        custom_prompt=None,
        enabled_tools={"index"},
    )
    runtime = {
        "llm_provider_name": "anthropic",
        "llm_provider": {
            "api_key": "anthropic-key",
            "model": "claude-opus-4-1-20250805",
        },
        "embedding_provider_raw_config": None,
        "max_workers": 2,
        "max_token_length": 2048,
        "llama_query_model": "claude-opus-4-1-20250805",
        "similarity_top_k": 3,
        "response_mode": "compact",
    }

    monkeypatch.setattr(entry, "get_chat_provider", lambda _name: ChatProvider)

    with pytest.raises(RuntimeError) as exc_info:
        entry.build_engine(args, runtime)

    assert "embedding_provider" in str(exc_info.value)
