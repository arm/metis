# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from contextlib import nullcontext
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from metis.cli import entry
from metis.cli import command_registry
from metis.engine.execution import ExecutionDiagnostic
from metis.engine.execution import ExecutionResult
from metis.engine.execution import ExecutionStatus


def test_cli_entry_imports_in_clean_interpreter():
    completed = subprocess.run(
        [sys.executable, "-c", "from metis.cli.entry import main"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr


def test_execute_command_rejects_triage_flag_for_ask_before_index_gating(monkeypatch):
    args = SimpleNamespace(
        quiet=True,
        triage=True,
        output_file=None,
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
        quiet=True,
        triage=True,
        output_file=None,
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


@pytest.mark.parametrize(
    "argv",
    [
        ["metis"],
        ["metis", "-v", "--non-interactive", "--config", "graph.yaml"],
    ],
)
def test_main_executes_configured_graph_by_default(monkeypatch, argv):
    calls = []
    messages = []

    def execute_graph(**kwargs):
        progress = kwargs["callbacks"].get("progress_callback")
        if progress is not None:
            progress({"event": "execution_stage_start", "stage": "review"})
            progress(
                {
                    "event": "execution_node_start",
                    "stage": "review",
                    "node": "reachability",
                }
            )
        kwargs["callbacks"]["diagnostic_callback"](
            SimpleNamespace(severity="warning", message="fallback review")
        )
        calls.append("graph")
        return ExecutionResult(
            ExecutionStatus.INCONCLUSIVE,
            {
                "review": {
                    "formats": ["sarif", "json"],
                    "findings": {"reviews": []},
                    "sarif": {"version": "2.1.0", "runs": []},
                },
                "triage": {
                    "formats": ["sarif"],
                    "sarif": {"version": "2.1.0", "runs": []},
                },
            },
            (ExecutionDiagnostic("review.fallback", "fallback review", "warning"),),
        )

    engine = SimpleNamespace(execute_graph=execute_graph)
    monkeypatch.setattr(sys, "argv", argv)
    monkeypatch.setattr(entry, "load_runtime_config", lambda **_kwargs: {})
    monkeypatch.setattr(entry, "build_engine", lambda *_args: (engine, None))
    monkeypatch.setattr(
        entry,
        "determine_output_file",
        lambda _cmd, args, _cmd_args: setattr(args, "output_file", ["graph.json"]),
    )
    monkeypatch.setattr(
        entry,
        "save_output",
        lambda *_args, **_kwargs: calls.append("save"),
    )
    monkeypatch.setattr(
        entry,
        "print_console",
        lambda message, *_args, **_kwargs: messages.append(message),
    )
    monkeypatch.setattr(
        entry, "finalize_cli_session_and_close", lambda *_args: calls.append("close")
    )

    entry.main()

    assert calls == ["graph", "save", "save", "close"]
    assert "[yellow]fallback review[/yellow]" in messages
    if "-v" in argv:
        assert "[cyan]Stage:[/cyan] review" in messages
        assert "[cyan]Node:[/cyan] review.reachability" in messages
    else:
        assert not any("Stage:" in message for message in messages)


def test_main_rejects_a_missing_codebase_before_creating_outputs(
    monkeypatch, tmp_path, capsys
):
    def fail_runtime(**_kwargs):
        raise AssertionError("runtime must not be loaded")

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "metis",
            "--codebase-path",
            "missing",
            "--log-file",
            "metis.log",
        ],
    )
    monkeypatch.setattr(entry, "load_runtime_config", fail_runtime)

    with pytest.raises(SystemExit, match="1"):
        entry.main()

    assert "Directory not found: missing" in capsys.readouterr().out
    assert not (tmp_path / "metis.log").exists()
    assert not (tmp_path / "results").exists()


def test_graph_outputs_are_projected_for_each_export_format(monkeypatch):
    calls = []
    findings = {"reviews": [{"reviews": [{"issue": "unsafe"}]}]}
    triage_sarif = {"version": "2.1.0", "runs": [{"id": "triage"}]}
    outputs = {
        "review": {
            "formats": ["sarif", "json", "html", "csv"],
            "findings": findings,
            "sarif": {"version": "2.1.0", "runs": [{"id": "review"}]},
        },
        "triage": {"formats": ["sarif"], "sarif": triage_sarif},
    }
    monkeypatch.setattr(
        entry,
        "save_output",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )

    entry._save_graph_outputs(  # type: ignore[attr-defined]
        ["graph.json", "report.html", "report.csv", "report.sarif"],
        ExecutionResult(
            ExecutionStatus.INCONCLUSIVE,
            outputs,
            (ExecutionDiagnostic("review.partial", "partial review", "warning"),),
        ),
        True,
    )

    assert calls[0][0] == (
        ["graph.json", "report.html", "report.csv", "graph.sarif"],
        findings,
        True,
    )
    assert calls[0][1]["sarif_payload"]["runs"] == [{"id": "review"}]
    assert calls[1] == (
        (
            ["report.sarif"],
            triage_sarif,
            True,
        ),
        {"sarif_payload": triage_sarif},
    )


def test_graph_outputs_never_share_paths_between_review_and_triage(monkeypatch):
    saved: list[list[str]] = []
    sarif = {"version": "2.1.0", "runs": []}
    outputs = {
        "review": {
            "formats": ["sarif", "json", "html", "csv"],
            "findings": {"reviews": []},
            "sarif": sarif,
        },
        "triage": {"formats": ["sarif", "json"], "sarif": sarif},
    }
    monkeypatch.setattr(
        entry,
        "save_output",
        lambda output_files, *_args, **_kwargs: saved.append(output_files),
    )

    entry._save_graph_outputs(  # type: ignore[attr-defined]
        ["report.json", "report.html", "report.csv", "report.sarif"],
        ExecutionResult(ExecutionStatus.OK, outputs),
        True,
    )

    review_files, triage_files = map(set, saved)
    assert review_files.isdisjoint(triage_files)
    assert {Path(path).suffix for path in review_files} == {
        ".sarif",
        ".json",
        ".html",
        ".csv",
    }
    assert {Path(path).suffix for path in triage_files} == {".sarif", ".json"}


@pytest.mark.parametrize(
    ("output_files", "generated_output", "expected"),
    (
        (
            ["results/graph_generated.json"],
            True,
            ["reports/review.json", "reports/review.sarif"],
        ),
        (
            ["runs/current.json"],
            False,
            ["runs/current.json", "runs/current.sarif"],
        ),
    ),
)
def test_graph_output_filename_precedence(
    monkeypatch: pytest.MonkeyPatch,
    output_files: list[str],
    generated_output: bool,
    expected: list[str],
) -> None:
    saved: list[list[str]] = []
    sarif = {"version": "2.1.0", "runs": []}
    outputs = {
        "review": {
            "formats": ("json", "sarif"),
            "filename": "reports/review",
            "findings": {"reviews": []},
            "sarif": sarif,
        }
    }
    monkeypatch.setattr(
        entry,
        "save_output",
        lambda output_files, *_args, **_kwargs: saved.append(output_files),
    )

    entry._save_graph_outputs(  # type: ignore[attr-defined]
        output_files,
        ExecutionResult(ExecutionStatus.OK, outputs),
        True,
        generated_output=generated_output,
    )

    assert saved == [expected]


def test_default_graph_failure_exits_cleanly(monkeypatch):
    calls = []
    engine = SimpleNamespace(
        execute_graph=lambda **_kwargs: (_ for _ in ()).throw(
            RuntimeError("graph failed")
        )
    )
    monkeypatch.setattr(sys, "argv", ["metis"])
    monkeypatch.setattr(entry, "load_runtime_config", lambda **_kwargs: {})
    monkeypatch.setattr(entry, "build_engine", lambda *_args: (engine, None))
    monkeypatch.setattr(entry, "determine_output_file", lambda *_args: None)
    monkeypatch.setattr(
        entry,
        "print_console",
        lambda message, *_args, **_kwargs: calls.append(message),
    )
    monkeypatch.setattr(
        entry,
        "finalize_cli_session_and_close",
        lambda *_args: calls.append("closed"),
    )

    with pytest.raises(SystemExit, match="1"):
        entry.main()

    assert "[bold red]Error:[/bold red] graph failed" in calls
    assert calls[-1] == "closed"


def test_main_passes_custom_config_path_to_runtime_loader(monkeypatch, tmp_path):
    config_path = tmp_path / "custom.yaml"
    captured = {}

    def load_runtime_config(*, config_path, enable_psql):
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
            "version",
        ],
    )
    monkeypatch.setattr(entry, "load_runtime_config", load_runtime_config)
    monkeypatch.setattr(entry, "build_engine", lambda *_args: (SimpleNamespace(), None))
    monkeypatch.setattr(entry, "run_non_interactive", lambda *_args: (0, None))
    monkeypatch.setattr(entry, "finalize_cli_session_and_close", lambda *_args: None)

    entry.main()

    assert captured == {"config_path": str(config_path), "enable_psql": False}


def test_main_returns_noninteractive_failure_status(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["metis", "--non-interactive", "--command", "version"],
    )
    monkeypatch.setattr(entry, "load_runtime_config", lambda **_kwargs: {})
    monkeypatch.setattr(entry, "build_engine", lambda *_args: (SimpleNamespace(), None))
    monkeypatch.setattr(entry, "run_non_interactive", lambda *_args: (1, None))
    monkeypatch.setattr(entry, "finalize_cli_session_and_close", lambda *_args: None)

    with pytest.raises(SystemExit, match="1"):
        entry.main()


def test_build_engine_defers_embedding_model_construction(
    monkeypatch,
    tmp_path,
):
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
    )
    runtime = {
        "llm_provider_name": "test-provider",
        "llm_provider": {
            "api_key": "test-api-key",
            "model": "test-model",
        },
        "embedding_provider_raw_config": {
            "api_key_env": "OPENAI_EMBEDDING_KEY",
            "name": "openai",
            "code_embedding_model": "text-embedding-3-large",
            "docs_embedding_model": "text-embedding-3-large",
        },
        "max_workers": 2,
        "max_token_length": 2048,
        "llama_query_model": "test-model",
        "similarity_top_k": 3,
        "response_mode": "compact",
    }
    monkeypatch.setenv("OPENAI_EMBEDDING_KEY", "embedding-key")

    monkeypatch.setattr(entry, "get_chat_provider", lambda _name: ChatProvider)
    monkeypatch.setattr(
        entry, "get_embedding_provider", lambda _name: EmbeddingProvider
    )
    monkeypatch.setenv("OPENAI_API_KEY", "embedding-key")
    monkeypatch.setattr(entry, "build_chroma_backend", build_backend)
    monkeypatch.setattr(entry, "MetisEngine", DummyEngine)

    _engine, _backend = entry.build_engine(args, runtime)

    assert captured["embed_model_code"] is None
    assert captured["embed_model_docs"] is None
    assert isinstance(
        captured["engine_kwargs"]["embedding_provider"], EmbeddingProvider
    )
    assert captured["engine_kwargs"]["usage_runtime"].codebase_path == str(tmp_path)


def test_build_engine_allows_graphs_without_index_stage_to_omit_embeddings(
    monkeypatch, tmp_path
):
    class ChatProvider:
        def __init__(self, _runtime):
            pass

    class DummyEngine:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    args = SimpleNamespace(
        backend="chroma",
        chroma_dir=str(tmp_path / "chromadb"),
        codebase_path=str(tmp_path),
        custom_prompt=None,
    )
    runtime = {
        "llm_provider_name": "test-provider",
        "llm_provider": {
            "api_key": "test-api-key",
            "model": "test-model",
        },
        "embedding_provider_raw_config": None,
        "max_workers": 2,
        "max_token_length": 2048,
        "llama_query_model": "test-model",
        "similarity_top_k": 3,
        "response_mode": "compact",
    }

    monkeypatch.setattr(entry, "get_chat_provider", lambda _name: ChatProvider)
    monkeypatch.setattr(
        entry,
        "build_chroma_backend",
        lambda *_args: SimpleNamespace(embed_model_code=None, embed_model_docs=None),
    )
    monkeypatch.setattr(entry, "MetisEngine", DummyEngine)

    engine, _backend = entry.build_engine(args, runtime)

    assert engine.kwargs["embedding_provider"] is None
