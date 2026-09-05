# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from contextlib import nullcontext
from pathlib import Path
import json
import sys
from types import SimpleNamespace
from unittest.mock import Mock, call

import pytest

from metis.cli import entry
from metis.cli import command_registry
from metis.engine.execution import ExecutionDiagnostic
from metis.engine.execution import ExecutionResult
from metis.engine.execution import ExecutionStatus


def test_execute_command_allows_interactive_triage_command_with_global_triage_flag(
    monkeypatch,
):
    args = SimpleNamespace(
        quiet=True,
        triage=True,
        output_file=None,
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


def test_interactive_output_override_does_not_replace_global_output(monkeypatch):
    args = SimpleNamespace(quiet=True, output_file=["global.json"])
    engine = SimpleNamespace(usage_command=lambda *_args, **_kwargs: None)
    outputs = []
    monkeypatch.setattr(
        command_registry.CommandSpec,
        "invoke",
        lambda self, engine, cmd_args, command_args, runtime: outputs.append(
            command_args.output_file
        ),
    )

    entry.execute_command(
        engine, "review_file", ["source.py", "--output-file", "override.json"], args
    )
    entry.execute_command(engine, "review_file", ["source.py"], args)

    assert outputs == [["override.json"], ["global.json"]]
    assert args.output_file == ["global.json"]


def test_interactive_loop_parses_quoted_paths_and_recovers_from_bad_quotes(monkeypatch):
    inputs = iter(
        [
            "review_file 'unterminated",
            r'review_file "source file.py" --output-file report\ file.json',
            "exit",
        ]
    )
    monkeypatch.setattr(entry, "prompt", lambda *_args, **_kwargs: next(inputs))
    monkeypatch.setattr(entry, "PG_SUPPORTED", False)
    calls = []

    def execute(engine, cmd, cmd_args, args):
        calls.append((cmd, cmd_args))
        return entry.EXIT_REQUESTED if cmd == "exit" else None

    monkeypatch.setattr(entry, "execute_command", execute)

    assert entry.run_interactive_loop(None, SimpleNamespace(quiet=True), None)
    assert calls == [
        ("review_file", ["source file.py", "--output-file", "report file.json"]),
        ("exit", []),
    ]


@pytest.mark.parametrize("verbose", [False, True])
@pytest.mark.parametrize("failure", [False, True])
def test_execute_graph_forwards_progress_and_finishes_reporter(
    monkeypatch, verbose, failure
):
    progress = object()
    reporter = Mock()
    build_progress = Mock(return_value=nullcontext(progress))
    build_reporter = Mock(return_value=reporter)
    monkeypatch.setattr(entry, "build_standard_progress", build_progress)
    monkeypatch.setattr(entry, "ExecutionGraphProgressReporter", build_reporter)
    callbacks = {"diagnostic_callback": object()}
    events = [
        {"event": "stage_start", "stage": "review"},
        {"event": "node_end", "stage": "review", "node": "result", "status": "ok"},
    ]
    result = object()

    def execute_graph(**kwargs):
        assert kwargs["callbacks"] is callbacks
        assert kwargs["include_triaged"] is None
        callback = callbacks.get("progress_callback")
        assert callback is (reporter if verbose else None)
        if callback is not None:
            for event in events:
                callback(event)
        if failure:
            raise RuntimeError("graph failed")
        return result

    engine = SimpleNamespace(execute_graph=execute_graph)
    args = SimpleNamespace(verbose=verbose, include_triaged=False)
    if failure:
        with pytest.raises(RuntimeError, match="graph failed"):
            entry._execute_graph_with_progress(engine, args, callbacks)
    else:
        assert entry._execute_graph_with_progress(engine, args, callbacks) is result

    if verbose:
        build_progress.assert_called_once_with(transient=True)
        build_reporter.assert_called_once_with(progress)
        assert reporter.mock_calls == [
            *(call(event) for event in events),
            call.finish(),
        ]
    else:
        build_progress.assert_not_called()
        build_reporter.assert_not_called()
        assert not reporter.mock_calls


def test_main_version_does_not_require_runtime_config(monkeypatch, capsys):
    def fail_load_runtime_config(*_args, **_kwargs):
        raise AssertionError("runtime config should not be loaded for --version")

    monkeypatch.setattr(sys, "argv", ["metis", "--version"])
    monkeypatch.setattr(entry, "load_runtime_config", fail_load_runtime_config)

    entry.main()

    assert "Metis" in capsys.readouterr().out


@pytest.mark.parametrize(
    "removed_args",
    (["--non-interactive"], ["--command", "version"]),
)
def test_main_rejects_removed_command_mode_flags(monkeypatch, removed_args, capsys):
    monkeypatch.setattr(sys, "argv", ["metis", *removed_args])

    with pytest.raises(SystemExit, match="2"):
        entry.main()

    assert "unrecognized arguments" in capsys.readouterr().err


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


def test_partial_graph_exports_sarif_without_findings_and_skips_failed_triage(tmp_path):
    sarif = {"version": "2.1.0", "runs": []}
    result = ExecutionResult(
        ExecutionStatus.ERROR,
        {
            "review": {"formats": ("json", "sarif"), "sarif": sarif},
            "triage": {"formats": ("sarif",)},
        },
    )
    requested_json = tmp_path / "report.json"
    requested_json.write_text("previous report", encoding="utf-8")
    requested_sarif = tmp_path / "report.sarif"

    entry._save_graph_outputs([str(requested_json), str(requested_sarif)], result, True)

    assert json.loads(requested_sarif.read_text()) == sarif
    assert requested_json.read_text() == "previous report"
    assert set(tmp_path.iterdir()) == {requested_json, requested_sarif}


@pytest.mark.parametrize(
    "command,arguments",
    [
        ("review_file", []),
        ("review_file", ["one.py", "two.py"]),
        ("review_dir", ["one", "two"]),
        ("update", ["one.patch", "two.patch"]),
        ("index", ["ignored"]),
        ("help", ["ignored"]),
        ("version", ["ignored"]),
        ("exit", ["ignored"]),
        ("ask", []),
        ("ask", [" "]),
    ],
)
def test_invalid_interactive_arguments_do_not_invoke_or_create_outputs(
    monkeypatch, tmp_path, command, arguments
):
    monkeypatch.chdir(tmp_path)
    invoke = Mock()
    engine = Mock()
    monkeypatch.setattr(command_registry.CommandSpec, "invoke", invoke)
    result = entry.execute_command(
        engine, command, arguments, SimpleNamespace(quiet=True, output_file=None)
    )
    assert result is not entry.EXIT_REQUESTED
    invoke.assert_not_called()
    engine.usage_command.assert_not_called()
    assert not (tmp_path / "results").exists()


@pytest.mark.parametrize(
    "arguments",
    [
        ["one.py", "--output-file"],
        ["one.py", "--output-file", ""],
        ["one.py", "--output-file", "--output-file", "report.json"],
    ],
)
def test_interactive_output_option_requires_a_value(monkeypatch, tmp_path, arguments):
    monkeypatch.chdir(tmp_path)
    invoke = Mock()
    monkeypatch.setattr(command_registry.CommandSpec, "invoke", invoke)
    with pytest.raises(ValueError, match="--output-file requires a filename"):
        entry.execute_command(
            Mock(),
            "review_file",
            arguments,
            SimpleNamespace(quiet=True, output_file=None),
        )
    invoke.assert_not_called()
    assert not (tmp_path / "results").exists()


@pytest.mark.parametrize(
    "embedding_config",
    [
        {"name": "openai", "api_key": "inert"},
        {"name": "no-such-embedding-provider"},
    ],
)
def test_build_engine_validates_embedding_before_provider_construction(
    monkeypatch, embedding_config
):
    def unexpected_provider(_config):
        pytest.fail("invalid embedding settings constructed a chat provider")

    monkeypatch.setattr(entry, "get_chat_provider", lambda _name: unexpected_provider)
    with pytest.raises(ValueError):
        entry.build_engine(
            None,
            {
                "llm_provider_name": "inert",
                "llm_provider": {},
                "embedding_provider_raw_config": embedding_config,
            },
        )


@pytest.mark.parametrize("schema_exists", [False, True])
def test_postgres_prompt_checks_index_only_for_index_commands(
    monkeypatch, schema_exists
):
    backend = Mock()
    backend.check_project_schema_exists.return_value = schema_exists
    inputs = iter(
        [
            "review_code",
            "review_file f",
            "review_dir d",
            "review_patch p",
            "ask question",
            "exit",
        ]
    )
    calls = []
    monkeypatch.setattr(entry, "PG_SUPPORTED", True)
    monkeypatch.setattr(entry, "PGVectorStoreImpl", type(backend), raising=False)
    monkeypatch.setattr(entry, "prompt", lambda *a, **kw: next(inputs))

    def execute(engine, command, command_args, args):
        calls.append(command)
        return entry.EXIT_REQUESTED if command == "exit" else None

    monkeypatch.setattr(entry, "execute_command", execute)
    entry.run_interactive_loop(None, SimpleNamespace(quiet=True), backend)
    assert calls == [
        "review_code",
        "review_file",
        "review_dir",
        "review_patch",
        *(["ask"] if schema_exists else []),
        "exit",
    ]
    backend.check_project_schema_exists.assert_called_once_with()


def test_main_reports_codebase_io_errors_without_setup(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["metis", "--codebase-path", "inaccessible"])

    def inaccessible(path):
        raise PermissionError("codebase access denied")

    monkeypatch.setattr(entry, "check_dir_exists", inaccessible)
    with pytest.raises(SystemExit, match="1"):
        entry.main()
    assert "codebase access denied" in capsys.readouterr().out


@pytest.mark.parametrize(
    "failure", [BrokenPipeError("closed pipe"), KeyboardInterrupt()]
)
def test_farewell_failure_cannot_skip_engine_close(monkeypatch, failure):
    engine = SimpleNamespace(close=Mock())

    def fail_print(*args, **kwargs):
        raise failure

    monkeypatch.setattr(entry, "print_console", fail_print)
    with pytest.raises(type(failure)) as caught:
        entry.finalize_cli_session_and_close(
            engine, SimpleNamespace(quiet=False), "Goodbye"
        )
    assert caught.value is failure
    engine.close.assert_called_once_with()
