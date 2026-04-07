# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json

from metis.cli import entry
from metis.usage.context import current_operation, current_scope
from metis.usage.runtime import UsageRuntime


class _DummyProvider:
    def __init__(self, _config):
        pass

    def get_embed_model_code(self, **_kwargs):
        return object()

    def get_embed_model_docs(self, **_kwargs):
        return object()


class _DummyEngine:
    def __init__(self, codebase_path=".", **_kwargs):
        self.codebase_path = codebase_path
        self.usage_runtime = UsageRuntime(codebase_path)
        self.closed = False

    def usage_command(self, command_name, target=None, display_name=None):
        return self.usage_runtime.command(
            command_name,
            target=target,
            display_name=display_name,
        )

    def finalize_usage_command(self, command):
        return self.usage_runtime.finalize_command(command)

    def usage_totals(self):
        return self.usage_runtime.snapshot_total()

    def has_usage(self):
        return self.usage_runtime.has_usage()

    def save_usage_summary(self, output_path=None):
        return self.usage_runtime.save_run_summary(output_path)

    def ask_question(self, _question):
        self.usage_runtime.collector.record(
            scope_id=current_scope(),
            operation=current_operation(),
            model="gpt-4o-mini",
            input_tokens=10,
            output_tokens=4,
            total_tokens=14,
        )
        return {"code": "ctx", "docs": "docs"}

    def close(self):
        self.closed = True


def _setup_cli(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        entry,
        "load_runtime_config",
        lambda enable_psql=False: {
            "llm_provider_name": "dummy",
            "max_workers": 2,
            "max_token_length": 2048,
            "llama_query_model": "gpt-test",
            "similarity_top_k": 3,
            "response_mode": "compact",
        },
    )
    monkeypatch.setattr(entry, "get_provider", lambda _name: _DummyProvider)
    monkeypatch.setattr(entry, "build_chroma_backend", lambda *args, **kwargs: object())
    monkeypatch.setattr(entry, "build_pg_backend", lambda *args, **kwargs: object())
    monkeypatch.setattr(entry, "MetisEngine", _DummyEngine)
    captured = []
    monkeypatch.setattr(
        "metis.cli.utils.console.print",
        lambda *args, **kwargs: captured.append(" ".join(str(arg) for arg in args)),
    )
    return captured


def test_noninteractive_verbose_command_prints_usage_and_persists_run(
    monkeypatch, tmp_path
):
    captured = _setup_cli(monkeypatch, tmp_path)
    monkeypatch.setattr(
        "sys.argv",
        [
            "metis",
            "--non-interactive",
            "--verbose",
            "--command",
            "ask explain",
            "--codebase-path",
            str(tmp_path),
        ],
    )

    entry.main()

    assert any("Token usage (ask)" in line for line in captured)
    assert any("Session token usage" in line for line in captured)
    usage_files = sorted((tmp_path / "results").glob("metis_usage_*.json"))
    assert usage_files
    payload = json.loads(usage_files[-1].read_text(encoding="utf-8"))
    assert payload["totals"]["total_tokens"] == 14
    assert payload["commands"][0]["command_name"] == "ask"


def test_noninteractive_default_quiet_prints_answer_but_not_usage(
    monkeypatch, tmp_path
):
    captured = _setup_cli(monkeypatch, tmp_path)
    monkeypatch.setattr(
        "sys.argv",
        [
            "metis",
            "--non-interactive",
            "--command",
            "ask explain",
            "--codebase-path",
            str(tmp_path),
        ],
    )

    entry.main()

    assert not any("Token usage (ask)" in line for line in captured)
    assert not any("Session token usage" in line for line in captured)
    assert any("Metis Answer:" in line for line in captured)
    assert any("Code Context:" in line for line in captured)
    assert any("Documentation Context:" in line for line in captured)
    usage_files = sorted((tmp_path / "results").glob("metis_usage_*.json"))
    assert usage_files
    payload = json.loads(usage_files[-1].read_text(encoding="utf-8"))
    assert payload["totals"]["total_tokens"] == 14
    assert payload["commands"][0]["command_name"] == "ask"


def test_noninteractive_help_does_not_persist_usage(monkeypatch, tmp_path):
    captured = _setup_cli(monkeypatch, tmp_path)
    monkeypatch.setattr(
        "sys.argv",
        [
            "metis",
            "--non-interactive",
            "--command",
            "help",
            "--codebase-path",
            str(tmp_path),
        ],
    )

    entry.main()

    assert not any("Token usage (help)" in line for line in captured)
    assert not any("Session token usage" in line for line in captured)
    results_dir = tmp_path / "results"
    usage_files = (
        sorted(results_dir.glob("metis_usage_*.json")) if results_dir.exists() else []
    )
    assert not results_dir.exists()
    assert not usage_files


def test_interactive_eof_finalizes_usage(monkeypatch, tmp_path):
    captured = _setup_cli(monkeypatch, tmp_path)
    prompts = iter(["ask explain"])

    def _fake_prompt(*_args, **_kwargs):
        try:
            return next(prompts)
        except StopIteration as exc:
            raise EOFError from exc

    monkeypatch.setattr(entry, "prompt", _fake_prompt)
    monkeypatch.setattr(
        "sys.argv",
        ["metis", "--codebase-path", str(tmp_path)],
    )

    entry.main()

    assert any("Token usage (ask)" in line for line in captured)
    assert any("Session token usage" in line for line in captured)
    assert any("Bye!" in line for line in captured)
