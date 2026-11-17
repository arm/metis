# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from concurrent.futures import CancelledError
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from metis.cli import commands
from metis.engine.execution.contracts import EmptyNodeConfiguration
from metis.engine.execution.contracts import ExecutionDiagnostic
from metis.engine.execution.contracts import NodeInvocation
from metis.engine.nodes.threat_model import history
from metis.engine.nodes.threat_model import registration
from metis.engine.nodes.threat_model import service
from metis.engine.model_tool_runner import ModelInputLimitError
from metis.engine.repository import EngineRepository
from metis.engine.runtime import EngineState
from metis.engine.llm_runner import ModelProviderConfigurationError
from test_execution_graph import _node_context
from test_threat_context import _config


@pytest.fixture
def threat_node(tmp_path, node_jobs):
    config = _config(tmp_path, with_model=True)
    repository = EngineRepository(config, EngineState())
    node = registration.create_node(config, repository)
    context = _node_context()
    context = replace(
        context,
        repository=repository,
        capabilities={"memory": config.memory_service},
        runtime=replace(
            context.runtime, model=config.llama_query_model, jobs=node_jobs
        ),
    )

    def invoke():
        return node.execute(NodeInvocation(EmptyNodeConfiguration(), {}, context))

    return config, invoke


@pytest.mark.parametrize("decision,expected", [(None, "inconclusive"), ([], "ok")])
def test_source_distillation_reports_exhaustion_but_accepts_empty_claims(
    threat_node, monkeypatch, decision, expected
):
    config, invoke = threat_node
    (Path(config.codebase_path) / "SECURITY.md").write_text(
        "Protect keys.", encoding="utf-8"
    )
    monkeypatch.setattr(
        service, "invoke_langchain_json_prompt_with_retry", lambda *a, **k: decision
    )

    result = invoke()

    assert result.status.value == result.outputs["threat_model"].status == expected
    assert [item.code for item in result.diagnostics] == (
        ["threat_model.distillation_inconclusive"] if decision is None else []
    )
    records = list(config.memory_service.iter_records(service.THREAT_MODEL_NAMESPACE))
    assert len(records) == 1
    assert "Protect keys." in records[0].summary_text


def _claim():
    return {
        "claim_type": "asset",
        "statement": "Protect keys.",
        "applies_to": ["repository"],
        "disposition": "review",
        "source_refs": [],
    }


@pytest.mark.parametrize(
    "response",
    [
        None,
        [],
        [{**_claim(), "source_claim_indexes": [9]}],
        RuntimeError("provider failure"),
    ],
)
def test_incomplete_reduction_keeps_claims_and_reports_safe_diagnostic(
    threat_node, monkeypatch, response
):
    config, _invoke = threat_node

    def model(*_args, **_kwargs):
        if isinstance(response, Exception):
            raise response
        return response

    monkeypatch.setattr(service, "invoke_langchain_json_prompt_with_retry", model)
    diagnostics = []
    claims = [_claim()]

    assert (
        service._model_reduce_source_claim_group(
            config, claims, diagnostics=diagnostics
        )
        == claims
    )
    assert [item.code for item in diagnostics] == [
        "threat_model.reduction_inconclusive"
    ]
    assert "provider failure" not in diagnostics[0].message


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize(
    "failure",
    [
        RuntimeError("provider failure"),
        ModelInputLimitError("prompt too large"),
        ModelProviderConfigurationError("provider configuration invalid"),
    ],
)
def test_requested_history_failure_stops_initialization(
    threat_node, monkeypatch, caplog, enabled, failure
):
    config, invoke = threat_node
    config.threat_model_config["history"] = {"enabled": enabled, "max_commits": 1}
    monkeypatch.setattr(history, "_git_history", lambda *a: [{"commit": "fixture"}])

    def fail(*_args):
        raise failure

    monkeypatch.setattr(history, "_distill_history", fail)

    result = invoke()

    assert result.status.value == ("error" if enabled else "ok")
    assert [item.code for item in result.diagnostics] == (
        ["threat_model.history_inconclusive"] if enabled else []
    )
    if enabled:
        assert result.outputs == {}
        assert result.diagnostics[0].severity == "error"
        assert f"Git-history threat-model distillation failed: {failure}" in caplog.text
    else:
        assert "Git-history threat-model distillation failed:" not in caplog.text


def test_history_failure_preserves_snapshot_without_publishing_stale_context(
    threat_node, monkeypatch
):
    config, invoke = threat_node
    source = Path(config.codebase_path) / "SECURITY.md"
    source.write_text("Protect keys.", encoding="utf-8")
    monkeypatch.setattr(
        service, "invoke_langchain_json_prompt_with_retry", lambda *a, **k: []
    )
    invoke()
    previous = list(config.memory_service.iter_records(service.THREAT_MODEL_NAMESPACE))
    source.write_text("Protect keys and signatures.", encoding="utf-8")
    config.threat_model_config["history"] = {"enabled": True, "max_commits": 1}
    monkeypatch.setattr(history, "_git_history", lambda *a: [{"commit": "fixture"}])

    def fail(*_args):
        raise RuntimeError("provider failure")

    monkeypatch.setattr(history, "_distill_history", fail)

    result = invoke()

    assert result.status.value == "error"
    assert result.outputs == {}
    assert (
        list(config.memory_service.iter_records(service.THREAT_MODEL_NAMESPACE))
        == previous
    )


@pytest.mark.parametrize("valid_empty", [False, True])
def test_snapshot_reuse_distinguishes_incomplete_from_empty_success(
    threat_node, monkeypatch, valid_empty
):
    config, invoke = threat_node
    (Path(config.codebase_path) / "SECURITY.md").write_text(
        "Protect keys.", encoding="utf-8"
    )
    calls = []

    def model(*_args, **kwargs):
        calls.append(kwargs["label"])
        return [] if valid_empty else None

    monkeypatch.setattr(service, "invoke_langchain_json_prompt_with_retry", model)
    first, second = invoke(), invoke()

    assert (
        first.status.value
        == second.status.value
        == ("ok" if valid_empty else "inconclusive")
    )
    assert len(calls) == (1 if valid_empty else 2)


def test_incomplete_reduction_is_retried_before_snapshot_reuse(
    threat_node, monkeypatch
):
    config, invoke = threat_node
    (Path(config.codebase_path) / "SECURITY.md").write_text(
        "Protect keys.", encoding="utf-8"
    )
    reductions = []

    def model(*_args, **kwargs):
        if kwargs["label"] == "threat-model source distillation":
            return [_claim()]
        reductions.append(True)
        return (
            None
            if len(reductions) == 1
            else [{**_claim(), "source_claim_indexes": [0]}]
        )

    monkeypatch.setattr(service, "invoke_langchain_json_prompt_with_retry", model)

    first, second, third = invoke(), invoke(), invoke()

    assert first.status.value == "inconclusive"
    assert second.status.value == third.status.value == "ok"
    assert len(reductions) == 2
    assert third.outputs["threat_model"].records_written == 0


def test_older_snapshot_without_completion_status_is_refreshed(
    threat_node, monkeypatch
):
    config, invoke = threat_node
    source = Path(config.codebase_path) / "SECURITY.md"
    source.write_text("Protect keys.", encoding="utf-8")
    calls = []

    def model(*_args, **_kwargs):
        calls.append(True)
        return []

    monkeypatch.setattr(service, "invoke_langchain_json_prompt_with_retry", model)
    invoke()
    records = list(config.memory_service.iter_records(service.THREAT_MODEL_NAMESPACE))
    for record in records:
        record.metadata.pop("snapshot_status")
    config.memory_service.replace_records(service.THREAT_MODEL_NAMESPACE, records)

    refreshed, reused = invoke(), invoke()

    assert refreshed.outputs["threat_model"].records_written == 1
    assert reused.outputs["threat_model"].records_written == 0
    assert len(calls) == 2


def test_diagnostic_collector_does_not_change_current_initialization_status(
    threat_node,
):
    config, _invoke = threat_node
    diagnostics = [ExecutionDiagnostic("prior.warning", "Earlier warning", "warning")]

    result = service.initialize_threat_model_memory(config, diagnostics=diagnostics)

    assert result["status"] == "ok"
    assert len(diagnostics) == 1


@pytest.mark.parametrize("stage", ["distillation", "reduction", "history"])
def test_cancellation_preserves_snapshot_and_is_never_a_warning(
    threat_node, monkeypatch, stage
):
    config, invoke = threat_node
    source = Path(config.codebase_path) / "SECURITY.md"
    source.write_text("Protect keys.", encoding="utf-8")
    monkeypatch.setattr(
        service, "invoke_langchain_json_prompt_with_retry", lambda *a, **k: []
    )
    invoke()
    previous = list(config.memory_service.iter_records(service.THREAT_MODEL_NAMESPACE))
    source.write_text("Protect keys and signatures.", encoding="utf-8")

    def cancel(*_args, **_kwargs):
        raise CancelledError("cancelled")

    monkeypatch.setattr(service, "invoke_langchain_json_prompt_with_retry", cancel)
    if stage != "distillation":
        monkeypatch.setattr(
            service, "_model_distilled_source_claims", lambda *a, **k: [_claim()]
        )
    if stage == "history":
        monkeypatch.setattr(
            service, "_model_reduce_source_claim_group", lambda c, claims, **k: claims
        )
        config.threat_model_config["history"] = {"enabled": True, "max_commits": 1}
        monkeypatch.setattr(history, "_git_history", lambda *a: [{"commit": "fixture"}])
        monkeypatch.setattr(history, "_distill_history", cancel)

    with pytest.raises(CancelledError, match="cancelled"):
        invoke()

    assert (
        list(config.memory_service.iter_records(service.THREAT_MODEL_NAMESPACE))
        == previous
    )


@pytest.mark.parametrize(
    "status,expected",
    [("inconclusive", "initialization incomplete"), ("ok", "initialized")],
)
def test_init_command_reports_the_initialization_outcome(monkeypatch, status, expected):
    messages = []
    monkeypatch.setattr(
        commands, "print_console", lambda message, _quiet: messages.append(message)
    )
    engine = SimpleNamespace(
        init_codebase=lambda: {
            "threat_model": {
                "status": status,
                "records_written": 1,
                "records_deleted": 0,
                "authoritative_sources": ["SECURITY.md"],
            }
        }
    )

    commands.run_init(engine, SimpleNamespace(quiet=True, output_file=None), None)

    assert f"Threat model {expected}." in messages[0]
