# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from types import SimpleNamespace

import pytest
from langgraph.store.memory import InMemoryStore

import metis.engine.threat_context as threat_context
from metis.engine.threat_context import initialize_threat_model_memory
from metis.memory import MemoryService


def _config(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    service = MemoryService(
        InMemoryStore(),
        repo_root=str(repo),
        tool_version="metis-test",
    )
    return SimpleNamespace(
        codebase_path=str(repo),
        threat_model_config={
            "include_well_known": True,
            "source_paths": [],
            "source_globs": [],
        },
        plugin_config={
            "docs": {"supported_extensions": [".md", ".html", ".txt", ".pdf", ".rst"]}
        },
        metisignore_file=".metisignore",
        max_token_length=100000,
        llm_provider=None,
        llama_query_model="",
        usage_runtime=None,
        chat_model_kwargs={},
        memory_service=service,
    )


def test_initialize_threat_model_memory_marks_security_doc_as_authoritative_policy(
    tmp_path,
):
    config = _config(tmp_path)
    security = tmp_path / "repo" / "SECURITY.html"
    security.write_text(
        "# Security\n\nUntrusted firmware images cross a secure-world boundary.\n",
        encoding="utf-8",
    )

    result = initialize_threat_model_memory(config)
    assert result["status"] == "ok"
    assert result["authoritative_sources"] == ["SECURITY.html"]
    record = config.memory_service.get_record(
        ("repo", "threat_model", "authoritative"),
        "SECURITY.html",
    )
    assert record is not None
    assert record.authority == "authoritative"
    assert record.metadata["binding"] is True
    assert "Untrusted firmware images cross a secure-world boundary." in (
        record.summary_text
    )


def test_initialize_threat_model_memory_removes_deleted_sources(tmp_path):
    config = _config(tmp_path)
    repo = tmp_path / "repo"
    security = repo / "SECURITY.md"
    security.write_text(
        "# Security\n\nFirmware images are untrusted.\n", encoding="utf-8"
    )

    initialize_threat_model_memory(config)
    security.unlink()
    result = initialize_threat_model_memory(config)

    assert result["records_deleted"] > 0
    assert (
        config.memory_service.get_record(
            ("repo", "threat_model", "authoritative"),
            "SECURITY.md",
        )
        is None
    )


def test_initialize_threat_model_memory_preserves_snapshot_on_model_failure(
    tmp_path, monkeypatch
):
    config = _config(tmp_path)
    config.llm_provider = SimpleNamespace(count_tokens=lambda _text: 1)
    config.llama_query_model = "test-model"
    repo = tmp_path / "repo"
    (repo / "SECURITY.md").write_text(
        "# Security\n\nFirmware images are untrusted.\n",
        encoding="utf-8",
    )
    config.memory_service.create_record(
        namespace=("repo", "threat_model", "contracts"),
        key="authoritative",
        artifact_type="threat_model_contract",
        memory_type="semantic",
        repo_fingerprint="old-repo",
        input_fingerprint="old-input",
        body_json={"authority": "authoritative"},
        summary_text="Known-good threat-model contract.",
        search_text="known-good threat-model contract",
        metadata={"authority": "authoritative", "binding": True},
        source_kind="compiled_contract",
    )
    monkeypatch.setattr(
        threat_context,
        "invoke_langchain_json_prompt_with_retry",
        lambda *_args, **_kwargs: None,
    )

    with pytest.raises(RuntimeError, match="distillation returned no valid response"):
        initialize_threat_model_memory(config)

    preserved = config.memory_service.get_record(
        ("repo", "threat_model", "contracts"),
        "authoritative",
    )
    assert preserved is not None
    assert preserved.summary_text == "Known-good threat-model contract."


def test_initialize_threat_model_memory_uses_configured_sources_only(tmp_path):
    config = _config(tmp_path)
    config.threat_model_config = {
        "include_well_known": False,
        "source_paths": ["docs/platform-risk-register.html"],
        "source_globs": ["design/*.md"],
    }
    repo = tmp_path / "repo"
    (repo / "SECURITY.md").write_text(
        "# Security\n\nThis default file should not be loaded.\n",
        encoding="utf-8",
    )
    (repo / "docs").mkdir()
    (repo / "docs" / "platform-risk-register.html").write_text(
        "<h1>Runtime Trust Boundaries</h1>"
        "<p>Images from flash are attacker-controlled.</p>",
        encoding="utf-8",
    )
    (repo / "design").mkdir()
    (repo / "design" / "boot-flow.md").write_text(
        "Threat Model\n\nBoot certificates cross a privilege boundary.\n",
        encoding="utf-8",
    )

    result = initialize_threat_model_memory(config)

    assert result["authoritative_sources"] == [
        "docs/platform-risk-register.html",
        "design/boot-flow.md",
    ]
    methods = {
        record.metadata["path"]: record.metadata["source"]["source_method"]
        for record in config.memory_service.iter_records(
            ("repo", "threat_model", "authoritative")
        )
    }
    assert methods == {
        "docs/platform-risk-register.html": "configured_path",
        "design/boot-flow.md": "configured_glob",
    }


def test_initialize_threat_model_memory_ignores_unsupported_sources(tmp_path):
    config = _config(tmp_path)
    config.threat_model_config = {
        "include_well_known": False,
        "source_paths": ["docs/security.pdf"],
        "source_globs": [],
    }
    repo = tmp_path / "repo"
    (repo / "docs").mkdir()
    (repo / "docs" / "security.pdf").write_bytes(
        b"%PDF-1.7\nbinary threat model data\n"
    )
    result = initialize_threat_model_memory(config)

    assert result["authoritative_sources"] == []
    assert result["records_deleted"] == 0


def test_threat_scope_contract_uses_model_derived_scope_clauses(tmp_path, monkeypatch):
    config = _config(tmp_path)
    repo = tmp_path / "repo"
    (repo / "SECURITY.md").write_text(
        "# Security\n\nSecurity is not our concern for this test component.\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        threat_context,
        "_model_distilled_source_claims",
        lambda *_args, **_kwargs: [
            {
                "claim_type": "analysis_policy",
                "statement": "Security findings are not project concerns.",
                "applies_to": ["repository"],
                "disposition": "out_of_scope",
            }
        ],
    )

    initialize_threat_model_memory(config)
    contract_record = config.memory_service.get_record(
        ("repo", "threat_model", "contracts"),
        "authoritative",
    )

    assert contract_record is not None
    assert contract_record.authority == "authoritative"
    assert contract_record.memory_type == "procedural"
    assert contract_record.body_json["scope_clauses"][0]["claim_type"] == (
        "analysis_policy"
    )
