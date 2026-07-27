# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from langgraph.store.memory import InMemoryStore

from metis.engine.threat_context import THREAT_MODEL_NAMESPACE
from metis.engine.threat_context_retrieval import format_threat_model_context
from metis.engine.threat_context_retrieval import get_threat_model_context
from metis.engine.threat_context_retrieval import threat_model_scope_policy
from metis.engine.threat_context_retrieval import threat_model_triage_override
from metis.memory import MemoryService


def _memory_with_contract(tmp_path, clauses):
    service = MemoryService(InMemoryStore(), repo_root=str(tmp_path))
    service.create_record(
        namespace=(*THREAT_MODEL_NAMESPACE, "contracts"),
        key="authoritative",
        artifact_type="threat_model_contract",
        memory_type="procedural",
        authority="authoritative",
        repo_fingerprint="repo",
        input_fingerprint="input",
        body_json={},
        summary_text="Authoritative project security contract.",
        search_text="authoritative security contract",
        metadata={
            "authority": "authoritative",
            "binding": True,
            "scope_clauses": clauses,
        },
        source_kind="compiled_contract",
    )
    return service


def test_authoritative_contract_drives_global_triage_override(tmp_path):
    memory = _memory_with_contract(
        tmp_path,
        [
            {
                "claim_type": "caller_contract",
                "disposition": "integration_risk",
                "reason": "Integrators own input validation.",
                "applies_to": ["repository"],
                "source_authority": "authoritative",
                "binding": True,
                "source_path": "SECURITY.md",
            },
            {
                "claim_type": "analysis_policy",
                "disposition": "out_of_scope",
                "reason": "Security findings are outside project scope.",
                "applies_to": ["repository"],
                "source_authority": "authoritative",
                "binding": True,
                "source_path": "SECURITY.md",
            },
        ],
    )
    context = get_threat_model_context(memory)

    assert len(context) == 1
    assert "Authoritative project security contract" in format_threat_model_context(
        context
    )

    override = threat_model_triage_override(
        threat_model_scope_policy(context, path="src/example.c")
    )

    assert override is not None
    assert override["status"] == "invalid"
    assert override["threat_model_policy"]["claim_type"] == "analysis_policy"
    assert override["threat_model_policy"]["source_path"] == "SECURITY.md"


def test_path_scoped_policy_does_not_apply_to_other_files(tmp_path):
    memory = _memory_with_contract(
        tmp_path,
        [
            {
                "claim_type": "caller_contract",
                "disposition": "integration_risk",
                "reason": "Callers own validation for this interface.",
                "applies_to": ["src/public_api/*.c"],
                "source_authority": "authoritative",
                "binding": True,
                "source_path": "THREAT_MODEL.md",
            },
            {
                "claim_type": "scope_rule",
                "disposition": "out_of_scope",
                "reason": "This interface is outside project security scope.",
                "applies_to": ["src/public_api/*.c"],
                "source_authority": "authoritative",
                "binding": True,
                "source_path": "THREAT_MODEL.md",
            },
        ],
    )
    context = get_threat_model_context(memory)

    matching = threat_model_scope_policy(
        context,
        path="src/public_api/call.c",
    )
    unrelated = threat_model_scope_policy(
        context,
        path="src/internal/call.c",
    )
    nested = threat_model_scope_policy(
        context,
        path="src/public_api/nested/call.c",
    )

    assert matching is not None
    assert matching["claim_type"] == "scope_rule"
    assert matching["disposition"] == "out_of_scope"
    assert unrelated is None
    assert nested is None
