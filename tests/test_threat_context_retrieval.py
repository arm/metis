# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from langgraph.store.memory import InMemoryStore
import pytest
from unittest.mock import Mock

from metis.engine.nodes.threat_model import THREAT_MODEL_NAMESPACE
from metis.engine.stages.triage.service import TriageService
from metis.engine.threat_context_retrieval import format_threat_model_context
from metis.engine.threat_context_retrieval import get_threat_model_context
from metis.engine.threat_context_retrieval import threat_model_scope_policy
from metis.engine.threat_context_retrieval import threat_model_triage_override
from metis.memory import MemoryService
from metis.sarif.triage import extract_findings
from metis.sarif.writer import generate_sarif


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

    finding = extract_findings(
        generate_sarif(
            {
                "reviews": [
                    {
                        "file": "src/public_api/../internal/call.c",
                        "reviews": [{"issue": "Needs classification"}],
                    }
                ]
            },
            tool_name="External",
        )
    )[0]
    memory = _memory_with_contract(
        tmp_path, [{**matching, "applies_to": ["src/public_api"]}]
    )
    classifier = Mock(return_value={"status": "valid", "reason": "Reviewed finding"})
    decision = TriageService(triage_checkpoint_every=1)._triage_one_finding(
        finding, classifier=classifier, debug_callback=None, memory_service=memory
    )
    assert decision is classifier.return_value
    classifier.assert_called_once()


@pytest.mark.parametrize(
    "uri_kind",
    [
        "relative",
        "file",
        "localhost",
        "symlink_relative",
        "symlink_file",
        "symlink_root_alias",
        "parent_relative",
        "parent_file",
        "parent_root_alias",
        "root_alias",
        "outside",
        "outside_symlink",
        "tilde_name",
        "tilde_directory",
    ],
)
def test_triage_uri_paths_share_confined_threat_context(tmp_path, uri_kind):
    root = tmp_path / "repository"
    source = root / {
        "tilde_name": "~entry.c",
        "tilde_directory": "~/entry.c",
    }.get(uri_kind, "src/entry.c")
    source.parent.mkdir(parents=True)
    source.write_text("void entry(void) {}\n")
    memory_root = root
    scope = (
        source.relative_to(root).as_posix()
        if uri_kind.startswith("tilde")
        else "src/*.c"
    )
    outside = uri_kind.startswith("outside")
    if uri_kind.startswith("parent"):
        nested = source.parent / "nested"
        nested.mkdir()
        (root / "alias").symlink_to(nested, target_is_directory=True)
        source = root / "alias" / ".." / source.name
    elif uri_kind.startswith("symlink"):
        (root / "alias").symlink_to(source.parent, target_is_directory=True)
        source = root / "alias" / source.name
        scope = "alias/*.c"
    elif outside:
        source = tmp_path / "outside.c"
        source.write_text("void outside(void) {}\n")
        scope = "repository"
        if uri_kind == "outside_symlink":
            (root / "src" / "escape.c").symlink_to(source)
            source = root / "src" / "escape.c"
    if uri_kind in {"root_alias", "symlink_root_alias", "parent_root_alias"}:
        memory_root = tmp_path / "root_alias"
        memory_root.symlink_to(root, target_is_directory=True)
    uri = (
        source.relative_to(root).as_posix()
        if uri_kind
        in {
            "relative",
            "symlink_relative",
            "parent_relative",
            "tilde_name",
            "tilde_directory",
        }
        else source.as_uri()
    )
    if uri_kind == "localhost":
        uri = uri.replace("file://", "file://localhost", 1)
    payload = generate_sarif(
        {
            "reviews": [
                {
                    "file": "src/entry.c",
                    "reviews": [{"issue": "Needs classification"}],
                }
            ],
        },
        tool_name="External",
    )
    location = payload["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    location["artifactLocation"]["uri"] = uri
    finding = extract_findings(payload)[0]
    original_path = finding.file_path
    memory = _memory_with_contract(memory_root, [])
    memory.create_record(
        namespace=(*THREAT_MODEL_NAMESPACE, "history"),
        key="scoped",
        artifact_type="threat_model_history_lesson",
        memory_type="episodic",
        authority="history_derived",
        repo_fingerprint="repo",
        input_fingerprint="input",
        body_json={},
        summary_text="History guidance.",
        metadata={"applies_to": [scope]},
    )
    classifier = Mock(return_value={"status": "valid", "reason": "Reviewed finding"})
    debug_callback = Mock()
    service = TriageService(triage_checkpoint_every=1)
    decision = service._triage_one_finding(
        finding,
        classifier=classifier,
        debug_callback=debug_callback,
        memory_service=memory,
    )
    assert decision is classifier.return_value
    passed_finding, context, passed_callback = classifier.call_args.args
    assert passed_finding is finding
    assert passed_callback is debug_callback
    assert {record["summary"] for record in context} == (
        set()
        if outside
        else {
            "Authoritative project security contract.",
            "History guidance.",
        }
    )

    contract = memory.get_record(
        (*THREAT_MODEL_NAMESPACE, "contracts"), "authoritative"
    )
    contract.metadata["scope_clauses"] = [
        {
            "claim_type": "analysis_policy",
            "disposition": "out_of_scope",
            "reason": "Outside project security scope.",
            "applies_to": [scope],
            "source_authority": "authoritative",
            "binding": True,
            "source_path": "SECURITY.md",
        }
    ]
    memory.put_record(contract)
    classifier.reset_mock()
    decision = service._triage_one_finding(
        finding,
        classifier=classifier,
        debug_callback=debug_callback,
        memory_service=memory,
    )
    if outside:
        assert decision is classifier.return_value
        classifier.assert_called_once_with(finding, [], debug_callback)
    else:
        assert decision["status"] == "invalid"
        classifier.assert_not_called()
    assert finding.file_path == original_path


@pytest.mark.parametrize(
    ("source", "scopes", "path", "matches"),
    [
        ("history", ["src/*.c"], "unrelated/src/file.c", False),
        ("history", ["src/**/*.c"], "src/file.c", True),
        ("history", ["src/**"], "src/nested/file.c", True),
        ("binding", ["src/*.c"], "unrelated/src/file.c", False),
        ("binding", ["src/*.c"], "src/nested/file.c", False),
        ("binding", ["src/*"], "src/nested/file.c", False),
        ("binding", ["*.c"], "dir.c/file.py", False),
        ("history", ["src/**/*.c"], "src/dir.c/file.py", False),
        ("binding", ["src/**/*.c"], "src/nested/file.c", True),
        ("history", ["**"], "src/nested/file.c", True),
        ("history", ["src"], "src/nested/file.c", True),
        ("history", ["src/file.c"], "unrelated/src/file.c", False),
        ("history", ["src/file.c"], "src/file.c", True),
        ("history", ["*.c"], "nested/file.c", False),
        ("history", ["src\\**\\*.c"], "src\\nested\\file.c", True),
        ("history", ["./src/*.c"], "src/file.c", True),
        ("history", ["src"], "./src/file.c", True),
        ("binding", ["src/**"], "src/../sensitive.c", False),
        ("history", ["**"], "../file.c", False),
        ("binding", ["**"], "/src/file.c", False),
        ("binding", ["src/[z-a].c"], "src/file.c", False),
        ("binding", ["src/[z-a].c", "src/*.c"], "src/file.c", True),
    ],
)
def test_scopes_match_from_the_repository_root(tmp_path, source, scopes, path, matches):
    claim = {
        "claim_type": "analysis_policy",
        "statement": "This interface is outside project security scope.",
        "applies_to": scopes,
        "disposition": "out_of_scope",
    }
    if source == "binding":
        memory = _memory_with_contract(
            tmp_path,
            [{**claim, "source_authority": "authoritative", "binding": True}],
        )
    else:
        memory = MemoryService(InMemoryStore(), repo_root=str(tmp_path))
        memory.create_record(
            namespace=(*THREAT_MODEL_NAMESPACE, source),
            key="scoped",
            artifact_type="threat_model_history_lesson",
            memory_type="episodic",
            authority="history_derived",
            repo_fingerprint="repo",
            input_fingerprint="input",
            body_json={"claims": [claim]},
            summary_text=claim["statement"],
            metadata={"applies_to": scopes},
        )

    context = get_threat_model_context(memory, path=path)
    policy = threat_model_scope_policy(context, path=path)
    if source == "binding":
        assert (policy is not None) == matches
    else:
        assert bool(context) == matches
        assert policy is None


def test_old_code_generated_records_are_not_threat_context(tmp_path):
    memory = _memory_with_contract(tmp_path, [])
    original = get_threat_model_context(memory)
    memory.create_record(
        namespace=(*THREAT_MODEL_NAMESPACE, "generated"),
        key="repository",
        artifact_type="threat_model_generated",
        memory_type="semantic",
        authority="inferred",
        repo_fingerprint="repo",
        input_fingerprint="input",
        summary_text="Previously inferred from source code.",
        body_json={
            "claims": [
                {
                    "claim_type": "asset",
                    "statement": "Previously inferred from source code.",
                    "applies_to": ["repository"],
                    "disposition": "advisory",
                }
            ]
        },
        metadata={"binding": False},
    )
    assert get_threat_model_context(memory) == original
