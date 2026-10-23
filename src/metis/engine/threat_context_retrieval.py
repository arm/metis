# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from glob import has_magic
import json
import posixpath
import re
from typing import Any

from pathspec.patterns.gitignore import GitIgnorePatternError
from pathspec.patterns.gitignore.spec import GitIgnoreSpecPattern

from metis.memory import MemoryService
from metis import runlog


from .nodes.threat_model import THREAT_MODEL_NAMESPACE


def get_threat_model_context(
    service: MemoryService | None,
    *,
    path: str = "",
) -> list[dict[str, Any]]:
    with runlog.span(
        "memory",
        "threat_model_context",
        {"operation": "retrieve", "path": path},
    ) as memory_span:
        records = _get_threat_model_context(service, path=path)
        memory_span.end(attributes={"count": len(records), "records": records})
        return records


def _get_threat_model_context(
    service: MemoryService | None,
    *,
    path: str,
) -> list[dict[str, Any]]:
    if service is None:
        return []

    contract = service.get_record(
        (*THREAT_MODEL_NAMESPACE, "contracts"),
        "authoritative",
    )
    records = []
    if contract is not None:
        records.append(
            {
                "summary": contract.summary_text,
                "metadata": {
                    "authority": contract.authority,
                    "scope_clauses": contract.metadata["scope_clauses"],
                },
            }
        )
    for source in service.iter_records(THREAT_MODEL_NAMESPACE):
        if source.artifact_type != "threat_model_authoritative":
            continue
        if isinstance(source.body_json, dict) and source.body_json.get(
            "distilled_claims"
        ):
            continue
        records.append(
            {
                "summary": source.summary_text,
                "metadata": {
                    "authority": source.authority,
                    "scope_clauses": [],
                },
            }
        )
    for lesson in service.iter_records((*THREAT_MODEL_NAMESPACE, "history")):
        applies_to = lesson.metadata["applies_to"]
        if _scope_applies_to_path(applies_to, path):
            records.append(
                {
                    "summary": lesson.summary_text,
                    "metadata": {
                        "authority": lesson.authority,
                        "scope_clauses": [],
                    },
                }
            )
    return records


def format_threat_model_context(records: list[dict[str, Any]]) -> str:
    sections = []
    for record in records:
        metadata = record["metadata"]
        authority = metadata["authority"]
        label = (
            f"{authority}, advisory" if authority == "history_derived" else authority
        )
        sections.append(f"- [{label}] {record['summary']}")
        clauses = metadata["scope_clauses"]
        if clauses:
            sections.append(
                "  Binding scope clauses: " + json.dumps(clauses, separators=(",", ":"))
            )
    return "\n".join(sections)


def threat_model_review_scope_guidance(records: list[dict[str, Any]]) -> str:
    if not any(
        record["metadata"]["authority"] == "authoritative" for record in records
    ):
        return ""
    return (
        "Treat applicable authoritative threat-model scope as binding. Apply "
        "path-scoped clauses only when their applies_to pattern matches the FILE."
    )


def threat_model_scope_policy(
    records: list[dict[str, Any]],
    *,
    path: str,
) -> dict[str, Any] | None:
    for clause in _scope_clauses(records):
        if _clause_authorizes_automatic_filter(clause, path):
            return dict(clause)
    return None


def threat_model_triage_override(
    policy: dict[str, Any] | None,
) -> dict[str, Any] | None:
    if policy is None:
        return None

    source_path = policy["source_path"]
    return {
        "status": "invalid",
        "reason": (
            "Invalid under authoritative threat-model scope "
            f"({source_path}). {policy['reason']} "
            "This is out of scope for project security."
        ),
        "evidence": [source_path],
        "resolution_chain": ["authoritative_threat_model_scope"],
        "unresolved_hops": [],
        "evidence_obligations": ["authoritative_threat_model_scope"],
        "evidence_coverage": {"authoritative_threat_model_scope": 1},
        "missing_evidence": [],
        "threat_model_policy": policy,
    }


def _scope_clauses(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        clause for record in records for clause in record["metadata"]["scope_clauses"]
    ]


def _clause_authorizes_automatic_filter(
    clause: dict[str, Any],
    path: str,
) -> bool:
    if _is_global_exclusion(clause):
        return True

    if (
        not _is_binding(clause)
        or clause["claim_type"] not in {"analysis_policy", "scope_rule"}
        or clause["disposition"] != "out_of_scope"
    ):
        return False

    scopes = clause["applies_to"]
    if not scopes or "repository" in scopes:
        return False

    return _scope_applies_to_path(scopes, path)


def _is_binding(clause: dict[str, Any]) -> bool:
    return clause["source_authority"] == "authoritative" and clause["binding"]


def _is_global_exclusion(clause: dict[str, Any]) -> bool:
    return (
        _is_binding(clause)
        and clause["claim_type"] == "analysis_policy"
        and clause["disposition"] == "out_of_scope"
        and "repository" in clause["applies_to"]
    )


def _scope_applies_to_path(scopes: list[str], path: str) -> bool:
    if not scopes or "repository" in scopes:
        return True
    if not path:
        return False
    normalized_path = posixpath.normpath(path.replace("\\", "/"))
    if normalized_path == ".." or normalized_path.startswith(("../", "/")):
        return False
    for scope in scopes:
        normalized_scope = scope.replace("\\", "/").removeprefix("./").rstrip("/")
        if has_magic(normalized_scope):
            try:
                match = GitIgnoreSpecPattern(f"/{normalized_scope}").match_file(
                    normalized_path
                )
            except (GitIgnorePatternError, re.error):
                continue
            if match is not None and not match.match.groupdict().get("ps_d"):
                return True
        elif normalized_path == normalized_scope or normalized_path.startswith(
            f"{normalized_scope}/"
        ):
            return True
    return False
