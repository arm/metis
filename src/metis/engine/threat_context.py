# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from dataclasses import dataclass
from glob import has_magic
from pathlib import Path
from typing import Any
from typing import Literal

from langgraph.store.memory import InMemoryStore
from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field

from metis.engine.llm_runner import invoke_langchain_json_prompt_with_retry
from metis.engine.prompt_catalog import get_engine_prompts
from metis.engine.repository import EngineRepository
from metis.engine.runtime import EngineState
from metis.memory import MemoryRecord
from metis.memory import MemoryService
from metis.memory.fingerprints import file_fingerprint
from metis.memory.fingerprints import input_fingerprint
from metis.memory.fingerprints import repo_fingerprint
from metis.utils import parse_json_output
from metis.utils import resolve_path_within_root
from metis.utils import split_snippet
from metis.utils import string_list

from .threat_context_history import write_history_records

logger = logging.getLogger("metis")

THREAT_MODEL_NAMESPACE = ("repo", "threat_model")
_PROMPTS = get_engine_prompts("threat_context")


@dataclass(frozen=True)
class ThreatSource:
    path: Path
    source: str


@dataclass(frozen=True)
class PreparedThreatSource:
    threat_source: ThreatSource
    rel_path: str
    source_fp: str
    distilled_claims: list[dict[str, Any]]
    summary: str


class _ThreatSourceClaimRecordModel(BaseModel):
    claim_type: Literal[
        "scope_rule",
        "trust_boundary",
        "caller_contract",
        "asset",
        "attacker_capability",
        "mitigation",
        "architecture_assumption",
        "analysis_policy",
    ]
    statement: str = Field(
        min_length=1,
        max_length=240,
        description=(
            "One concise plain-text statement without Markdown or line breaks."
        ),
    )
    applies_to: list[str] = Field(
        default_factory=list,
        description=(
            "Use repository for repository-wide claims, otherwise repository-relative "
            "path globs."
        ),
    )
    disposition: Literal["out_of_scope", "integration_risk", "advisory", "review"]

    model_config = ConfigDict(extra="forbid")


class _ThreatSourceClaimResponseModel(BaseModel):
    records: list[_ThreatSourceClaimRecordModel] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid")


class _ThreatSourceClaimReductionRecordModel(_ThreatSourceClaimRecordModel):
    source_claim_indexes: list[int] = Field(
        min_length=1,
        description="Indexes of candidate claims that support this merged claim.",
    )


class _ThreatSourceClaimReductionResponseModel(BaseModel):
    records: list[_ThreatSourceClaimReductionRecordModel] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid")


def _parse_distilled_records(
    raw: Any,
    *,
    response_model: type[BaseModel],
) -> list[dict[str, Any]] | None:
    if isinstance(raw, BaseModel):
        data = raw.model_dump()
    elif isinstance(raw, dict):
        data = raw
    elif isinstance(raw, str):
        data = parse_json_output(raw)
    else:
        return None

    try:
        records = response_model.model_validate(data).model_dump()["records"]
    except (TypeError, ValueError):
        return None
    return records


def initialize_threat_model_memory(
    config,
    repository: EngineRepository | None = None,
) -> dict[str, Any]:
    service = config.memory_service
    if service is None:
        return {"status": "disabled", "records_written": 0}

    repository = repository or EngineRepository(config, EngineState())
    repo_root = Path(config.codebase_path).expanduser().resolve()
    repo_fp = repo_fingerprint(repo_root)
    threat_config = config.threat_model_config
    supported_extensions = {
        str(extension).lower()
        for extension in (
            config.plugin_config.get("docs", {}).get("supported_extensions", [])
        )
        if str(extension).lower() != ".pdf"
    }
    threat_sources = _find_threat_sources(
        repo_root,
        threat_config,
        supported_extensions=supported_extensions,
        is_metisignored=repository.is_metisignored,
    )
    candidate_records = _build_threat_model_snapshot(
        config,
        service,
        repo_root,
        repo_fp,
        threat_sources,
    )
    records_deleted = 0
    for namespace in (
        (*THREAT_MODEL_NAMESPACE, "authoritative"),
        (*THREAT_MODEL_NAMESPACE, "contracts"),
        (*THREAT_MODEL_NAMESPACE, "history"),
    ):
        replacement = [
            record for record in candidate_records if record.namespace == namespace
        ]
        records_deleted += service.replace_records(namespace, replacement)
    return {
        "status": "ok",
        "records_written": len(candidate_records),
        "records_deleted": records_deleted,
        "authoritative_sources": [
            source.path.relative_to(repo_root).as_posix() for source in threat_sources
        ],
    }


def _build_threat_model_snapshot(
    config,
    service: MemoryService,
    repo_root: Path,
    repo_fp: str,
    threat_sources: list[ThreatSource],
) -> list[MemoryRecord]:
    candidate_service = MemoryService(
        InMemoryStore(),
        repo_root=service.repo_root,
        tool_version=service.tool_version,
    )
    prepared_sources: list[PreparedThreatSource] = []
    for source in threat_sources:
        prepared = _prepare_threat_source(
            config,
            repo_root,
            source,
        )
        if prepared is None:
            raise RuntimeError(
                f"Threat-model source could not be read: "
                f"{source.path.relative_to(repo_root).as_posix()}"
            )
        prepared_sources.append(prepared)
        _write_threat_source_record(
            candidate_service,
            repo_fp,
            prepared,
        )

    claims: list[dict[str, Any]] = []
    for prepared in prepared_sources:
        source_ref = _repo_file_source(
            prepared.rel_path,
            input_fp=prepared.source_fp,
            source_method=prepared.threat_source.source,
        )
        claims.extend(
            {
                **claim,
                "source_refs": [source_ref],
            }
            for claim in prepared.distilled_claims
        )
    _write_authoritative_contract_record(
        candidate_service,
        repo_fp,
        authoritative_claims=_model_reduce_source_claim_group(config, claims),
    )
    write_history_records(
        config,
        candidate_service,
        repo_root,
        repo_fp,
    )
    return list(candidate_service.iter_records(THREAT_MODEL_NAMESPACE))


def _dedupe_scope_clauses(clauses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_key: dict[tuple[str, str, str, tuple[str, ...], str], dict[str, Any]] = {}
    for clause in clauses:
        key = (
            clause["claim_type"],
            clause["disposition"],
            clause["reason"],
            tuple(clause["applies_to"]),
            clause["source_path"],
        )
        by_key.setdefault(key, clause)
    return list(by_key.values())


def _repo_file_source(
    rel_path: str,
    *,
    input_fp: str = "",
    source_method: str = "",
    text_origin: str = "repo_file",
) -> dict[str, Any]:
    source: dict[str, Any] = {
        "kind": "repo_file",
        "uri": f"file:{rel_path}",
        "path": rel_path,
        "display_name": rel_path,
        "content_type": "text/plain",
        "text_origin": text_origin,
    }
    if input_fp:
        source["input_fingerprint"] = input_fp
    if source_method:
        source["source_method"] = source_method
    return source


def _prepare_threat_source(
    config,
    repo_root: Path,
    threat_source: ThreatSource,
) -> PreparedThreatSource | None:
    try:
        text = threat_source.path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    rel_path = threat_source.path.relative_to(repo_root).as_posix()
    distilled_claims = _model_distilled_source_claims(
        config,
        rel_path=rel_path,
        text=text,
    )
    summary = (
        "; ".join(claim["statement"] for claim in distilled_claims)
        or text.strip()
        or f"Authoritative threat model/security guidance from {rel_path}."
    )
    return PreparedThreatSource(
        threat_source=threat_source,
        rel_path=rel_path,
        source_fp=file_fingerprint(threat_source.path),
        distilled_claims=distilled_claims,
        summary=summary,
    )


def _write_threat_source_record(
    service: MemoryService,
    repo_fp: str,
    prepared: PreparedThreatSource,
) -> None:
    source_ref = _repo_file_source(
        prepared.rel_path,
        input_fp=prepared.source_fp,
        source_method=prepared.threat_source.source,
    )
    service.create_record(
        namespace=(*THREAT_MODEL_NAMESPACE, "authoritative"),
        key=prepared.rel_path,
        artifact_type="threat_model_authoritative",
        memory_type="semantic",
        authority="authoritative",
        repo_fingerprint=repo_fp,
        input_fingerprint=prepared.source_fp,
        body_json={
            "distilled_claims": prepared.distilled_claims,
            "source_ref": source_ref,
            "authority": "authoritative",
            "binding": True,
        },
        summary_text=(
            f"Authoritative project policy source {prepared.rel_path}: "
            f"{prepared.summary}"
        ),
        search_text=f"{prepared.rel_path} {prepared.summary}",
        metadata={
            "path": prepared.rel_path,
            "source": source_ref,
            "source_method": prepared.threat_source.source,
            "authority": "authoritative",
            "binding": True,
        },
        source_kind="repo_file",
    )


def _write_authoritative_contract_record(
    service: MemoryService,
    repo_fp: str,
    *,
    authoritative_claims: list[dict[str, Any]],
) -> None:
    if not authoritative_claims:
        return

    clauses: list[dict[str, Any]] = []
    source_refs: list[dict[str, Any]] = []
    claim_summaries: list[str] = []

    for claim in authoritative_claims:
        statement = claim["statement"]
        claim_type = claim["claim_type"]
        disposition = claim["disposition"]
        claim_source_refs = _claim_source_refs(claim)
        claim_summaries.append(f"{claim_type}: {statement}")
        source_refs.extend(claim_source_refs)
        if claim_type not in {
            "scope_rule",
            "caller_contract",
            "analysis_policy",
        } or disposition not in {"out_of_scope", "integration_risk", "advisory"}:
            continue
        source_path = claim_source_refs[0]["path"]
        clauses.append(
            {
                "claim_type": claim_type,
                "disposition": disposition,
                "reason": statement,
                "applies_to": claim["applies_to"],
                "source_authority": "authoritative",
                "binding": True,
                "source_path": source_path,
            }
        )

    clauses = _dedupe_scope_clauses(clauses)

    source_refs = _dedupe_source_refs(source_refs)
    body = {
        "authority": "authoritative",
        "binding": True,
        "scope_clauses": clauses,
        "source_refs": source_refs,
    }
    summary = f"Authoritative threat-model contract: {'; '.join(claim_summaries)}"
    service.create_record(
        namespace=(*THREAT_MODEL_NAMESPACE, "contracts"),
        key="authoritative",
        artifact_type="threat_model_contract",
        memory_type="procedural",
        authority="authoritative",
        repo_fingerprint=repo_fp,
        input_fingerprint=input_fingerprint(body),
        body_json=body,
        summary_text=summary,
        search_text=" ".join(claim_summaries) or summary,
        metadata={
            "authority": "authoritative",
            "binding": True,
            "role": "compiled_contract",
            "scope_clauses": clauses,
            "sources": source_refs,
        },
        source_kind="compiled_contract",
    )


def _dedupe_source_refs(source_refs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for source in source_refs:
        key = (source["kind"], source["path"])
        by_key.setdefault(key, source)
    return list(by_key.values())


def _model_distilled_source_claims(
    config,
    *,
    rel_path: str,
    text: str,
) -> list[dict[str, Any]]:
    llm_provider = config.llm_provider
    model = config.llama_query_model
    if llm_provider is None or not model:
        return []
    evidence_chunks = [
        chunk
        for chunk, _ in split_snippet(
            text,
            int(config.max_token_length),
            llm_provider.count_tokens,
        )
    ]
    if not evidence_chunks:
        return []
    try:
        records: list[dict[str, Any]] = []
        for batch_index, evidence in enumerate(evidence_chunks, start=1):
            logger.info(
                "Distilling threat model source %s batch %d/%d",
                rel_path,
                batch_index,
                len(evidence_chunks),
            )
            batch_records = invoke_langchain_json_prompt_with_retry(
                llm_provider,
                config.usage_runtime,
                model=model,
                system_prompt=_PROMPTS["source_distillation_system"],
                user_prompt=_PROMPTS["source_distillation_user"],
                variables={
                    "path": rel_path,
                    "batch_index": batch_index,
                    "total_batches": len(evidence_chunks),
                    "evidence": evidence,
                },
                parse=lambda raw: _parse_distilled_records(
                    raw,
                    response_model=_ThreatSourceClaimResponseModel,
                ),
                logger=logger,
                label="threat-model source distillation",
                batch_size=1,
                invalid_message="invalid threat-model distillation response",
                final_keep_message="returning no distilled source claims",
                response_model=_ThreatSourceClaimResponseModel,
                temperature=0.0,
                chat_model_kwargs=config.chat_model_kwargs,
            )
            if batch_records is None:
                raise RuntimeError("distillation returned no valid response")
            records.extend(batch_records)
    except Exception as exc:
        logger.warning(
            "Threat-model source distillation failed for %s: %s", rel_path, exc
        )
        raise RuntimeError(
            f"Threat-model source distillation failed for {rel_path}: {exc}"
        ) from exc
    return _dedupe_distilled_claims(records)


def _model_reduce_source_claim_group(
    config,
    claims: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    claims = _dedupe_distilled_claims(claims)
    if not claims:
        return []
    evidence = _source_claim_reduce_evidence(claims)
    llm_provider = config.llm_provider
    model = config.llama_query_model
    if llm_provider is None or not model:
        return claims
    try:
        records = invoke_langchain_json_prompt_with_retry(
            llm_provider,
            config.usage_runtime,
            model=model,
            system_prompt=_PROMPTS["source_reduction_system"],
            user_prompt=_PROMPTS["source_reduction_user"],
            variables={"evidence": evidence},
            parse=lambda raw: _parse_distilled_records(
                raw,
                response_model=_ThreatSourceClaimReductionResponseModel,
            ),
            logger=logger,
            label="threat-model source claim deduplication",
            batch_size=len(claims),
            invalid_message="invalid threat-model source claim deduplication response",
            final_keep_message="keeping unreduced source claims",
            response_model=_ThreatSourceClaimReductionResponseModel,
            temperature=0.0,
            chat_model_kwargs=config.chat_model_kwargs,
        )
    except Exception as exc:
        logger.warning("Threat-model source claim deduplication failed: %s", exc)
        return claims

    if not records:
        return claims

    referenced_indexes = {
        index for record in records for index in record["source_claim_indexes"]
    }
    if referenced_indexes != set(range(len(claims))):
        logger.warning(
            "Threat-model source claim deduplication returned incomplete provenance; "
            "keeping unreduced source claims"
        )
        return claims

    reduced: list[dict[str, Any]] = []
    for record in records:
        applies_to = list(record["applies_to"])
        source_refs = []
        for index in record["source_claim_indexes"]:
            claim = claims[index]
            applies_to.extend(claim["applies_to"])
            source_refs.extend(_claim_source_refs(claim))
        reduced.append(
            {
                "claim_type": record["claim_type"],
                "statement": record["statement"],
                "applies_to": list(dict.fromkeys(applies_to)),
                "disposition": record["disposition"],
                "source_refs": _dedupe_source_refs(source_refs),
            }
        )
    return _dedupe_distilled_claims(reduced)


def _source_claim_reduce_evidence(claims: list[dict[str, Any]]) -> str:
    return json.dumps(
        [
            {
                "index": index,
                "claim_type": claim["claim_type"],
                "disposition": claim["disposition"],
                "applies_to": claim["applies_to"],
                "statement": claim["statement"],
            }
            for index, claim in enumerate(claims)
        ],
        separators=(",", ":"),
    )


def _find_threat_sources(
    repo_root: Path,
    threat_config: dict[str, Any],
    *,
    supported_extensions: set[str],
    is_metisignored: Callable[[str], bool],
) -> list[ThreatSource]:
    resolved_paths: set[Path] = set()
    for pattern in string_list(threat_config.get("source_patterns")):
        pattern_path = Path(pattern)
        suffix = pattern_path.suffix.lower()
        if suffix and not has_magic(suffix) and suffix not in supported_extensions:
            continue
        if pattern_path.is_absolute():
            try:
                pattern_path = pattern_path.relative_to(repo_root)
            except ValueError:
                continue
        if ".." in pattern_path.parts:
            continue
        for path in repo_root.glob(pattern_path.as_posix()):
            resolved = _safe_repo_path(repo_root, path)
            if (
                resolved is None
                or resolved.suffix.lower() not in supported_extensions
                or is_metisignored(str(resolved))
            ):
                continue
            resolved_paths.add(resolved)

    return [
        ThreatSource(path=resolved, source="configured_pattern")
        for resolved in sorted(
            resolved_paths,
            key=lambda path: path.relative_to(repo_root).as_posix(),
        )
    ]


def _claim_source_refs(claim: dict[str, Any]) -> list[dict[str, Any]]:
    return list(claim.get("source_refs") or [])


def _dedupe_distilled_claims(claims: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: list[dict[str, Any]] = []
    by_key: dict[tuple[str, str, str], dict[str, Any]] = {}
    for claim in claims:
        statement = claim["statement"]
        key = (
            " ".join(statement.casefold().split()),
            claim["claim_type"],
            claim["disposition"],
        )
        existing = by_key.get(key)
        if existing is None:
            existing = dict(claim)
            by_key[key] = existing
            deduped.append(existing)
            continue
        existing["applies_to"] = list(
            dict.fromkeys([*existing["applies_to"], *claim["applies_to"]])
        )
        source_refs = _dedupe_source_refs(
            [*_claim_source_refs(existing), *_claim_source_refs(claim)]
        )
        if not source_refs:
            continue
        existing["source_refs"] = source_refs
    return deduped


def _safe_repo_path(
    repo_root: Path,
    path: Path,
) -> Path | None:
    if path.is_symlink():
        return None
    try:
        resolved = resolve_path_within_root(repo_root, path)
    except (OSError, ValueError):
        return None
    return resolved if resolved.is_file() else None
