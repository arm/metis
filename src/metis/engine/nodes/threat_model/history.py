# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import logging
import subprocess
from collections import deque
from pathlib import Path
from typing import Any

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field

from metis.engine.llm_runner import invoke_langchain_json_prompt_with_retry
from metis.engine.llm_runner import rendered_prompt_token_count
from metis.engine.model_tool_runner import ModelInputLimitError
from metis.engine.prompt_catalog import get_engine_prompts
from metis.memory import MemoryService
from metis.memory.fingerprints import input_fingerprint

from .parsing import parse_records

logger = logging.getLogger("metis")
_PROMPTS = get_engine_prompts(
    "threat_context",
    required=("history_distillation_system", "history_distillation_user"),
)


class _HistoryLessonModel(BaseModel):
    statement: str = Field(min_length=1, max_length=240)
    applies_to: list[str] = Field(min_length=1)
    source_commit_indexes: list[int] = Field(min_length=1)

    model_config = ConfigDict(extra="forbid")


class _HistoryLessonResponseModel(BaseModel):
    records: list[_HistoryLessonModel]

    model_config = ConfigDict(extra="forbid")


def write_history_records(
    config,
    service: MemoryService,
    repo_root: Path,
    repo_fp: str,
) -> None:
    history_config = config.threat_model_config.get("history")
    if (
        not isinstance(history_config, dict)
        or history_config.get("enabled") is not True
    ):
        return

    commits = _git_history(repo_root, int(history_config["max_commits"]))
    if not commits:
        return
    lessons = _distill_history(config, commits)
    for index, lesson in enumerate(lessons):
        source_commits = [commits[item] for item in lesson["source_commit_indexes"]]
        body = {
            "statement": lesson["statement"],
            "applies_to": lesson["applies_to"],
            "source_commits": source_commits,
        }
        service.create_record(
            namespace=("repo", "threat_model", "history"),
            key=f"lesson:{index}",
            artifact_type="threat_model_history_lesson",
            memory_type="episodic",
            authority="history_derived",
            repo_fingerprint=repo_fp,
            input_fingerprint=input_fingerprint(body),
            body_json=body,
            summary_text=lesson["statement"],
            search_text=" ".join(
                [
                    lesson["statement"],
                    *lesson["applies_to"],
                ]
            ),
            metadata={
                "applies_to": lesson["applies_to"],
            },
            source_kind="git_history",
        )


def _git_history(repo_root: Path, max_commits: int) -> list[dict[str, Any]]:
    result = subprocess.run(
        [
            "git",
            "log",
            "-n",
            str(max_commits),
            "--format=%x1e%H%x1f%cs%x1f%B%x1d",
            "--name-only",
        ],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )

    commits = []
    for entry in result.stdout.split("\x1e"):
        metadata, separator, path_text = entry.strip().partition("\x1d")
        if not separator:
            continue
        fields = metadata.split("\x1f", 2)
        if len(fields) != 3:
            continue
        commits.append(
            {
                "commit": fields[0],
                "date": fields[1],
                "message": fields[2].strip(),
                "paths": [line for line in path_text.splitlines() if line],
            }
        )
    return commits


def _distill_history(config, commits: list[dict[str, Any]]) -> list[dict[str, Any]]:
    llm_provider = config.llm_provider
    model = config.llama_query_model
    if llm_provider is None or not model:
        raise RuntimeError("Git-history distillation requires an LLM")

    evidence_records = [
        {
            "index": index,
            "date": commit["date"],
            "message": commit["message"],
            "paths": commit["paths"],
        }
        for index, commit in enumerate(commits)
    ]
    batches = deque([evidence_records] if evidence_records else [])
    lessons: list[dict[str, Any]] = []
    while batches:
        batch = batches.popleft()
        evidence = "\n".join(
            json.dumps(record, separators=(",", ":")) for record in batch
        )
        if (
            rendered_prompt_token_count(
                lambda value: llm_provider.count_tokens(value, model=model),
                system_prompt=_PROMPTS["history_distillation_system"],
                user_prompt=_PROMPTS["history_distillation_user"],
                variables={"evidence": evidence},
            )
            > config.max_token_length
        ):
            if len(batch) > 1:
                midpoint = len(batch) // 2
                batches.extendleft(reversed([batch[:midpoint], batch[midpoint:]]))
                continue
            record = batch[0]
            message = record["message"]
            paths = record["paths"]
            if message and paths:
                parts = [{**record, "paths": []}, {**record, "message": ""}]
            elif len(message) > 1:
                midpoint = len(message) // 2
                parts = [
                    {**record, "message": message[:midpoint]},
                    {**record, "message": message[midpoint:]},
                ]
            elif len(paths) > 1:
                midpoint = len(paths) // 2
                parts = [
                    {**record, "paths": paths[:midpoint]},
                    {**record, "paths": paths[midpoint:]},
                ]
            else:
                raise ModelInputLimitError(
                    "Git-history prompt cannot hold one commit fragment"
                )
            batches.extendleft([part] for part in reversed(parts))
            continue
        supplied_indexes = {record["index"] for record in batch}
        records = invoke_langchain_json_prompt_with_retry(
            llm_provider,
            config.usage_runtime,
            model=model,
            system_prompt=_PROMPTS["history_distillation_system"],
            user_prompt=_PROMPTS["history_distillation_user"],
            variables={"evidence": evidence},
            parse=_parse_history_lessons,
            logger=logger,
            label="git-history threat-model distillation",
            batch_size=1,
            invalid_message="invalid git-history distillation response",
            final_keep_message="returning no git-history lessons",
            response_model=_HistoryLessonResponseModel,
            max_input_tokens=int(config.max_token_length),
            chat_model_kwargs=config.chat_model_kwargs,
        )
        if records is None:
            raise RuntimeError("Git-history distillation returned no valid response")
        if any(
            not set(record["source_commit_indexes"]) <= supplied_indexes
            for record in records
        ):
            raise RuntimeError(
                "Git-history distillation returned unsupported provenance"
            )
        lessons.extend(records)
    return _dedupe_history_lessons(lessons)


def _parse_history_lessons(raw: Any) -> list[dict[str, Any]] | None:
    return parse_records(raw, response_model=_HistoryLessonResponseModel)


def _dedupe_history_lessons(
    lessons: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    deduped: dict[str, dict[str, Any]] = {}
    for lesson in lessons:
        indexes = lesson["source_commit_indexes"]
        key = lesson["statement"].casefold()
        existing = deduped.get(key)
        if existing is None:
            deduped[key] = {
                **lesson,
                "applies_to": list(lesson["applies_to"]),
                "source_commit_indexes": list(indexes),
            }
            continue
        existing["applies_to"] = list(
            dict.fromkeys(existing["applies_to"] + lesson["applies_to"])
        )
        existing["source_commit_indexes"] = list(
            dict.fromkeys(existing["source_commit_indexes"] + indexes)
        )
    return list(deduped.values())
