# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import CancelledError
import logging
from pathlib import Path
import sqlite3
from typing import cast

from metis.engine.stages.triage.models import TriageRun
from metis.engine.execution.contracts import NodeJobs
from metis.memory import MemoryService
from metis.engine.threat_context_retrieval import get_threat_model_context
from metis.engine.threat_context_retrieval import threat_model_scope_policy
from metis.engine.threat_context_retrieval import threat_model_triage_override
from metis.sarif.models import SarifPayload
from metis.sarif.triage import (
    apply_triage_result,
    save_sarif_file,
)
from metis.sarif.utils import create_fingerprint
from metis.generated_artifacts import generated_artifact_publication
from metis import runlog
from metis.utils import resolve_path_within_root


from .contracts import TriageClassifier
from .contracts import TriageDecision

logger = logging.getLogger("metis")


class TriageService:
    def __init__(
        self,
        *,
        triage_checkpoint_every: int,
    ) -> None:
        self.triage_checkpoint_every = triage_checkpoint_every

    def _invoke_callback(self, callback, *args, **kwargs) -> None:
        if not callable(callback):
            return
        try:
            callback(*args, **kwargs)
        except CancelledError:
            raise
        except Exception:
            pass

    def _emit_triage_progress(
        self, progress_callback, total: int, event: str, **kwargs
    ):
        self._invoke_callback(
            progress_callback, {"event": event, "total": total, **kwargs}
        )

    def _triage_one_finding(
        self,
        finding,
        *,
        classifier: TriageClassifier,
        debug_callback,
        memory_service: MemoryService | None,
    ) -> TriageDecision | None:
        fingerprint = create_fingerprint(
            finding.file_path, finding.line, finding.rule_id
        )
        finding_id = (
            f"sarif:{finding.run_index}:{finding.result_index}:{fingerprint[:12]}"
        )
        with runlog.span(
            "task",
            "triage_finding",
            {
                "kind": "triage_finding",
                "finding_id": finding_id,
                "sarif": {
                    "run_index": finding.run_index,
                    "result_index": finding.result_index,
                },
                "fingerprint": fingerprint,
                "file_path": finding.file_path,
                "line": finding.line,
                "rule_id": finding.rule_id,
                "message": finding.message,
            },
        ) as task_span:
            runlog.bump("tasks")
            with runlog.span(
                "threat_context",
                "scope_policy",
                {"path": finding.file_path},
            ) as context_span:
                context_path = finding.file_path
                context_memory = memory_service
                if (
                    context_memory is not None
                    and context_memory.repo_root
                    and context_path
                ):
                    root = Path(context_memory.repo_root).expanduser().absolute()
                    try:
                        context_path = (
                            resolve_path_within_root(
                                root, root / context_path, preserve_aliases=True
                            )
                            .relative_to(root)
                            .as_posix()
                        )
                    except (OSError, RuntimeError, ValueError):
                        context_memory = None
                threat_model_context = get_threat_model_context(
                    context_memory,
                    path=context_path,
                )
                policy = threat_model_scope_policy(
                    threat_model_context,
                    path=context_path,
                )
                override = threat_model_triage_override(policy)
                context_span.end(
                    attributes={
                        "records": threat_model_context,
                        "policy": policy,
                        "override": override,
                    }
                )
            if override is not None:
                runlog.event(
                    "decision",
                    {
                        "kind": "threat_model_override",
                        "finding_id": finding_id,
                        "decision": override,
                    },
                )
                decision = cast(TriageDecision, override)
            else:
                decision = classifier(
                    finding,
                    threat_model_context,
                    debug_callback,
                )
            if decision is not None:
                runlog.event(
                    "artifact",
                    {
                        "kind": "triage_decision",
                        "finding_id": finding_id,
                        "payload": decision,
                    },
                )
            task_span.end(
                status=(
                    "inconclusive"
                    if decision is None or decision.get("status") == "inconclusive"
                    else "ok"
                ),
                attributes={"decision": decision},
            )
            return decision

    def _record_triage_success(self, triaged_payload: dict, finding, decision: dict):
        apply_triage_result(
            triaged_payload,
            run_index=finding.run_index,
            result_index=finding.result_index,
            status=decision["status"],
            reason=decision["reason"],
            metadata={
                "evidence": decision.get("evidence"),
                "resolution_chain": decision.get("resolution_chain"),
                "unresolved_hops": decision.get("unresolved_hops"),
                "decision_source": decision.get(
                    "decision_source",
                    "policy" if "threat_model_policy" in decision else None,
                ),
                "validation_errors": decision.get("validation_errors"),
                "evidence_requirements": decision.get("evidence_obligations"),
                "evidence_coverage": decision.get("evidence_coverage"),
                "missing_evidence": decision.get("missing_evidence"),
                "threat_model_policy": decision.get("threat_model_policy"),
            },
        )

    def _record_triage_failure(self, triaged_payload: dict, finding, exc):
        logger.warning(
            "Marking triage inconclusive for run=%s result=%s due to failure: %s",
            finding.run_index,
            finding.result_index,
            exc,
        )
        apply_triage_result(
            triaged_payload,
            run_index=finding.run_index,
            result_index=finding.result_index,
            status="inconclusive",
            reason=f"Triage failed before a decision could be produced: {exc}",
            metadata={
                "decision_source": "execution_failure",
                "validation_errors": ["triage execution failed"],
                "evidence_requirements": ["triage_execution"],
                "evidence_coverage": {"triage_execution": 0},
                "missing_evidence": ["triage execution failed"],
            },
        )

    def _handle_finding_result(
        self,
        *,
        triaged_payload: dict,
        finding,
        total: int,
        idx: int,
        decision: dict | None,
        error: Exception | None,
        progress_callback,
        checkpoint_callback,
        processed: int,
    ) -> tuple[int, bool]:
        if decision is None and error is None:
            return processed, False
        if error is not None:
            self._record_triage_failure(triaged_payload, finding, error)
            self._emit_triage_progress(
                progress_callback,
                total,
                "error",
                index=idx,
                finding=finding,
                error=str(error),
            )
        else:
            self._record_triage_success(triaged_payload, finding, decision or {})
            self._emit_triage_progress(
                progress_callback,
                total,
                "done",
                index=idx,
                finding=finding,
                decision=decision,
            )

        processed += 1
        self._invoke_callback(checkpoint_callback, triaged_payload, processed, total)
        return processed, True

    def _triage_findings_parallel(
        self,
        *,
        findings,
        triaged_payload: dict,
        total: int,
        progress_callback,
        debug_callback,
        checkpoint_callback,
        classifier: TriageClassifier,
        jobs: NodeJobs,
        memory_service: MemoryService | None,
        processed: int,
    ) -> tuple[int, set[tuple[int, int]]]:
        handled: set[tuple[int, int]] = set()
        scheduled = list(enumerate(findings, start=1))
        outcomes: dict[int, tuple] = {}
        progress_base = processed

        def invoke(item):
            idx, finding = item
            self._emit_triage_progress(
                progress_callback,
                total,
                "start",
                index=idx,
                finding=finding,
            )
            try:
                decision = self._triage_one_finding(
                    finding,
                    classifier=classifier,
                    debug_callback=debug_callback,
                    memory_service=memory_service,
                )
                outcome = idx, finding, decision, None
            except CancelledError:
                raise
            except Exception as exc:
                outcome = idx, finding, None, exc
            outcomes[idx] = outcome
            return outcome

        def report_completion(item, completed: int, _scheduled_total: int) -> None:
            nonlocal processed
            self._emit_triage_progress(
                progress_callback,
                total,
                "progress",
                completed=progress_base + completed,
            )
            idx, finding = item
            outcome = outcomes.get(idx)
            if outcome is None:
                return
            _idx, _finding, decision, error = outcome
            processed, was_handled = self._handle_finding_result(
                triaged_payload=triaged_payload,
                finding=finding,
                total=total,
                idx=idx,
                decision=decision,
                error=error,
                progress_callback=progress_callback,
                checkpoint_callback=checkpoint_callback,
                processed=processed,
            )
            outcomes.pop(idx, None)
            if was_handled:
                handled.add((finding.run_index, finding.result_index))

        failure: BaseException | None = None
        try:
            jobs.run(
                scheduled,
                invoke,
                label=None,
                result_key=lambda item: item[0],
                on_complete=report_completion,
            )
        except BaseException as exc:
            failure = exc
            raise
        finally:
            try:
                for idx, finding, decision, error in tuple(outcomes.values()):
                    processed, was_handled = self._handle_finding_result(
                        triaged_payload=triaged_payload,
                        finding=finding,
                        total=total,
                        idx=idx,
                        decision=decision,
                        error=error,
                        progress_callback=None,
                        checkpoint_callback=None,
                        processed=processed,
                    )
                    if was_handled:
                        handled.add((finding.run_index, finding.result_index))
                if processed > progress_base and (
                    processed < total or failure is not None
                ):
                    self._invoke_callback(
                        checkpoint_callback, triaged_payload, processed, processed
                    )
            except BaseException as checkpoint_error:
                if failure is None:
                    raise
                logger.warning(
                    "Unable to checkpoint completed triage decisions: %s",
                    checkpoint_error,
                )
        return processed, handled

    def triage_run(
        self,
        run: TriageRun,
        *,
        classifier: TriageClassifier,
        jobs: NodeJobs,
        memory_service: MemoryService | None = None,
        progress_callback=None,
        debug_callback=None,
        checkpoint_callback=None,
    ) -> TriageRun:
        if not run.remaining:
            return run

        triaged_payload = run.sarif.model_dump(mode="json", by_alias=True)
        processed, handled = self._triage_findings_parallel(
            findings=run.remaining,
            triaged_payload=triaged_payload,
            total=run.total,
            progress_callback=progress_callback,
            debug_callback=debug_callback,
            checkpoint_callback=checkpoint_callback,
            classifier=classifier,
            jobs=jobs,
            memory_service=memory_service,
            processed=run.processed,
        )
        remaining = tuple(
            finding
            for finding in run.remaining
            if (finding.run_index, finding.result_index) not in handled
        )
        return TriageRun(
            sarif=SarifPayload.model_validate(triaged_payload),
            remaining=remaining,
            total=run.total,
            processed=processed,
        )

    def checkpoint_callback(
        self,
        target_path: str,
        *,
        checkpoint_every: int | None = None,
        codebase_path: str | None = None,
    ) -> Callable[[dict, int, int], None]:
        every = checkpoint_every
        if every is None:
            every = self.triage_checkpoint_every
        try:
            every = int(every)
        except (TypeError, ValueError):
            every = 0
        if every < 1:
            every = 0

        def checkpoint(triaged_payload: dict, processed: int, total: int) -> None:
            if every <= 0 or processed <= 0:
                return
            if processed < total and processed % every != 0:
                return
            try:
                with generated_artifact_publication(codebase_path, target_path):
                    save_sarif_file(target_path, triaged_payload)
            except (OSError, TypeError, ValueError, sqlite3.Error) as exc:
                logger.error(
                    "Unable to save triage checkpoint %s: %s", target_path, exc
                )

        return checkpoint
