# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
from typing import cast

from metis.engine.stages.triage.models import TriageRun
from metis.memory import MemoryService
from metis.engine.threat_context_retrieval import get_threat_model_context
from metis.engine.threat_context_retrieval import threat_model_scope_policy
from metis.engine.threat_context_retrieval import threat_model_triage_override
from metis.sarif.models import SarifPayload
from metis.sarif.triage import (
    apply_triage_result,
    save_sarif_file,
)
from metis.usage import submit_with_current_context

from .contracts import TriageClassifier
from .contracts import TriageDecision

logger = logging.getLogger("metis")


class TriageService:
    def __init__(
        self,
        *,
        max_workers: int,
        triage_checkpoint_every: int,
    ) -> None:
        self.max_workers = max(1, max_workers)
        self.triage_checkpoint_every = triage_checkpoint_every

    def _invoke_callback(self, callback, *args, **kwargs) -> None:
        if not callable(callback):
            return
        try:
            callback(*args, **kwargs)
        except Exception:
            pass

    def _emit_triage_progress(
        self, progress_callback, total: int, event: str, **kwargs
    ):
        self._invoke_callback(
            progress_callback, {"event": event, "total": total, **kwargs}
        )

    def _run_triage_checkpoint(
        self,
        checkpoint_callback,
        triaged_payload: dict,
        processed: int,
        total: int,
    ) -> None:
        self._invoke_callback(checkpoint_callback, triaged_payload, processed, total)

    def _triage_one_finding(
        self,
        finding,
        *,
        classifier: TriageClassifier,
        debug_callback,
        memory_service: MemoryService | None,
    ) -> TriageDecision | None:
        threat_model_context = get_threat_model_context(
            memory_service,
            path=finding.file_path,
        )
        policy = threat_model_scope_policy(
            threat_model_context,
            path=finding.file_path,
        )
        override = threat_model_triage_override(policy)
        if override is not None:
            return cast(TriageDecision, override)
        return classifier(finding, threat_model_context, debug_callback)

    def _record_triage_success(self, triaged_payload: dict, finding, decision: dict):
        apply_triage_result(
            triaged_payload,
            run_index=finding.run_index,
            result_index=finding.result_index,
            status=decision["status"],
            reason=decision["reason"],
            metadata={
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
        self._run_triage_checkpoint(
            checkpoint_callback, triaged_payload, processed, total
        )
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
        memory_service: MemoryService | None,
        processed: int,
    ) -> tuple[int, set[tuple[int, int]]]:
        handled: set[tuple[int, int]] = set()
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_map = {}
            for idx, finding in enumerate(findings, start=1):
                self._emit_triage_progress(
                    progress_callback,
                    total,
                    "start",
                    index=idx,
                    finding=finding,
                )
                future = submit_with_current_context(
                    executor,
                    self._triage_one_finding,
                    finding,
                    classifier=classifier,
                    debug_callback=debug_callback,
                    memory_service=memory_service,
                )
                future_map[future] = (idx, finding)

            for future in as_completed(future_map):
                idx, finding = future_map[future]
                try:
                    decision = future.result()
                    error = None
                except Exception as exc:
                    decision = None
                    error = exc
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
                if was_handled:
                    handled.add((finding.run_index, finding.result_index))
        return processed, handled

    def triage_run(
        self,
        run: TriageRun,
        *,
        classifier: TriageClassifier,
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
            if every <= 0:
                return
            if processed >= total:
                return
            if processed % every != 0:
                return
            save_sarif_file(target_path, triaged_payload)

        return checkpoint
