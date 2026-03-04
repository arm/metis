# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

from metis.engine.graphs.types import TriageRequest
from metis.sarif.triage import (
    apply_triage_result,
    extract_findings,
    load_sarif_file,
    save_sarif_file,
)

logger = logging.getLogger("metis")


class TriageServiceExecutionMixin:
    def _emit_triage_progress(
        self, progress_callback, total: int, event: str, **kwargs
    ):
        if not callable(progress_callback):
            return
        try:
            progress_callback({"event": event, "total": total, **kwargs})
        except Exception:
            pass

    def _run_triage_checkpoint(
        self,
        checkpoint_callback,
        triaged_payload: dict,
        processed: int,
        total: int,
    ) -> None:
        if not callable(checkpoint_callback):
            return
        try:
            checkpoint_callback(triaged_payload, processed, total)
        except Exception:
            pass

    def _build_triage_request(
        self,
        *,
        finding,
        retriever_code,
        retriever_docs,
        debug_callback,
    ) -> TriageRequest:
        analyzer = self._get_thread_triage_analyzer(finding.file_path)
        return {
            "finding_message": finding.message,
            "finding_file_path": finding.file_path,
            "finding_line": finding.line,
            "finding_rule_id": finding.rule_id,
            "finding_snippet": finding.snippet,
            "retriever_code": retriever_code,
            "retriever_docs": retriever_docs,
            "debug_callback": debug_callback,
            "triage_analyzer": analyzer,
            "triage_codebase_path": self.codebase_path,
        }

    def _triage_one_finding(
        self,
        finding,
        *,
        debug_callback,
    ) -> dict:
        retriever_code, retriever_docs = self._get_thread_triage_query_engines()
        req = self._build_triage_request(
            finding=finding,
            retriever_code=retriever_code,
            retriever_docs=retriever_docs,
            debug_callback=debug_callback,
        )
        return self._get_thread_triage_graph().triage(req)

    def _record_triage_success(self, triaged_payload: dict, finding, decision: dict):
        apply_triage_result(
            triaged_payload,
            run_index=finding.run_index,
            result_index=finding.result_index,
            status=decision["status"],
            reason=decision["reason"],
        )

    def _record_triage_failure(self, finding, exc):
        logger.warning(
            "Skipping triage annotation for run=%s result=%s due to failure: %s",
            finding.run_index,
            finding.result_index,
            exc,
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
    ) -> int:
        if error is not None:
            self._record_triage_failure(finding, error)
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
        return processed

    def _triage_findings_sequential(
        self,
        *,
        findings,
        triaged_payload: dict,
        total: int,
        progress_callback,
        debug_callback,
        checkpoint_callback,
        processed: int,
    ) -> int:
        for idx, finding in enumerate(findings, start=1):
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
                    debug_callback=debug_callback,
                )
            except Exception as exc:
                processed = self._handle_finding_result(
                    triaged_payload=triaged_payload,
                    finding=finding,
                    total=total,
                    idx=idx,
                    decision=None,
                    error=exc,
                    progress_callback=progress_callback,
                    checkpoint_callback=checkpoint_callback,
                    processed=processed,
                )
                continue

            processed = self._handle_finding_result(
                triaged_payload=triaged_payload,
                finding=finding,
                total=total,
                idx=idx,
                decision=decision,
                error=None,
                progress_callback=progress_callback,
                checkpoint_callback=checkpoint_callback,
                processed=processed,
            )
        return processed

    def _triage_findings_parallel(
        self,
        *,
        findings,
        triaged_payload: dict,
        total: int,
        progress_callback,
        debug_callback,
        checkpoint_callback,
        processed: int,
    ) -> int:
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
                future = executor.submit(
                    self._triage_one_finding,
                    finding,
                    debug_callback=debug_callback,
                )
                future_map[future] = (idx, finding)

            for future in as_completed(future_map):
                idx, finding = future_map[future]
                try:
                    decision = future.result()
                except Exception as exc:
                    processed = self._handle_finding_result(
                        triaged_payload=triaged_payload,
                        finding=finding,
                        total=total,
                        idx=idx,
                        decision=None,
                        error=exc,
                        progress_callback=progress_callback,
                        checkpoint_callback=checkpoint_callback,
                        processed=processed,
                    )
                    continue

                processed = self._handle_finding_result(
                    triaged_payload=triaged_payload,
                    finding=finding,
                    total=total,
                    idx=idx,
                    decision=decision,
                    error=None,
                    progress_callback=progress_callback,
                    checkpoint_callback=checkpoint_callback,
                    processed=processed,
                )
        return processed

    def triage_sarif_payload(
        self,
        payload: dict,
        progress_callback=None,
        debug_callback=None,
        checkpoint_callback=None,
        include_triaged: bool = False,
    ) -> dict:
        triaged = payload
        findings = extract_findings(triaged, include_triaged=include_triaged)
        if not findings:
            return triaged

        total = len(findings)
        processed = 0

        if total <= 1 or self.max_workers <= 1:
            try:
                self._get_thread_triage_query_engines()
            except Exception as exc:
                logger.warning(
                    "Skipping triage annotations due to initialization failure: %s",
                    exc,
                )
                return triaged
            self._triage_findings_sequential(
                findings=findings,
                triaged_payload=triaged,
                total=total,
                progress_callback=progress_callback,
                debug_callback=debug_callback,
                checkpoint_callback=checkpoint_callback,
                processed=processed,
            )
            return triaged

        self._triage_findings_parallel(
            findings=findings,
            triaged_payload=triaged,
            total=total,
            progress_callback=progress_callback,
            debug_callback=debug_callback,
            checkpoint_callback=checkpoint_callback,
            processed=processed,
        )

        return triaged

    def triage_sarif_file(
        self,
        input_path: str,
        output_path: str | None = None,
        progress_callback=None,
        debug_callback=None,
        checkpoint_every: int | None = None,
        include_triaged: bool = False,
    ) -> str:
        payload = load_sarif_file(input_path)
        target_path = output_path or input_path

        every = checkpoint_every
        if every is None:
            every = self.triage_checkpoint_every
        try:
            every = int(every)
        except Exception:
            every = 0
        if every < 1:
            every = 0

        def _checkpoint(triaged_payload: dict, processed: int, total: int):
            if every <= 0:
                return
            if processed >= total:
                return
            if processed % every != 0:
                return
            save_sarif_file(target_path, triaged_payload)

        triaged = self.triage_sarif_payload(
            payload,
            progress_callback=progress_callback,
            debug_callback=debug_callback,
            checkpoint_callback=_checkpoint,
            include_triaged=include_triaged,
        )
        save_sarif_file(target_path, triaged)
        return target_path
