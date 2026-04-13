# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

from metis.engine.options import TriageOptions, coerce_triage_options
from metis.engine.graphs.types import TriageRequest
from metis.sarif.triage import (
    apply_triage_result,
    extract_findings,
    load_sarif_file,
    save_sarif_file,
)
from metis.usage import submit_with_current_context

logger = logging.getLogger("metis")


class TriageServiceExecutionMixin:
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

    def _build_triage_request(
        self,
        *,
        finding,
        retriever_code,
        retriever_docs,
        debug_callback,
        options: TriageOptions,
    ) -> TriageRequest:
        analyzer = self._get_thread_triage_analyzer(finding.file_path)
        return {
            "finding_message": finding.message,
            "finding_file_path": finding.file_path,
            "finding_line": finding.line,
            "finding_rule_id": finding.rule_id,
            "finding_snippet": finding.snippet,
            "finding_source_tool": getattr(finding, "source_tool", ""),
            "finding_is_metis": bool(getattr(finding, "is_metis_source", False)),
            "finding_explanation": getattr(finding, "explanation", ""),
            "retriever_code": retriever_code,
            "retriever_docs": retriever_docs,
            "debug_callback": debug_callback,
            "triage_analyzer": analyzer,
            "triage_codebase_path": self.codebase_path,
            "use_retrieval_context": options.use_retrieval_context,
        }

    def _triage_one_finding(
        self,
        finding,
        *,
        debug_callback,
        options: TriageOptions,
    ) -> dict:
        retriever_code = retriever_docs = None
        if options.use_retrieval_context:
            retriever_code, retriever_docs = self._get_thread_triage_query_engines()
        req = self._build_triage_request(
            finding=finding,
            retriever_code=retriever_code,
            retriever_docs=retriever_docs,
            debug_callback=debug_callback,
            options=options,
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

    def _triage_findings_parallel(
        self,
        *,
        findings,
        triaged_payload: dict,
        total: int,
        progress_callback,
        debug_callback,
        checkpoint_callback,
        options: TriageOptions,
    ) -> None:
        processed = 0
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
                    debug_callback=debug_callback,
                    options=options,
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
                processed = self._handle_finding_result(
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

    def triage_sarif_payload(
        self,
        payload: dict,
        progress_callback=None,
        debug_callback=None,
        checkpoint_callback=None,
        options: TriageOptions | None = None,
        include_triaged: bool | None = None,
        use_retrieval_context: bool | None = None,
    ) -> dict:
        options = coerce_triage_options(
            options,
            include_triaged=include_triaged,
            use_retrieval_context=use_retrieval_context,
        )
        triaged = payload
        findings = extract_findings(
            triaged,
            include_triaged=options.include_triaged,
        )
        if not findings:
            return triaged

        total = len(findings)

        if options.use_retrieval_context:
            self._get_thread_triage_query_engines()

        self._triage_findings_parallel(
            findings=findings,
            triaged_payload=triaged,
            total=total,
            progress_callback=progress_callback,
            debug_callback=debug_callback,
            checkpoint_callback=checkpoint_callback,
            options=options,
        )

        return triaged

    def triage_sarif_file(
        self,
        input_path: str,
        output_path: str | None = None,
        progress_callback=None,
        debug_callback=None,
        checkpoint_every: int | None = None,
        options: TriageOptions | None = None,
        include_triaged: bool | None = None,
        use_retrieval_context: bool | None = None,
    ) -> str:
        options = coerce_triage_options(
            options,
            include_triaged=include_triaged,
            use_retrieval_context=use_retrieval_context,
        )
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
            options=options,
        )
        save_sarif_file(target_path, triaged)
        return target_path
