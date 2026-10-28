# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory

from metis.json_io import load_json_object_file
from metis.json_io import write_json_atomic
from metis.sarif.models import SarifPayload
from metis.sarif.writer import generate_sarif

from .review.models import PatchReviewResult
from .review.models import StandardReviewResult
from .review.storage import ReviewOutput
from .triage.storage import TriageStore


class StreamingOutput:
    """Run-owned output descriptors shared by producers, consumers, and exporters."""

    def __init__(
        self, codebase_path, stages, *, review_path=None, triage_path=None, source=None
    ):
        review_path = Path(review_path) if review_path is not None else None
        triage_path = Path(triage_path) if triage_path is not None else None
        self._directory = TemporaryDirectory(prefix="metis-output-")
        self.directory = Path(self._directory.name)
        self.codebase_path = codebase_path
        self.stages = stages
        self.materialize = review_path is None and triage_path is None
        if review_path is None and triage_path is not None:
            review_path = triage_path.with_suffix(".review.json")
        if triage_path is None and review_path is not None:
            triage_path = review_path.with_suffix(".triage.sarif")
        self.review_path = (
            review_path if review_path is not None else self.directory / "review.json"
        )
        self.triage_path = (
            triage_path if triage_path is not None else self.directory / "triage.sarif"
        )
        self.source = source
        self.review = None
        self.triage = None
        self.include_triaged = False

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        try:
            if self.triage is not None:
                self.triage.close()
        finally:
            try:
                if self.review is not None:
                    self.review.close()
            finally:
                self._directory.cleanup()

    def open_review(self, request, files):
        if "review" not in self.stages:
            return None
        self.review = ReviewOutput(
            self.review_path, files, mode=request.mode, codebase_path=self.codebase_path
        )
        return self.review

    def open_triage(self, payload, include_triaged):
        if "triage" not in self.stages:
            return None
        self.include_triaged = include_triaged
        source = self.source
        if source is None:
            if self.review is not None:
                source = self.review_path
            else:
                source = self.directory / "input.sarif"
                write_json_atomic(
                    source, payload.model_dump(mode="json", by_alias=True), indent=4
                )
        self.triage = TriageStore(
            source, destination=self.triage_path, codebase_path=self.codebase_path
        )
        return self.triage

    def finish_triage(self, observe):
        self.triage.publish(self.triage_path, observe=observe)

    def callbacks(self, callbacks):
        callbacks = dict(callbacks or {})
        stage_completed = callbacks.get("stage_completed_callback")
        if callable(stage_completed):
            callbacks["stage_completed_callback"] = lambda result: stage_completed(
                self.export(result)
            )
        checkpoint = callbacks.get("checkpoint_callback")
        if callable(checkpoint) and self.materialize and "triage" in self.stages:

            def publish(store, processed, total):
                store.publish(self.triage_path)
                checkpoint(load_json_object_file(self.triage_path), processed, total)

            callbacks["checkpoint_callback"] = publish
        return callbacks

    def reference(self, stage):
        path = self.review_path if stage == "review" else self.triage_path
        is_review = stage == "review" or self.triage.is_review
        return {
            "json_path"
            if is_review and path.suffix.lower() != ".sarif"
            else "sarif_path": str(path)
        }

    def export(self, result):
        outputs = dict(result.outputs)
        for stage, store, path in (
            ("review", self.review, self.review_path),
            ("triage", self.triage, self.triage_path),
        ):
            if store is None or not outputs.get(stage):
                continue
            values = dict(outputs[stage])
            is_review = stage == "review" or store.is_review
            if self.materialize:
                payload = load_json_object_file(path)
                if stage == "review":
                    result_type = (
                        PatchReviewResult
                        if "overall_changes" in payload
                        else StandardReviewResult
                    )
                    values["findings"] = result_type.model_validate(payload)
                values["sarif"] = SarifPayload.model_validate(
                    generate_sarif(payload, read_source=stage == "review")
                    if is_review and path.suffix.lower() != ".sarif"
                    else payload
                )
            else:
                values.pop("findings", None)
                values.pop("sarif", None)
                values.update(self.reference(stage))
            if stage == "triage" and not self.materialize:
                values.update(
                    processed=store.processed,
                    total=store.count(include_triaged=self.include_triaged),
                )
            outputs[stage] = values
        return replace(result, outputs=outputs)
