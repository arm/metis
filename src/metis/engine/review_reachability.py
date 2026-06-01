# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import os
import threading
from typing import Any

from .repository import EngineRepository
from .review_aggregation import ReviewResultAggregator, same_review_file
from .review_validation import ReviewFindingValidator
from .runtime import EngineConfig


class ReachabilityReviewBackend:
    def __init__(
        self,
        config: EngineConfig,
        repository: EngineRepository,
        reachability_service,
        reachability_settings: dict[str, Any] | None = None,
    ):
        self._config = config
        self._repository = repository
        self._service = reachability_service
        self._settings = dict(reachability_settings or {})
        self._cache = None
        self._cache_condition = threading.Condition()
        self._cache_building = False

    @property
    def enabled(self):
        return self._service is not None

    def is_file_in_codebase(self, file_path):
        try:
            base = os.path.abspath(self._config.codebase_path)
            target = os.path.abspath(str(file_path))
            return os.path.commonpath([base, target]) == base
        except (OSError, ValueError):
            return False

    def supports_file(self, file_path):
        plugin = self._repository.get_plugin_for_path(str(file_path))
        supports = getattr(plugin, "supports_reachability_review", None)
        return bool(callable(supports) and supports())

    def should_review_codebase(self, files, review_file_func=None):
        return (
            self.enabled
            and review_file_func is None
            and any(self.supports_file(path) for path in files)
        )

    def remaining_standard_files(self, files):
        return [path for path in files if not self.supports_file(path)]

    def call_settings(self, *, progress_callback=None, codebase=False):
        settings = dict(self._settings)
        if codebase:
            settings.setdefault("lens_profile", "review")
            if not settings.get("max_paths"):
                settings.setdefault("confirm_paths", False)
        if progress_callback is not None:
            settings["progress_callback"] = progress_callback
        return settings

    def codebase_reviews(self, *, progress_callback=None):
        with self._cache_condition:
            if self._cache is not None:
                return list(self._cache)
            if self._cache_building:
                while self._cache_building and self._cache is None:
                    self._cache_condition.wait()
                if self._cache is not None:
                    return list(self._cache)
            self._cache_building = True

        try:
            settings = self.call_settings(
                progress_callback=progress_callback,
                codebase=True,
            )
            cache = self._service.review_codebase(**settings)
        except Exception:
            with self._cache_condition:
                self._cache_building = False
                self._cache_condition.notify_all()
            raise

        with self._cache_condition:
            self._cache = list(cache)
            self._cache_building = False
            self._cache_condition.notify_all()
        return list(self._cache)

    def file_review(self, file_path, *, progress_callback=None):
        if self._cache is not None:
            return self._global_review_for_file(
                file_path,
                progress_callback=progress_callback,
            )
        settings = self.call_settings(progress_callback=progress_callback)
        return self._service.review_file(file_path, **settings)

    def aggregate_results(self, results, *, validate_candidates=None):
        if not self.enabled:
            return results
        return ReviewResultAggregator(
            self._config,
            self._settings,
            final_adjudicator=self.final_adjudicator(),
        ).aggregate(
            results,
            validate_candidates=validate_candidates,
        )

    def validate_candidates(self, candidates):
        return ReviewFindingValidator(
            self._config,
            self._settings,
        ).validate_candidates(candidates)

    def invoke_validation_batch(self, batch, *, model, reasoning_effort=None):
        return ReviewFindingValidator(
            self._config,
            self._settings,
        ).invoke_batch(
            batch,
            model=model,
            reasoning_effort=reasoning_effort,
        )

    def final_adjudicator(self):
        adjudicator = getattr(self._service, "adjudicate_final_findings", None)
        return adjudicator if callable(adjudicator) else None

    def _global_review_for_file(
        self,
        file_path,
        *,
        progress_callback=None,
    ):
        abs_path = os.path.abspath(str(file_path))
        relative_path = self._repository.normalize_match_path(abs_path)
        for review in self.codebase_reviews(progress_callback=progress_callback):
            if same_review_file(review.get("file"), relative_path):
                return review
        return {"file": relative_path, "file_path": abs_path, "reviews": []}
