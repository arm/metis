# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from collections.abc import Mapping
from dataclasses import dataclass, fields, replace
from typing import Any

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import NonNegativeInt
from pydantic import PositiveInt

from .workers import coerce_worker_count

DEFAULT_REACHABILITY_MAX_PATHS = 0
DEFAULT_REACHABILITY_MAX_PATHS_PER_SINK = 3
DEFAULT_REACHABILITY_MAX_PATH_LENGTH = 25
# Each evidence-resolution round may invoke the model and tools again for every
# unresolved finding; two retries bound that provider cost.
DEFAULT_REACHABILITY_EVIDENCE_RESOLUTION_ROUNDS = 2


class ReachabilityConfiguration(BaseModel):
    max_paths: NonNegativeInt | None = None
    max_paths_per_sink: NonNegativeInt | None = None
    max_path_length: PositiveInt | None = None
    domain_profiles: tuple[str, ...] | None = None
    domain_hints: tuple[str, ...] | None = None

    model_config = ConfigDict(extra="forbid", frozen=True)

    def as_review_settings(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude_none=True)


@dataclass(frozen=True, slots=True)
class ReachabilityReviewOptions:
    confirmation_model: str | None = None
    max_workers: int | str | None = None
    max_paths: int = DEFAULT_REACHABILITY_MAX_PATHS
    max_paths_per_sink: int = DEFAULT_REACHABILITY_MAX_PATHS_PER_SINK
    max_path_length: int = DEFAULT_REACHABILITY_MAX_PATH_LENGTH
    progress_callback: Any = None
    reasoning_effort: str | None = None
    domain_hints: Any = None
    domain_profiles: Any = None
    confirm_paths: bool = True
    lens_profile: str = "all"
    evidence_resolution_rounds: int = DEFAULT_REACHABILITY_EVIDENCE_RESOLUTION_ROUNDS

    def __post_init__(self):
        if self.max_workers is not None:
            object.__setattr__(
                self, "max_workers", coerce_worker_count(self.max_workers)
            )
        object.__setattr__(
            self,
            "evidence_resolution_rounds",
            max(0, int(self.evidence_resolution_rounds or 0)),
        )

    @classmethod
    def from_kwargs(
        cls,
        kwargs: Mapping[str, Any] | None = None,
        *,
        default_workers: int,
        options: "ReachabilityReviewOptions | None" = None,
        overrides: Mapping[str, Any] | None = None,
    ):
        option_keys = {field.name for field in fields(cls)}
        unknown_keys = set(kwargs or ()) | set(overrides or ())
        unknown_keys -= option_keys
        if unknown_keys:
            unknown = ", ".join(sorted(unknown_keys))
            raise TypeError(f"unknown reachability review option(s): {unknown}")
        values = (
            {key: getattr(options, key) for key in option_keys}
            if options is not None
            else {}
        )
        values.update(
            {key: value for key, value in (kwargs or {}).items() if key in option_keys}
        )
        values.update(
            {
                key: value
                for key, value in (overrides or {}).items()
                if key in option_keys
            }
        )
        if values.get("max_workers") is None:
            values["max_workers"] = default_workers
        return cls(**values)

    def with_confirmation_model(self, model):
        return replace(self, confirmation_model=model)

    def with_max_workers(self, max_workers):
        return replace(self, max_workers=max_workers)

    def with_progress_callback(self, progress_callback):
        return replace(self, progress_callback=progress_callback)

    def supplementary_cache_key(self, scope_id: object, graph_fingerprint: str):
        return (
            str(scope_id or "whole_graph"),
            str(self.confirmation_model or ""),
            str(self.reasoning_effort or ""),
            str(self.lens_profile or "all"),
            repr(self.domain_hints or ()),
            repr(self.domain_profiles or ()),
            graph_fingerprint,
        )
