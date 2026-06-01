# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from dataclasses import dataclass
from typing import Any

from metis.reachability_settings import (
    DEFAULT_REACHABILITY_MAX_PATH_LENGTH,
    DEFAULT_REACHABILITY_MAX_PATHS,
    DEFAULT_REACHABILITY_MAX_PATHS_PER_SINK,
    DEFAULT_REACHABILITY_WORKERS,
)


@dataclass
class ReachabilityReviewOptions:
    confirmation_model: str | None = None
    max_workers: int = DEFAULT_REACHABILITY_WORKERS
    max_paths: int = DEFAULT_REACHABILITY_MAX_PATHS
    max_paths_per_sink: int = DEFAULT_REACHABILITY_MAX_PATHS_PER_SINK
    max_path_length: int = DEFAULT_REACHABILITY_MAX_PATH_LENGTH
    progress_callback: Any = None
    reasoning_effort: str | None = None
    source_functions: Any = None
    security_functions: Any = None
    domain_hints: Any = None
    domain_profiles: Any = None
    confirm_paths: bool = True
    lens_profile: str = "all"

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
