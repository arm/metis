# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from dataclasses import dataclass
from dataclasses import replace
from typing import Any

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import PositiveInt

DEFAULT_REACHABILITY_MAX_PATH_LENGTH = 25


class ReachabilityConfiguration(BaseModel):
    max_path_length: PositiveInt | None = None
    domain_profiles: tuple[str, ...] | None = None
    domain_hints: tuple[str, ...] | None = None

    model_config = ConfigDict(extra="forbid", frozen=True)

    def as_review_settings(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude_none=True)


@dataclass(frozen=True, slots=True)
class ReachabilityReviewOptions:
    confirmation_model: str | None = None
    max_path_length: int = DEFAULT_REACHABILITY_MAX_PATH_LENGTH
    progress_callback: Any = None
    reasoning_effort: str | None = None
    domain_hints: Any = None
    domain_profiles: Any = None

    def with_progress_callback(
        self, progress_callback: Any
    ) -> "ReachabilityReviewOptions":
        return replace(self, progress_callback=progress_callback)
