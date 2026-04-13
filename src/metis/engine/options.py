# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class ReviewOptions:
    use_retrieval_context: bool = True
    debug_callback: Any = None


@dataclass(frozen=True, slots=True)
class TriageOptions:
    use_retrieval_context: bool = True
    include_triaged: bool = False


def coerce_review_options(
    options: ReviewOptions | None = None,
    *,
    use_retrieval_context: bool | None = None,
    debug_callback: Any = None,
) -> ReviewOptions:
    if options is None:
        return ReviewOptions(
            use_retrieval_context=(
                True if use_retrieval_context is None else use_retrieval_context
            ),
            debug_callback=debug_callback,
        )
    if use_retrieval_context is None and debug_callback is None:
        return options
    return ReviewOptions(
        use_retrieval_context=(
            options.use_retrieval_context
            if use_retrieval_context is None
            else use_retrieval_context
        ),
        debug_callback=(
            options.debug_callback if debug_callback is None else debug_callback
        ),
    )


def coerce_triage_options(
    options: TriageOptions | None = None,
    *,
    use_retrieval_context: bool | None = None,
    include_triaged: bool | None = None,
) -> TriageOptions:
    if options is None:
        return TriageOptions(
            use_retrieval_context=(
                True if use_retrieval_context is None else use_retrieval_context
            ),
            include_triaged=(False if include_triaged is None else include_triaged),
        )
    return TriageOptions(
        use_retrieval_context=(
            options.use_retrieval_context
            if use_retrieval_context is None
            else use_retrieval_context
        ),
        include_triaged=(
            options.include_triaged if include_triaged is None else include_triaged
        ),
    )
