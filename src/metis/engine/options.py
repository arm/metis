# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ReviewOptions:
    use_retrieval_context: bool = True


@dataclass(frozen=True, slots=True)
class TriageOptions:
    use_retrieval_context: bool = True
    include_triaged: bool = False


def coerce_review_options(
    options: ReviewOptions | None = None,
    *,
    use_retrieval_context: bool | None = None,
) -> ReviewOptions:
    if options is None:
        return ReviewOptions(
            use_retrieval_context=(
                True if use_retrieval_context is None else use_retrieval_context
            )
        )
    if use_retrieval_context is None:
        return options
    return ReviewOptions(
        use_retrieval_context=use_retrieval_context,
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
