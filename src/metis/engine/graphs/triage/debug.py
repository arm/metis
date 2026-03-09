# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from ..types import TriageState


def _emit_debug(state: TriageState, event: str, **payload) -> None:
    cb = state.get("debug_callback")
    if not callable(cb):
        return
    try:
        cb({"event": event, **payload})
    except Exception:
        pass
