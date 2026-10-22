# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from concurrent.futures import CancelledError
from importlib import metadata


def load_registration[Registration](
    entry_point: metadata.EntryPoint,
    registration_type: type[Registration],
    *,
    label: str,
    entry_point_label: str,
) -> Registration:
    try:
        loaded = entry_point.load()
        registration = (
            loaded()
            if callable(loaded) and not isinstance(loaded, registration_type)
            else loaded
        )
    except CancelledError:
        raise
    except Exception as exc:
        raise RuntimeError(f"{label} failed to load: {exc}") from exc
    if not isinstance(registration, registration_type):
        raise TypeError(
            f"{entry_point_label} did not return a {registration_type.__name__}"
        )
    return registration
