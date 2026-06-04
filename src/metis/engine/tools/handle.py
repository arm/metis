# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass
from typing import Generic, TypeVar

from metis.exceptions import ToolDisabledError

T = TypeVar("T")


@dataclass(slots=True)
class ToolHandle(Generic[T]):
    name: str
    implementation: T | None

    @property
    def enabled(self) -> bool:
        return self.implementation is not None

    def require(self) -> T:
        if self.implementation is None:
            raise ToolDisabledError(self.name)
        return self.implementation

    def close(self) -> None:
        if self.implementation is None:
            return
        close = getattr(self.implementation, "close", None)
        if callable(close):
            close()
