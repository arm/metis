# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import atheris
import sys
from unidiff import PatchSet


def TestOneInput(data: bytes) -> None:
    """Fuzz entry point: attempt to parse `data` as a unified diff."""
    try:
        PatchSet(data.decode("utf-8", errors="ignore"))
    except Exception:
        pass


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
