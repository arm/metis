# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import atheris
import sys
from metis.utils import safe_decode_unicode


def TestOneInput(data):
    s = data.decode("utf-8", errors="ignore")
    try:
        _ = safe_decode_unicode(s)
    except Exception:
        pass


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
