# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import stat
from pathlib import Path

import pytest

from metis.json_io import write_json_atomic


def test_write_json_atomic_preserves_target_and_cleans_temporary_file(
    tmp_path: Path,
) -> None:
    target = tmp_path / "result.json"
    write_json_atomic(
        target,
        {"text": "£"},
        indent=2,
        ensure_ascii=False,
        allow_nan=False,
        mode=0o600,
    )

    expected = target.read_text(encoding="utf-8")
    assert expected == '{\n  "text": "£"\n}'
    assert stat.S_IMODE(target.stat().st_mode) == 0o600

    with pytest.raises(ValueError):
        write_json_atomic(target, {"value": float("nan")}, indent=2, allow_nan=False)

    assert target.read_text(encoding="utf-8") == expected
    assert list(tmp_path.iterdir()) == [target]
