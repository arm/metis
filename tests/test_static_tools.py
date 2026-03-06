# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import pytest

from metis.engine.tools.static_tools import StaticToolRunner


def _build_runner(tmp_path):
    runner = StaticToolRunner(codebase_path=str(tmp_path))
    runner._has_grep = False
    runner._has_find = False
    runner._has_cat = False
    runner._has_sed = False
    return runner


def test_cat_fallback_reads_file(tmp_path):
    source = tmp_path / "a.txt"
    source.write_text("line1\nline2\n", encoding="utf-8")

    runner = _build_runner(tmp_path)
    out = runner.cat("a.txt")
    assert out == "line1\nline2\n"


def test_sed_fallback_slices_lines(tmp_path):
    source = tmp_path / "a.txt"
    source.write_text("1\n2\n3\n4\n5\n", encoding="utf-8")

    runner = _build_runner(tmp_path)
    out = runner.sed("a.txt", 2, 4)
    assert out == "2\n3\n4"


def test_find_name_fallback_finds_matching_files(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "target.c").write_text("x", encoding="utf-8")
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "target.c").write_text("y", encoding="utf-8")
    (tmp_path / "lib" / "other.c").write_text("z", encoding="utf-8")

    runner = _build_runner(tmp_path)
    out = runner.find_name("target.c")
    assert out == ["lib/target.c", "src/target.c"]


def test_grep_fallback_searches_recursively(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.c").write_text("alpha\nbeta\n", encoding="utf-8")
    (tmp_path / "src" / "b.c").write_text("gamma\nbeta42\n", encoding="utf-8")

    runner = _build_runner(tmp_path)
    out = runner.grep(r"beta", "src")
    lines = out.splitlines()
    assert "src/a.c:2:beta" in lines
    assert "src/b.c:2:beta42" in lines


def test_grep_fallback_invalid_pattern_raises(tmp_path):
    (tmp_path / "x.txt").write_text("hello\n", encoding="utf-8")
    runner = _build_runner(tmp_path)
    with pytest.raises(ValueError, match="Invalid grep pattern"):
        runner.grep("(", ".")
