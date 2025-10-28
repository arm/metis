# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates
# SPDX-License-Identifier: Apache-2.0

from unidiff import PatchSet

from metis.engine.diff_utils import extract_content_from_diff, process_diff_file


def _make_patch(patch_text: str):
    return PatchSet.from_string(patch_text)


def test_extract_content_from_diff_additions_only():
    patch = """--- a/foo.txt
+++ b/foo.txt
@@ -0,0 +1,3 @@
+alpha
+beta
+gamma
"""
    ps = _make_patch(patch)
    file_diff = next(iter(ps))
    content = extract_content_from_diff(file_diff)
    assert content == "alpha\nbeta\ngamma\n"


def test_process_diff_includes_original_when_available(tmp_path):
    # Create a fake codebase with an original file
    codebase = tmp_path / "codebase"
    codebase.mkdir()
    original = codebase / "foo.txt"
    original.write_text("orig1\norig2\n")

    patch = """--- a/foo.txt
+++ b/foo.txt
@@ -1,2 +1,3 @@
 orig1
-orig2
+new2
+new3
"""
    ps = _make_patch(patch)
    file_diff = next(iter(ps))

    # Set a very large token limit to force including original content
    snippet = process_diff_file(str(codebase), file_diff, max_token_length=10_000_000)
    assert "ORIGINAL_FILE:" in snippet
    assert "FILE_CHANGES:" in snippet
    assert "orig1" in snippet
    assert "+new2" in snippet and "+new3" in snippet and "-orig2" in snippet


def test_process_diff_without_original(tmp_path):
    # No original file present in the codebase directory
    codebase = tmp_path / "codebase"
    codebase.mkdir()
    patch = """--- a/bar.txt
+++ b/bar.txt
@@ -0,0 +1,1 @@
+line
"""
    ps = _make_patch(patch)
    file_diff = next(iter(ps))
    snippet = process_diff_file(str(codebase), file_diff, max_token_length=100)
    # Should not include ORIGINAL_FILE heading, but should include change lines
    assert "ORIGINAL_FILE:" not in snippet
    assert "+line\n" in snippet
