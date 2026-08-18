# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
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


def test_process_diff_preserves_added_and_removed_lines_without_wrappers():
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

    assert process_diff_file(file_diff) == "-orig2\n+new2\n+new3\n"
