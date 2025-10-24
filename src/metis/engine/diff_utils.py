# SPDX-License-Identifier: Apache-2.0

import logging
import os

from metis.utils import count_tokens, read_file_content


logger = logging.getLogger("metis")


def extract_content_from_diff(file_diff):
    content_lines = []
    for hunk in file_diff:
        for line in hunk:
            if line.is_added:
                content_lines.append(line.value)
    return "".join(content_lines)


def process_diff_file(codebase_path, file_diff, max_token_length):
    changed_lines = []
    for hunk in file_diff:
        for line in hunk:
            if line.is_added:
                changed_lines.append("+" + line.value)
            elif line.is_removed:
                changed_lines.append("-" + line.value)
    snippet = "".join(changed_lines)
    original_file_path = os.path.join(codebase_path, file_diff.path)
    original_content = read_file_content(original_file_path)
    if original_content:
        logger.info(f"Fetched original content for {file_diff.path}.")
        total_tokens = count_tokens(original_content) + count_tokens(snippet)
        if total_tokens <= max_token_length:
            snippet = f"ORIGINAL_FILE:\n{original_content}\n\nFILE_CHANGES:\n{snippet}"
        else:
            snippet = f"FILE_CHANGES:\n{snippet}"
    return snippet
