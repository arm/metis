# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import codecs
import json
import os
import difflib
import re
import sys

import tiktoken


def safe_decode_unicode(s):
    if isinstance(s, str):
        return codecs.decode(json.dumps(s), "unicode_escape").strip('"')
    return s


def count_tokens(text, model="gpt-4"):
    encoding = tiktoken.encoding_for_model(model)
    return len(encoding.encode(text))


def split_snippet(snippet, max_tokens, model="gpt-4"):
    lines = snippet.splitlines(keepends=True)
    chunks = []
    current_chunk = ""
    current_token_count = 0

    for line in lines:
        line_token_count = count_tokens(line, model)
        # If adding this line would exceed the limit, flush the current chunk.
        if current_token_count + line_token_count > max_tokens:
            if current_chunk:
                chunks.append(current_chunk)
            current_chunk = line
            current_token_count = line_token_count
        else:
            current_chunk += line
            current_token_count += line_token_count

    if current_chunk:
        chunks.append(current_chunk)
    return chunks


def llm_call(provider, system_prompt, prompt, **kwargs):
    return provider.call_llm(system_prompt, prompt, **kwargs)


def parse_json_output(model_output):
    """
    Clean up and parse model output as JSON.
    """
    cleaned = extract_json_content(model_output)
    try:
        parsed = json.loads(cleaned)
        return parsed
    except Exception:
        return cleaned


def extract_json_content(model_output):
    cleaned = model_output.strip()
    if cleaned.startswith("```json"):
        cleaned = cleaned[len("```json") :].strip()
    elif cleaned.startswith("```"):
        cleaned = cleaned[len("```") :].strip()
    if cleaned.endswith("```"):
        cleaned = cleaned[: -len("```")].strip()
    elif cleaned.endswith("'''"):
        cleaned = cleaned[: -len("'''")].strip()
    return cleaned


def read_file_content(file_path):
    """Read file content if it exists"""
    if not os.path.exists(file_path):
        return ""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception:
        return ""


def normalize_lines(lines):
    """Remove all whitespace characters from the joined lines."""
    joined = "".join(lines)
    return re.sub(r"\s+", "", joined)


def find_snippet_line(snippet, file_path, threshold=0.80):
    """
    Finds the first line number where the snippet matches a window in the file
    above the given similarity threshold. Returns 1 if not found.
    """
    with open(file_path, "r", encoding="utf-8") as f:
        file_lines = f.readlines()

    snippet_lines = snippet.strip().splitlines()
    snippet_len = len(snippet_lines)
    norm_snippet = normalize_lines(snippet_lines)

    for i in range(len(file_lines) - snippet_len + 1):

        window = file_lines[i : i + snippet_len]
        norm_window = normalize_lines(window)

        score = difflib.SequenceMatcher(None, norm_window, norm_snippet).ratio()
        if score >= threshold:
            return i + 1

    return 1


def retry_on_recursion_error(fn, *args, bump=5000, retries=10, **kwargs):
    """
    Calls `fn(*args, **kwargs)`, catching RecursionError up to `retries` times.
    On each failure, increase the recursion limit by `bump` * `attempt` and retry.
    Restores the original limit before returning.
    """
    original_limit = sys.getrecursionlimit()
    try:
        return fn(*args, **kwargs)
    except RecursionError as e:
        for attempt in range(1, retries + 1):
            new_limit = original_limit + bump * attempt
            sys.setrecursionlimit(new_limit)
            try:
                return fn(*args, **kwargs)
            except RecursionError:
                continue
        raise e
    finally:
        sys.setrecursionlimit(original_limit)
