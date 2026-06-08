# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import codecs
import json
import os
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
    """Split text into token-bounded chunks, returning (chunk, start_line) pairs."""
    lines = snippet.splitlines(keepends=True)
    chunks: list[tuple[str, int]] = []
    current_chunk = ""
    current_start = 1
    next_start = 1
    current_token_count = 0

    for line in lines:
        line_token_count = count_tokens(line, model)
        if current_token_count + line_token_count > max_tokens:
            if current_chunk:
                chunks.append((current_chunk, current_start))
            current_chunk = line
            current_start = next_start
            current_token_count = line_token_count
        else:
            current_chunk += line
            current_token_count += line_token_count
        next_start += 1

    if current_chunk:
        chunks.append((current_chunk, current_start))
    return chunks


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
    """
    Extract JSON content from LLM output that may contain explanatory text.
    Handles cases like:
    - Pure JSON
    - JSON wrapped in ```json ... ```
    - JSON embedded in explanatory text
    """
    cleaned = model_output.strip()

    # Remove markdown code blocks first
    if "```json" in cleaned:
        # Extract content between ```json and ```
        start_idx = cleaned.find("```json") + len("```json")
        end_idx = cleaned.find("```", start_idx)
        if end_idx != -1:
            cleaned = cleaned[start_idx:end_idx].strip()
    elif cleaned.startswith("```"):
        cleaned = cleaned[len("```") :].strip()
        if cleaned.endswith("```"):
            cleaned = cleaned[: -len("```")].strip()

    # If still not valid JSON, try to extract JSON object/array from text
    if not cleaned.startswith("{") and not cleaned.startswith("["):
        json_start = -1

        # Find first JSON structure (object or array)
        for i, char in enumerate(cleaned):
            if char == "{" or char == "[":
                json_start = i
                break

        if json_start == -1:
            return cleaned

        # Find matching closing brace/bracket using stack
        stack = []
        json_end = -1

        for i in range(json_start, len(cleaned)):
            char = cleaned[i]
            if char == "{" or char == "[":
                stack.append(char)
            elif char == "}" or char == "]":
                if stack:
                    stack.pop()
                    if not stack:
                        json_end = i + 1
                        break

        if json_end != -1:
            extracted = cleaned[json_start:json_end]
            # Verify it's valid JSON
            try:
                json.loads(extracted)
                return extracted
            except json.JSONDecodeError:
                pass

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
