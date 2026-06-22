# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import codecs
import json
import math
import os
import sys
from collections.abc import Callable
from functools import lru_cache

import tiktoken

TokenCounter = Callable[[str], int]

_ANTHROPIC_MODEL_MARKERS = ("claude", "anthropic")
_ANTHROPIC_CHARS_PER_TOKEN = 3.5
_HEURISTIC_CHARS_PER_TOKEN = 4.0
_DEFAULT_TIKTOKEN_ENCODING = "cl100k_base"

# Approximate chars-per-token for families without an offline tokenizer.
# Order matters: more specific markers first. Sources: Meta Llama 3 paper
# (arXiv:2407.21783), Mistral tokenization docs, Qwen2 tech report
# (arXiv:2407.10671), Google Gemini token docs, HF tokenizer configs.
_MODEL_FAMILY_CHARS_PER_TOKEN: tuple[tuple[tuple[str, ...], float], ...] = (
    (("llama-3", "llama3", "meta.llama3"), 3.9),
    (("llama-2", "llama2", "meta.llama2", "codellama"), 3.2),
    (("llama",), 3.9),
    (("mixtral", "mistral-7b", "mistral:7b"), 3.2),
    (("mistral",), 3.9),
    (("qwen",), 4.0),
    (("deepseek",), 4.0),
    (("gemma", "gemini"), 4.0),
    (("phi-3", "phi3"), 3.5),
    (("phi",), 4.0),
    (("command", "cohere"), 4.0),
    (("titan", "amazon."), 4.0),
)


def safe_decode_unicode(s):
    if isinstance(s, str):
        return codecs.decode(json.dumps(s), "unicode_escape").strip('"')
    return s


def _is_anthropic_model(model: str | None) -> bool:
    if not model:
        return False
    lowered = model.lower()
    return any(marker in lowered for marker in _ANTHROPIC_MODEL_MARKERS)


@lru_cache(maxsize=None)
def _tiktoken_encoding_for(model: str | None):
    if model:
        try:
            return tiktoken.encoding_for_model(model)
        except KeyError:
            pass
    return tiktoken.get_encoding(_DEFAULT_TIKTOKEN_ENCODING)


def _chars_per_token_for(model: str | None) -> float:
    if model:
        lowered = model.lower()
        for markers, ratio in _MODEL_FAMILY_CHARS_PER_TOKEN:
            if any(m in lowered for m in markers):
                return ratio
    return _HEURISTIC_CHARS_PER_TOKEN


def heuristic_token_count(
    text: str,
    chars_per_token: float | None = None,
    *,
    model: str | None = None,
) -> int:
    if not text:
        return 0
    ratio = (
        chars_per_token if chars_per_token is not None else _chars_per_token_for(model)
    )
    return max(1, math.ceil(len(text) / ratio))


def anthropic_token_count(text: str) -> int:
    return heuristic_token_count(text, _ANTHROPIC_CHARS_PER_TOKEN)


def tiktoken_token_count(text: str, model: str | None = None) -> int:
    return len(_tiktoken_encoding_for(model).encode(text))


def count_tokens(text: str, model: str | None = None) -> int:
    """Estimate token count for ``text`` from ``model`` name alone.

    Prefer :meth:`ChatProvider.count_tokens` when a provider instance is
    available; this standalone form is for call sites (e.g. usage callbacks)
    that only see a model id string. Anthropic/Claude ids and recognised
    open-weight families use chars-per-token heuristics; OpenAI ids use their
    native tiktoken encoding; unknown ids fall back to ``cl100k_base``.
    """
    if _is_anthropic_model(model):
        return anthropic_token_count(text)
    if model:
        lowered = model.lower()
        for markers, ratio in _MODEL_FAMILY_CHARS_PER_TOKEN:
            if any(m in lowered for m in markers):
                return heuristic_token_count(text, ratio)
    return tiktoken_token_count(text, model)


def split_snippet(
    snippet: str,
    max_tokens: int,
    token_counter: TokenCounter | None = None,
) -> list[tuple[str, int]]:
    """Split text into token-bounded chunks, returning (chunk, start_line) pairs."""
    counter = token_counter or count_tokens
    lines = snippet.splitlines(keepends=True)
    chunks: list[tuple[str, int]] = []
    current_chunk = ""
    current_start = 1
    next_start = 1
    current_token_count = 0

    for line in lines:
        line_token_count = counter(line)
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
