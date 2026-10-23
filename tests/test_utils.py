import math
from datetime import datetime
from datetime import timezone

import pytest

from metis.utils import resolve_path_within_root
from metis.utils import safe_int
from metis.utils import normalized_string_tuple
from metis.utils import utc_now_iso
from metis.utils import (
    anthropic_token_count,
    count_tokens,
    extract_json_content,
    heuristic_token_count,
    split_snippet,
    tiktoken_token_count,
)


def test_tolerant_integer_conversion_keeps_explicit_defaults_and_ranges():
    for invalid in (None, "bad", "1.5", [], math.inf, -math.inf, math.nan):
        assert safe_int(invalid, None) is None
        assert safe_int(invalid, -1) == -1
    for value, expected in (("2", 2), (b"3", 3), (2.9, 2), (-2, -2), (False, 0)):
        assert safe_int(value, None) == expected


def test_strict_manifest_list_normalization_does_not_coerce_values():
    assert normalized_string_tuple(None, error="invalid list") == ()
    for values in ([" One ", "", "  ", "TWO", "One"], ("One", "TWO", "One")):
        assert normalized_string_tuple(values, error="invalid list") == (
            "one",
            "two",
            "one",
        )
    for values in ("one", {"one"}, {"one": True}, [1], [None]):
        with pytest.raises(ValueError, match="invalid list"):
            normalized_string_tuple(values, error="invalid list")


def test_utc_timestamp_uses_z_suffix_and_is_current():
    before = datetime.now(timezone.utc)
    timestamp = utc_now_iso()
    assert timestamp.endswith("Z")
    assert before <= datetime.fromisoformat(timestamp) <= datetime.now(timezone.utc)


@pytest.mark.parametrize("preserve_aliases", [False, True])
@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("./~/source.c", "~/source.c"),
        ("./~metis-no-such-user/source.c", "~metis-no-such-user/source.c"),
        ("~/source.c", "home/source.c"),
        ("~metis-no-such-user/source.c", None),
    ],
)
def test_source_paths_expand_only_leading_tilde(
    tmp_path, monkeypatch, preserve_aliases, target, expected
):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    if expected is None:
        with pytest.raises(RuntimeError, match="home directory"):
            resolve_path_within_root(
                tmp_path, target, preserve_aliases=preserve_aliases
            )
    else:
        assert (
            resolve_path_within_root(
                tmp_path, target, preserve_aliases=preserve_aliases
            )
            == tmp_path / expected
        )


@pytest.mark.parametrize("root_name", ["~", "~metis-no-such-user"])
def test_source_paths_preserve_literal_root(tmp_path, monkeypatch, root_name):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    root = tmp_path / root_name
    root.mkdir()
    assert resolve_path_within_root(f"./{root_name}", "source.c") == root / "source.c"


@pytest.mark.parametrize("preserve_aliases", [False, True])
def test_source_paths_confine_case_aliases(tmp_path, preserve_aliases):
    root = tmp_path / "Repository"
    root.mkdir()
    alias = tmp_path / "repository"
    (root / "source.c").write_text("source", encoding="utf-8")
    for relative in (".", "source.c", "new/source.c"):
        if alias.exists():
            assert (
                resolve_path_within_root(
                    root, alias / relative, preserve_aliases=preserve_aliases
                )
                == root / relative
            )
        else:
            with pytest.raises(ValueError, match="Path escapes codebase"):
                resolve_path_within_root(
                    root, alias / relative, preserve_aliases=preserve_aliases
                )
    for outside in (tmp_path / "other/source.c", alias / "../source.c"):
        with pytest.raises(ValueError, match="Path escapes codebase"):
            resolve_path_within_root(root, outside, preserve_aliases=preserve_aliases)
    prospective = tmp_path / "missing"
    assert (
        resolve_path_within_root(
            prospective, "new/source.c", preserve_aliases=preserve_aliases
        )
        == prospective / "new/source.c"
    )
    with pytest.raises(ValueError, match="Path escapes codebase"):
        resolve_path_within_root(
            prospective, root / "source.c", preserve_aliases=preserve_aliases
        )


@pytest.mark.parametrize("ancestor", ["missing", "file", "alias"])
def test_source_paths_validate_parent_components(tmp_path, ancestor):
    (tmp_path / "file").write_text("not a directory", encoding="utf-8")
    (tmp_path / "real" / "nested").mkdir(parents=True)
    (tmp_path / "alias").symlink_to(
        tmp_path / "real" / "nested", target_is_directory=True
    )
    target = f"{ancestor}/../new.c"
    if ancestor == "alias":
        result = resolve_path_within_root(tmp_path, target, preserve_aliases=True)
        assert result == tmp_path / "real" / "new.c"
        assert not result.exists()
    else:
        with pytest.raises(NotADirectoryError, match="Path parent"):
            resolve_path_within_root(tmp_path, target, preserve_aliases=True)


@pytest.mark.parametrize(
    ("model_output", "expected"),
    [
        ('{"key": "value"}', '{"key": "value"}'),
        ("[1, 2, 3]", "[1, 2, 3]"),
        ('```json\n  {"a": 1}  \n```', '{"a": 1}'),
        ("```\n[1, 2, 3]\n```", "[1, 2, 3]"),
        ('Here is the result:\n{"data": 1}', '{"data": 1}'),
        ('Result:\n{"data": 1}\nDone.', '{"data": 1}'),
        ("The array is [1, 2, 3] here.", "[1, 2, 3]"),
        (
            'First: [1, 2] and second: {"x": 3}',
            "[1, 2]",
        ),
        (
            'Result: {"text": "braces } and brackets ] stay quoted"} done.',
            '{"text": "braces } and brackets ] stay quoted"}',
        ),
        (
            'Thinking.\n```json\n{"reviews": [{"issue": "Buffer overflow"}]}\n```\nDone.',
            '{"reviews": [{"issue": "Buffer overflow"}]}',
        ),
        ("Just plain text without any JSON", "Just plain text without any JSON"),
        ("   ", ""),
        ('{"key": "value"', '{"key": "value"'),
        (
            '{"data": 1}\nThis is the output.',
            '{"data": 1}\nThis is the output.',
        ),
        ('{"a": 1} {"b": 2}', '{"a": 1} {"b": 2}'),
        (
            'First: [not JSON] then {"valid": true}',
            'First: [not JSON] then {"valid": true}',
        ),
    ],
)
def test_extract_json_content(model_output: str, expected: str) -> None:
    assert extract_json_content(model_output) == expected


# ============================================================
# Token counting Tests
# ============================================================
def test_heuristic_token_count_default_ratio():
    text = "hello world!"
    assert heuristic_token_count(text) == math.ceil(len(text) / 4.0)
    assert heuristic_token_count("") == 0
    assert heuristic_token_count("x") == 1


def test_anthropic_token_count_uses_anthropic_ratio():
    text = "def f():\n    return 42\n"
    assert anthropic_token_count(text) == math.ceil(len(text) / 3.5)
    assert anthropic_token_count("") == 0


@pytest.mark.parametrize(
    ("model", "ratio"),
    [
        ("llama3:8b", 3.9),
        ("meta-llama/Llama-2-7b-hf", 3.2),
        ("codellama:13b", 3.2),
        ("meta.llama3-1-70b-instruct-v1:0", 3.9),
        ("mixtral:8x7b", 3.2),
        ("mistralai/Mistral-7B-Instruct-v0.2", 3.2),
        ("mistral-large-latest", 3.9),
        ("qwen2.5-coder:7b", 4.0),
        ("deepseek-r1:32b", 4.0),
        ("gemma2:9b", 4.0),
        ("gemini-2.0-flash", 4.0),
        ("phi3:mini", 3.5),
        ("microsoft/phi-2", 4.0),
        ("cohere.command-r-plus-v1:0", 4.0),
        ("amazon.titan-text-express-v1", 4.0),
    ],
)
def test_heuristic_token_count_model_family_ratios(model, ratio):
    text = "x" * 200
    assert heuristic_token_count(text, model=model) == math.ceil(len(text) / ratio)
    assert count_tokens(text, model=model) == math.ceil(len(text) / ratio)


def test_heuristic_token_count_unknown_model_uses_default():
    text = "x" * 200
    assert heuristic_token_count(text, model="some-future-model") == math.ceil(
        len(text) / 4.0
    )


def test_tiktoken_token_count_known_model():
    text = "x" * 100
    n = tiktoken_token_count(text, "gpt-4o")
    assert n > 0
    assert n != math.ceil(len(text) / 3.5)


def test_tiktoken_token_count_unknown_model_falls_back_to_cl100k():
    text = "hello world"
    assert tiktoken_token_count(text, "amazon.titan-embed-text-v2:0") == (
        tiktoken_token_count(text, None)
    )


@pytest.mark.parametrize("model", ["gpt-4o", "unknown-model"])
def test_tiktoken_token_count_treats_special_tokens_as_literal_text(model: str) -> None:
    assert tiktoken_token_count("<|endoftext|>", model) == 7


def test_tiktoken_token_count_falls_back_when_registry_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unavailable(_model: str | None) -> None:
        raise ValueError("Unknown encoding cl100k_base")

    monkeypatch.setattr("metis.utils._tiktoken_encoding_for", unavailable)
    text = "hello world"

    assert tiktoken_token_count(text, "gpt-4") == heuristic_token_count(
        text,
        model="gpt-4",
    )


@pytest.mark.parametrize(
    "model",
    [
        "claude-sonnet-4-6",
        "anthropic.claude-3-5-sonnet-20241022-v2:0",
        "us.anthropic.claude-3-7-sonnet-20250219-v1:0",
        "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-v2",
    ],
)
def test_count_tokens_dispatches_anthropic_ids_to_heuristic(model):
    text = "def f():\n    return 42\n"
    assert count_tokens(text, model=model) == anthropic_token_count(text)


def test_count_tokens_default_matches_legacy_gpt4():
    """No-model default must preserve the previous gpt-4 behaviour."""
    text = "hello world, this is a tokenizer test"
    assert count_tokens(text) == tiktoken_token_count(text, "gpt-4")


def test_split_snippet_uses_supplied_token_counter():
    text = "alpha\nbeta\ngamma\ndelta\n"
    chunks = split_snippet(
        text,
        max_tokens=2,
        token_counter=lambda value: len(value.splitlines()),
    )
    assert [s for _, s in chunks] == [1, 3]
    assert "".join(c for c, _ in chunks) == text


def test_split_snippet_default_counter():
    text = "a\nb\nc\nd\n"
    chunks = split_snippet(text, max_tokens=1)
    assert "".join(c for c, _ in chunks) == text


def test_split_snippet_splits_one_overlong_line_without_data_loss():
    text = "abc\fdef\u2028ghijkl\nok\n"
    chunks = split_snippet(text, max_tokens=4, token_counter=len)

    assert "".join(chunk for chunk, _start in chunks) == text
    assert all(len(chunk) <= 4 for chunk, _start in chunks)
    assert all(start == 1 for chunk, start in chunks if "ok" not in chunk)
    assert any(start == 2 for chunk, start in chunks if "ok" in chunk)
    assert split_snippet(text, max_tokens=4, token_counter=len) == chunks


def test_split_snippet_checks_the_complete_candidate_chunk():
    def non_additive_counter(value: str) -> int:
        return 3 if value == "ab" else len(value)

    chunks = split_snippet("ab", max_tokens=2, token_counter=non_additive_counter)

    assert chunks == [("a", 1), ("b", 1)]
    assert all(non_additive_counter(chunk) <= 2 for chunk, _start in chunks)
