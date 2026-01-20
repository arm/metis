import json

from metis.utils import extract_json_content


# ============================================================
# Pure JSON Tests
# ============================================================
def test_extract_json_content_pure_json_object():
    """Extract pure JSON object unchanged."""
    result = extract_json_content('{"key": "value"}')
    assert result == '{"key": "value"}'
    assert json.loads(result) == {"key": "value"}


def test_extract_json_content_pure_json_array():
    """Extract pure JSON array unchanged."""
    result = extract_json_content("[1, 2, 3]")
    assert result == "[1, 2, 3]"
    assert json.loads(result) == [1, 2, 3]


def test_extract_json_content_empty_object():
    """Handle empty JSON object."""
    result = extract_json_content("{}")
    assert result == "{}"
    assert json.loads(result) == {}


def test_extract_json_content_empty_array():
    """Handle empty JSON array."""
    result = extract_json_content("[]")
    assert result == "[]"
    assert json.loads(result) == []


# ============================================================
# Markdown Code Block Tests
# ============================================================
def test_extract_json_content_markdown_json_block():
    """Extract JSON from ```json code blocks."""
    input_text = '```json\n{"a": 1}\n```'
    result = extract_json_content(input_text)
    assert json.loads(result) == {"a": 1}


def test_extract_json_content_markdown_plain_block():
    """Extract JSON from ``` plain code blocks."""
    input_text = '```\n{"a": 1}\n```'
    result = extract_json_content(input_text)
    assert json.loads(result) == {"a": 1}


def test_extract_json_content_markdown_with_whitespace():
    """Handle whitespace inside markdown code blocks."""
    input_text = '```json\n  {"a": 1}  \n```'
    result = extract_json_content(input_text)
    assert json.loads(result) == {"a": 1}


def test_extract_json_content_markdown_array_block():
    """Extract array from ```json code blocks."""
    input_text = "```json\n[1, 2, 3]\n```"
    result = extract_json_content(input_text)
    assert json.loads(result) == [1, 2, 3]


# ============================================================
# Embedded JSON Tests
# ============================================================
def test_extract_json_content_text_before_json():
    """Extract JSON with preceding text."""
    input_text = 'Here is the result:\n{"data": 1}'
    result = extract_json_content(input_text)
    assert json.loads(result) == {"data": 1}


def test_extract_json_content_text_after_json():
    """JSON at start with following text is returned as-is (starts with {)."""
    input_text = '{"data": 1}\nThis is the output.'
    result = extract_json_content(input_text)
    # When input starts with { or [, function returns cleaned input as-is
    # The JSON extraction logic only triggers when JSON is NOT at the start
    assert result == input_text


def test_extract_json_content_text_surrounding_json():
    """Extract JSON with text on both sides."""
    input_text = 'Result:\n{"data": 1}\nDone.'
    result = extract_json_content(input_text)
    assert json.loads(result) == {"data": 1}


def test_extract_json_content_embedded_array():
    """Extract array embedded in text."""
    input_text = "The array is [1, 2, 3] here."
    result = extract_json_content(input_text)
    assert json.loads(result) == [1, 2, 3]


def test_extract_json_content_explanation_with_json():
    """Handle LLM-style response with explanation then JSON."""
    input_text = """I've analyzed the code and found the following issues:

{"reviews": [{"issue": "Buffer overflow", "severity": "High"}]}

Let me know if you need more details."""
    result = extract_json_content(input_text)
    parsed = json.loads(result)
    assert "reviews" in parsed
    assert parsed["reviews"][0]["issue"] == "Buffer overflow"


# ============================================================
# Nested Structure Tests
# ============================================================
def test_extract_json_content_nested_objects():
    """Handle nested JSON objects."""
    input_text = '{"outer": {"inner": "value"}}'
    result = extract_json_content(input_text)
    assert json.loads(result) == {"outer": {"inner": "value"}}


def test_extract_json_content_nested_arrays():
    """Handle nested JSON arrays."""
    input_text = "[[1, 2], [3, 4]]"
    result = extract_json_content(input_text)
    assert json.loads(result) == [[1, 2], [3, 4]]


def test_extract_json_content_mixed_nesting():
    """Handle mixed object and array nesting."""
    input_text = '{"arr": [{"k": "v"}]}'
    result = extract_json_content(input_text)
    assert json.loads(result) == {"arr": [{"k": "v"}]}


def test_extract_json_content_deeply_nested():
    """Handle deeply nested structures."""
    input_text = '{"a": {"b": {"c": {"d": [1, 2, 3]}}}}'
    result = extract_json_content(input_text)
    expected = {"a": {"b": {"c": {"d": [1, 2, 3]}}}}
    assert json.loads(result) == expected


# ============================================================
# Edge Case Tests
# ============================================================
def test_extract_json_content_no_json():
    """Return original text when no JSON is present."""
    input_text = "Just plain text without any JSON"
    result = extract_json_content(input_text)
    assert result == input_text


def test_extract_json_content_whitespace_only():
    """Handle whitespace-only input."""
    result = extract_json_content("   ")
    assert result == ""


def test_extract_json_content_incomplete_json():
    """Handle incomplete/invalid JSON gracefully."""
    input_text = '{"key": "value"'
    result = extract_json_content(input_text)
    # Should return the cleaned input since JSON is invalid
    assert result == input_text


def test_extract_json_content_multiple_json_objects():
    """When input starts with JSON, return as-is even with multiple objects."""
    input_text = '{"a": 1} {"b": 2}'
    result = extract_json_content(input_text)
    # Input starts with {, so function returns cleaned input as-is
    # It does not attempt to extract only the first JSON object
    assert result == input_text


def test_extract_json_content_first_valid_json():
    """Extract first valid JSON structure from text with multiple."""
    input_text = 'First: [1, 2] and second: {"x": 3}'
    result = extract_json_content(input_text)
    # Should extract the first JSON structure found
    assert json.loads(result) == [1, 2]


# ============================================================
# Special Character Tests
# ============================================================
def test_extract_json_content_unicode():
    """Handle unicode characters in JSON."""
    input_text = '{"msg": "한글 메시지"}'
    result = extract_json_content(input_text)
    assert json.loads(result) == {"msg": "한글 메시지"}


def test_extract_json_content_escaped_quotes():
    """Handle escaped quotes inside JSON strings."""
    input_text = '{"text": "say \\"hello\\""}'
    result = extract_json_content(input_text)
    assert json.loads(result) == {"text": 'say "hello"'}


def test_extract_json_content_newlines_in_value():
    """Handle newlines inside JSON string values."""
    input_text = '{"text": "line1\\nline2"}'
    result = extract_json_content(input_text)
    assert json.loads(result) == {"text": "line1\nline2"}


def test_extract_json_content_special_chars():
    """Handle special characters in JSON."""
    input_text = '{"path": "C:\\\\Users\\\\test", "tab": "a\\tb"}'
    result = extract_json_content(input_text)
    parsed = json.loads(result)
    assert parsed["path"] == "C:\\Users\\test"
    assert parsed["tab"] == "a\tb"


# ============================================================
# Real-world LLM Output Tests
# ============================================================
def test_extract_json_content_llm_thinking_then_json():
    """Handle LLM output with thinking/reasoning before JSON."""
    input_text = """Let me analyze this code carefully.

Looking at the function, I can identify a potential buffer overflow.

```json
{
    "reviews": [
        {
            "issue": "Buffer overflow in strcpy",
            "severity": "High",
            "cwe": "CWE-120"
        }
    ]
}
```

This is a serious security issue."""
    result = extract_json_content(input_text)
    parsed = json.loads(result)
    assert parsed["reviews"][0]["cwe"] == "CWE-120"


def test_extract_json_content_json_without_markdown():
    """Handle JSON embedded in plain text without markdown."""
    input_text = (
        'The analysis result is {"status": "complete", "issues": 0} end of report.'
    )
    result = extract_json_content(input_text)
    parsed = json.loads(result)
    assert parsed["status"] == "complete"
    assert parsed["issues"] == 0
