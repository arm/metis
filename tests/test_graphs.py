# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from metis.engine.graphs.types import AskRequest
from metis.engine.graphs.types import ReviewState
from metis.engine.graphs.ask import AskGraph
from metis.engine.graphs.review import (
    review_node_build_prompt,
    review_node_llm,
    review_node_parse,
)
from metis.engine.graphs.review import ReviewGraph
from metis.engine.llm_runner import rendered_prompt_token_count
from metis.engine.model_tool_runner import ModelInputLimitError


class _Doc:
    def __init__(self, text):
        self.page_content = text


class DummyRetriever:
    def __init__(self, label):
        self._label = label

    def get_relevant_documents(self, q):
        return [_Doc(f"{self._label} context for: {q}")]


def test_ask_graph_returns_code_and_docs():
    g = AskGraph(llm_provider=object(), llama_query_model="test-model")
    req: AskRequest = {
        "question": "What is here?",
        "retriever_code": DummyRetriever("code"),
        "retriever_docs": DummyRetriever("docs"),
    }
    out = g.ask(req)
    assert isinstance(out, dict)
    assert "code" in out and "docs" in out
    assert "code context" in out["code"] or "code" in out["code"].lower()
    assert "docs" in out["docs"].lower()


def test_review_nodes_pipeline_parses():
    # Initial minimal state
    state: ReviewState = {
        "file_path": "a/file.c",
        "snippet": "int main(){}",
    }

    language_prompts = {
        "security_review_file": "Do a security review [[REVIEW_SCHEMA_FIELDS]]",
        "security_review_checks": "Checks...",
        "validation_review": "Validate...",
    }
    s1 = review_node_build_prompt(
        state,
        language_prompts=language_prompts,
        default_prompt_key="security_review_file",
        report_prompt="",
        custom_prompt_text=None,
        custom_guidance_precedence="",
        schema_prompt_section='- "issue": desc',
    )
    assert "system_prompt" in s1

    review_payload = {
        "reviews": [
            {
                "issue": "Issue A",
                "code_snippet": "int main(){}",
                "reasoning": "Because.",
                "mitigation": "Fix it.",
                "confidence": 0.5,
                "cwe": "CWE-79",
                "severity": "Medium",
            }
        ]
    }

    s2 = review_node_llm(
        s1,
        invoke_review=lambda _system, _body: review_payload["reviews"],
    )
    assert "parsed_reviews" in s2
    assert s2["parsed_reviews"]

    s3 = review_node_parse(s2)
    assert s3.get("parsed_reviews") and isinstance(s3["parsed_reviews"], list)


@pytest.fixture
def budgeted_review_graph():
    provider = Mock()
    provider.count_tokens = len
    tool = SimpleNamespace(name="sed", description="Read source", metadata={})
    graph = ReviewGraph(
        provider,
        {},
        None,
        "",
        "test-model",
        500,
        model_tools=(tool,),
        model_tool_max_rounds=2,
    )
    graph._schema_prompt_section = ""
    graph._prompt_runner.invoke = Mock(return_value=[])
    return graph


def _budgeted_request(snippet):
    return {
        "file_path": "target.c",
        "snippet": snippet,
        "language_prompts": {
            "security_review_file": "Review. [[REVIEW_SCHEMA_FIELDS]]",
            "security_review_checks": "Check.",
        },
    }


def test_review_chunks_include_prompt_and_numbering_in_input_budget(
    budgeted_review_graph,
):
    graph = budgeted_review_graph
    source = "".join(f"int value_{index};\n" for index in range(80))
    assert graph.review(_budgeted_request(source))["reviews"] == []
    requests = [call.args[0] for call in graph._prompt_runner.invoke.call_args_list]
    assert len(requests) > 1
    numbered_lines = []
    for request in requests:
        assert request.max_input_tokens == 500
        assert (
            rendered_prompt_token_count(
                len,
                system_prompt=request.system_prompt,
                user_prompt=request.user_prompt,
                variables=request.variables,
                model_tools=request.model_tools,
            )
            <= 500
        )
        numbered_lines.extend(
            line.strip()
            for line in request.variables["body_text"].splitlines()
            if ": int value_" in line
        )
    assert numbered_lines == [f"{index + 1}: int value_{index};" for index in range(80)]


def test_unsplittable_review_fails_without_model_calls(budgeted_review_graph):
    graph = budgeted_review_graph
    with pytest.raises(ModelInputLimitError, match="one source fragment"):
        graph.review(_budgeted_request("x" * 1000))
    graph._prompt_runner.invoke.assert_not_called()


def test_oversized_base_prompt_fails_without_model_calls(budgeted_review_graph):
    graph = budgeted_review_graph
    graph._schema_prompt_section = "x" * 1000
    with pytest.raises(ModelInputLimitError, match="prompt context"):
        graph.review(_budgeted_request("int target;\n"))
    graph._prompt_runner.invoke.assert_not_called()


def test_large_patch_context_is_omitted_but_original_anchors_are_retained(
    budgeted_review_graph,
):
    graph = budgeted_review_graph
    graph._prompt_runner.invoke.return_value = [
        {"code_snippet": "int target;", "start_line": 1001, "end_line": 1001}
    ]
    diff = "--- a/target.c\n+++ b/target.c\n@@ -1001 +1001 @@\n-int target;\n+int target = 1;\n"
    request = {
        **_budgeted_request(diff),
        "mode": "patch",
        "original_file": "int filler;\n" * 1000 + "int target;\n",
    }
    result = graph.review(request)
    graph._prompt_runner.invoke.assert_called_once()
    body = graph._prompt_runner.invoke.call_args.args[0].variables["body_text"]
    assert "FILE: target.c" in body
    assert diff in body
    assert "[Full-file context omitted.]" in body
    assert "int filler;" not in body
    assert result["reviews"][0]["anchor"]["start_line"] == 1001
