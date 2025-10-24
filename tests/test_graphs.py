# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates
# SPDX-License-Identifier: Apache-2.0

import pytest

import metis.utils as mutils

from metis.engine.graphs.ask import AskGraph
from metis.engine.graphs.review import (
    review_node_retrieve,
    review_node_build_prompt,
    review_node_llm,
    review_node_parse,
)


class _Doc:
    def __init__(self, text):
        self.page_content = text


class DummyRetriever:
    def __init__(self, label):
        self._label = label

    def get_relevant_documents(self, q):
        return [_Doc(f"{self._label} context for: {q}")]


@pytest.fixture
def patch_llm_call(monkeypatch):
    # Patch LLM call used by AskGraph answer node
    def _fake_llm_call(_provider, _system, _prompt, model=None):
        return "LLM_OUTPUT"

    # Patch both the metis.utils symbol and the alias imported in ask
    monkeypatch.setattr(mutils, "llm_call", _fake_llm_call)
    import metis.engine.graphs.ask as askmod

    monkeypatch.setattr(askmod, "llm_call", _fake_llm_call)


def test_ask_graph_returns_code_and_docs(patch_llm_call):
    g = AskGraph(llm_provider=object(), llama_query_model="test-model")
    req = {
        "question": "What is here?",
        "retriever_code": DummyRetriever("code"),
        "retriever_docs": DummyRetriever("docs"),
    }
    out = g.ask(req)  # type: ignore[arg-type]
    assert isinstance(out, dict)
    assert "code" in out and "docs" in out
    assert "code context" in out["code"] or "code" in out["code"].lower()
    assert "docs" in out["docs"].lower()


def test_review_nodes_pipeline_parses(patch_llm_call):
    # Initial minimal state
    state = {
        "file_path": "a/file.c",
        "snippet": "int main(){}",
        "retriever_code": DummyRetriever("code"),
        "retriever_docs": DummyRetriever("docs"),
        "context_prompt": "Use file: {file_path}",
    }

    # Step 1: retrieve context
    s1 = review_node_retrieve(state)
    assert "context" in s1

    # Step 2: build prompt
    language_prompts = {
        "security_review_file": "Do a security review",
        "security_review_checks": "Checks...",
        "validation_review": "Validate...",
    }
    s2 = review_node_build_prompt(
        s1,
        language_prompts=language_prompts,
        default_prompt_key="security_review_file",
        report_prompt="",
        custom_prompt_text=None,
        custom_guidance_precedence="",
    )
    assert "system_prompt" in s2

    # Step 3: run LLM review (stub)
    class _DummyNode:
        def invoke(self, _):
            return '{"reviews": [{"issue": "A", "line_number": 1}]}'

    s3 = review_node_llm(s2, review_node=_DummyNode())
    assert "raw_review" in s3

    # Step 4: parse
    s4 = review_node_parse(s3)
    assert s4.get("parsed_reviews") and isinstance(s4["parsed_reviews"], list)
