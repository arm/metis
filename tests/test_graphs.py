# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

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


def test_ask_graph_returns_code_and_docs():
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


def test_review_nodes_pipeline_parses():
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
        "security_review_file": "Do a security review [[REVIEW_SCHEMA_FIELDS]]",
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
        schema_prompt_section='- "issue": desc',
    )
    assert "system_prompt" in s2

    # Step 3: run LLM review (stub)
    class _DummyNode:
        def __init__(self, payload):
            self._payload = payload

        def invoke(self, _):
            return self._payload

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

    s3 = review_node_llm(
        s2,
        structured_node=_DummyNode(review_payload),
        fallback_node=None,
    )
    assert "parsed_reviews" in s3
    assert s3["parsed_reviews"]

    # Step 4: parse
    s4 = review_node_parse(s3)
    assert s4.get("parsed_reviews") and isinstance(s4["parsed_reviews"], list)
