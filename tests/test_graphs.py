# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.engine.graphs.types import AskRequest
from metis.engine.graphs.types import ReviewState
from metis.engine.graphs.types import TriageState
from metis.engine.graphs.ask import AskGraph
from metis.engine.graphs.review import (
    review_node_retrieve,
    review_node_build_prompt,
    review_node_llm,
    review_node_parse,
)
from metis.engine.graphs.triage.llm import _build_user_prompt, triage_node_llm


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
        "retriever_code": DummyRetriever("code"),
        "retriever_docs": DummyRetriever("docs"),
        "context_prompt": "Use file: {file_path}",
        "use_retrieval_context": True,
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
        invoke_review=lambda _system, _body: review_payload["reviews"],
    )
    assert "parsed_reviews" in s3
    assert s3["parsed_reviews"]

    # Step 4: parse
    s4 = review_node_parse(s3)
    assert s4.get("parsed_reviews") and isinstance(s4["parsed_reviews"], list)


def test_retrieve_text_does_not_stringify_backend_objects():
    from metis.engine.graphs.utils import retrieve_text

    class _BackendNode:
        text = "safe graph text"
        embedding = [0.1, 0.2]

        def __str__(self):
            return "BackendNode(text='safe graph text', embedding=[0.1, 0.2])"

    class _Retriever:
        def get_relevant_documents(self, _query):
            return [_BackendNode()]

    context = retrieve_text(_Retriever(), "lookup")

    assert context == "safe graph text"
    assert "embedding" not in context


def test_review_node_retrieve_no_index_skips_retrievers():
    class _BoomRetriever:
        def get_relevant_documents(self, _query):
            raise AssertionError("retriever should not be called")

    state: ReviewState = {
        "file_path": "a/file.c",
        "snippet": "int main(){}",
        "retriever_code": _BoomRetriever(),
        "retriever_docs": _BoomRetriever(),
        "context_prompt": "ignored",
        "use_retrieval_context": False,
    }

    out = review_node_retrieve(state)

    assert out["context"] == ""


def test_review_node_llm_omits_context_section_in_no_index_mode():
    captured = {}

    state: ReviewState = {
        "file_path": "foo.py",
        "snippet": "print('hello')",
        "context": "should not appear",
        "mode": "file",
        "system_prompt": "prompt",
        "use_retrieval_context": False,
    }

    review_node_llm(
        state,
        invoke_review=lambda _system, body: (
            captured.setdefault("body_text", body) or []
        ),
    )

    assert "CONTEXT:" not in captured["body_text"]


def test_triage_user_prompt_omits_rag_context_in_no_index_mode():
    prompt = _build_user_prompt(
        TriageState(
            finding_rule_id="R1",
            finding_file_path="a.c",
            finding_line=1,
            finding_message="msg",
            finding_snippet="code",
            context="should not appear",
            use_retrieval_context=False,
        )
    )

    assert "RAG Context:" not in prompt


def test_triage_node_llm_omits_context_wording_in_no_index_mode():
    captured = {}

    class _Decision:
        status = "valid"
        reason = "ok"
        evidence = []
        resolution_chain = []
        unresolved_hops = []

    class _DecisionModel:
        def invoke(self, messages):
            captured["system"] = messages[0].content
            captured["user"] = messages[1].content
            return _Decision()

    triage_node_llm(
        TriageState(
            finding_rule_id="R1",
            finding_file_path="a.c",
            finding_line=1,
            finding_message="msg",
            finding_snippet="code",
            context="should not appear",
            use_retrieval_context=False,
            triage_system_prompt="system",
            triage_decision_prompt=(
                "Given the finding details, RAG context, and tool outputs, return a final triage decision.\n\n"
                "{triage_input}\n\nTool Outputs:\n{tool_outputs}\n"
            ),
            evidence_pack="tools",
        ),
        decision_model=_DecisionModel(),
    )

    combined = captured["system"] + "\n" + captured["user"]
    assert "RAG Context:" not in combined
