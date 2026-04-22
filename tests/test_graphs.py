# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.engine.graphs.ask import AskGraph
from metis.engine.graphs.review import (
    review_node_build_prompt,
    review_node_collect_project_context,
    review_node_collect_tool_evidence,
    review_node_llm,
    review_node_parse,
    review_node_retrieve,
)
from metis.engine.graphs.review_tools import (
    build_review_langchain_tools,
    run_review_tool_phase,
)
from metis.engine.graphs.triage.llm import _build_user_prompt, triage_node_llm
from metis.engine.graphs.triage.retrieval import triage_node_retrieve


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
    state = {
        "file_path": "a/file.c",
        "snippet": "int main(){}",
        "retriever_code": DummyRetriever("code"),
        "retriever_docs": DummyRetriever("docs"),
        "use_retrieval_context": True,
    }

    s1 = review_node_retrieve(state)
    assert "context" in s1
    assert "context for:" in s1["context"]

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

    s4 = review_node_parse(s3)
    assert s4.get("parsed_reviews") and isinstance(s4["parsed_reviews"], list)


def test_review_node_retrieve_no_index_skips_retrievers():
    class _BoomRetriever:
        def get_relevant_documents(self, _query):
            raise AssertionError("retriever should not be called")

    state = {
        "file_path": "a/file.c",
        "snippet": "int main(){}",
        "retriever_code": _BoomRetriever(),
        "retriever_docs": _BoomRetriever(),
        "use_retrieval_context": False,
    }

    out = review_node_retrieve(state)

    assert out["context"] == ""


def test_review_node_llm_omits_tool_evidence_section_in_no_index_mode():
    captured = {}

    class _DummyNode:
        def invoke(self, payload):
            captured.update(payload)
            return {"reviews": []}

    state = {
        "file_path": "foo.py",
        "snippet": "print('hello')",
        "context": "should not appear",
        "mode": "file",
        "system_prompt": "prompt",
        "use_retrieval_context": False,
    }

    review_node_llm(
        state,
        structured_node=_DummyNode(),
        fallback_node=None,
    )

    assert "TOOL_EVIDENCE:" not in captured["body_text"]


def test_review_node_llm_includes_context_as_tool_evidence():
    captured = {}

    class _DummyNode:
        def invoke(self, payload):
            captured.update(payload)
            return {"reviews": []}

    state = {
        "file_path": "foo.py",
        "snippet": "print('hello')",
        "mode": "file",
        "system_prompt": "prompt",
        "context": "[foo.py]\ncallers validate input",
        "use_retrieval_context": True,
    }

    review_node_llm(
        state,
        structured_node=_DummyNode(),
        fallback_node=None,
    )

    assert "TOOL_EVIDENCE:" in captured["body_text"]


def test_review_node_llm_includes_rag_tool_evidence():
    captured = {}

    class _DummyNode:
        def invoke(self, payload):
            captured.update(payload)
            return {"reviews": []}

    state = {
        "file_path": "foo.py",
        "snippet": "print('hello')",
        "mode": "file",
        "system_prompt": "prompt",
        "context": "[foo.py]\ndeterministic context",
        "project_context": "[PROJECT_CONTEXT]\nuserspace C library",
        "tool_evidence": "[RAG_TOOL_RESULTS]\nextra context",
        "use_retrieval_context": True,
    }

    review_node_llm(
        state,
        structured_node=_DummyNode(),
        fallback_node=None,
    )

    assert "deterministic context" in captured["body_text"]
    assert "userspace C library" in captured["body_text"]
    assert "extra context" in captured["body_text"]


def test_review_langchain_tools_only_expose_rag():
    class _Toolbox:
        def has(self, name):
            return name == "rag_search"

        def rag_search(self, query, *, retriever_code=None, retriever_docs=None):
            return query

    tools, _ = build_review_langchain_tools(_Toolbox())

    assert [tool.name for tool in tools] == ["rag_search"]


def test_review_tool_phase_runs_rag_search():
    captured = {}

    class _Toolbox:
        def has(self, name):
            return name == "rag_search"

        def rag_search(self, query, *, retriever_code=None, retriever_docs=None):
            captured["query"] = query
            return "[CODE_RAG]\ncode\n\n[DOCS_RAG]\ndocs"

    class _ToolModel:
        def __init__(self):
            self.turn = 0

        def invoke(self, _messages):
            self.turn += 1
            if self.turn == 1:
                return type(
                    "Msg",
                    (),
                    {
                        "tool_calls": [
                            {
                                "name": "rag_search",
                                "id": "tool-1",
                                "args": {"query": "what callers reach this auth path?"},
                            }
                        ],
                        "content": "",
                    },
                )()
            return type("Msg", (), {"tool_calls": [], "content": "done"})()

    class _ChatModel:
        def bind_tools(self, _tools):
            return _ToolModel()

    tools, tools_by_name = build_review_langchain_tools(_Toolbox())
    out = run_review_tool_phase(
        chat_model=_ChatModel(),
        tools=tools,
        tools_by_name=tools_by_name,
        system_prompt="prompt",
        body_text="body",
    )

    assert "callers reach this auth path" in captured["query"]
    assert "[RAG_TOOL_RESULTS]" in out["tool_evidence"]
    assert "[RAG_TOOL_QUERIES]" in out["tool_evidence"]


def test_review_langchain_tools_emit_debug_callback():
    events = []

    class _Toolbox:
        def has(self, name):
            return name == "rag_search"

        def rag_search(self, query, *, retriever_code=None, retriever_docs=None):
            return f"result for {query}"

    tools, tools_by_name = build_review_langchain_tools(
        _Toolbox(),
        debug_callback=events.append,
    )

    result = tools_by_name["rag_search"].invoke({"query": "what is this project?"})

    assert "result for" in result
    assert events
    assert events[0]["event"] == "tool_call"
    assert events[0]["tool_name"] == "rag_search"


def test_review_node_collect_tool_evidence_uses_only_rag():
    captured = {}

    class _Toolbox:
        def has(self, name):
            return name == "rag_search"

        def rag_search(self, query, *, retriever_code=None, retriever_docs=None):
            captured["query"] = query
            return "[CODE_RAG]\ncode\n\n[DOCS_RAG]\ndocs"

    class _ToolChat:
        def bind_tools(self, _tools):
            return self

        def invoke(self, _messages):
            if not hasattr(self, "_seen"):
                self._seen = True
                return type(
                    "Msg",
                    (),
                    {
                        "tool_calls": [
                            {
                                "name": "rag_search",
                                "id": "tool-1",
                                "args": {"query": "what trust boundary applies here?"},
                            }
                        ],
                        "content": "",
                    },
                )()
            return type("Msg", (), {"tool_calls": [], "content": "done"})()

    state = {
        "file_path": "src/auth.py",
        "snippet": "def check_token(user_token):\n    return validate_token(user_token)\n",
        "mode": "file",
        "context": "[src/auth.py]\ndeterministic context",
        "retriever_code": object(),
        "retriever_docs": object(),
        "use_retrieval_context": True,
    }

    out = review_node_collect_tool_evidence(
        state,
        chat_model=_ToolChat(),
        toolbox=_Toolbox(),
        tool_system_prompt="prompt",
    )

    assert "trust boundary applies" in captured["query"]
    assert "[RAG_TOOL_RESULTS]" in out["tool_evidence"]


def test_review_node_collect_project_context_uses_static_rag_query():
    captured = {}
    events = []

    class _Toolbox:
        def has(self, name):
            return name == "rag_search"

        def rag_search(self, query, *, retriever_code=None, retriever_docs=None):
            captured["query"] = query
            captured["retriever_code"] = retriever_code
            captured["retriever_docs"] = retriever_docs
            return "[CODE_RAG]\nuserspace library auth helpers\n\n[DOCS_RAG]\ncomponent trust assumptions"

    state = {
        "file_path": "src/auth.py",
        "snippet": "def check_token(user_token):\n    return validate_token(user_token)\n",
        "mode": "file",
        "retriever_code": object(),
        "retriever_docs": object(),
        "use_retrieval_context": True,
        "debug_callback": events.append,
    }

    out = review_node_collect_project_context(
        state,
        toolbox=_Toolbox(),
    )

    assert (
        "What project, subsystem, or component does this code belong to?"
        in captured["query"]
    )
    assert (
        "kernel, driver, firmware, runtime, service, userspace library"
        in captured["query"]
    )
    assert "[PROJECT_CONTEXT]" in out["project_context"]
    assert events
    assert events[0]["tool_name"] == "project_context_rag"


def test_triage_node_retrieve_uses_shared_rag_tool():
    captured = {}

    class _Toolbox:
        def has(self, name):
            return name == "rag_search"

        def rag_search(self, query, *, retriever_code=None, retriever_docs=None):
            captured["query"] = query
            captured["retriever_code"] = retriever_code
            captured["retriever_docs"] = retriever_docs
            return "[CODE_RAG]\ncode\n\n[DOCS_RAG]\ndocs"

    state = {
        "finding_rule_id": "R1",
        "finding_file_path": "a.c",
        "finding_line": 1,
        "finding_message": "msg",
        "finding_snippet": "code",
        "retriever_code": object(),
        "retriever_docs": object(),
        "use_retrieval_context": True,
    }

    out = triage_node_retrieve(state, toolbox=_Toolbox())

    assert "[CODE_RAG]" in out["context"]
    assert captured["retriever_code"] is state["retriever_code"]
    assert captured["retriever_docs"] is state["retriever_docs"]


def test_triage_user_prompt_omits_rag_context_in_no_index_mode():
    prompt = _build_user_prompt(
        {
            "finding_rule_id": "R1",
            "finding_file_path": "a.c",
            "finding_line": 1,
            "finding_message": "msg",
            "finding_snippet": "code",
            "context": "should not appear",
            "use_retrieval_context": False,
        }
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
        {
            "finding_rule_id": "R1",
            "finding_file_path": "a.c",
            "finding_line": 1,
            "finding_message": "msg",
            "finding_snippet": "code",
            "context": "should not appear",
            "use_retrieval_context": False,
            "triage_system_prompt": "system",
            "triage_decision_prompt": (
                "Given the finding details, RAG context, and tool outputs, return a final triage decision.\n\n"
                "{triage_input}\n\nTool Outputs:\n{tool_outputs}\n"
            ),
            "evidence_pack": "tools",
        },
        decision_model=_DecisionModel(),
    )

    combined = captured["system"] + "\n" + captured["user"]
    assert "RAG Context:" not in combined
