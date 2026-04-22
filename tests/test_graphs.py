# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.engine.graphs.ask import AskGraph
from metis.engine.graphs.review import (
    review_node_collect_baseline_context,
    review_node_collect_tool_evidence,
    review_node_build_prompt,
    review_node_llm,
    review_node_parse,
)
from metis.engine.graphs.review_tools import (
    build_review_langchain_tools,
    run_review_tool_phase,
)
from metis.engine.graphs.review_retrieval import (
    assess_review_context_quality,
    compute_review_obligation_coverage,
)
from metis.engine.graphs.triage.llm import _build_user_prompt, triage_node_llm
from metis.engine.graphs.triage.retrieval import triage_node_retrieve


class _Doc:
    def __init__(self, text, source="doc.txt"):
        self.page_content = text
        self.metadata = {"source": source}


class DummyRetriever:
    def __init__(self, label, source="doc.txt"):
        self._label = label
        self._source = source

    def get_relevant_documents(self, q):
        return [_Doc(f"{self._label} context for: {q}", source=self._source)]


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
        "retriever_code": object(),
        "retriever_docs": object(),
    }

    # Step 1: build prompt
    language_prompts = {
        "security_review_file": "Do a security review [[REVIEW_SCHEMA_FIELDS]]",
        "security_review_checks": "Checks...",
        "validation_review": "Validate...",
    }
    s2 = review_node_build_prompt(
        state,
        language_prompts=language_prompts,
        default_prompt_key="security_review_file",
        report_prompt="",
        custom_prompt_text=None,
        custom_guidance_precedence="",
        schema_prompt_section='- "issue": desc',
    )
    assert "system_prompt" in s2

    # Step 2: run LLM review (stub)
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

    # Step 3: parse
    s4 = review_node_parse(s3)
    assert s4.get("parsed_reviews") and isinstance(s4["parsed_reviews"], list)


def test_review_langchain_tools_hide_rag_when_retrieval_disabled():
    class _Toolbox:
        def has(self, name):
            return name in {"sed", "cat", "grep", "find_name"}

        def sed(self, path, start_line, end_line):
            return ""

        def cat(self, path):
            return ""

        def grep(self, pattern, path):
            return ""

        def find_name(self, name, max_results=20):
            return []

    tools, _ = build_review_langchain_tools(_Toolbox())

    assert {tool.name for tool in tools} == {"sed", "cat", "grep", "find_name"}


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


def test_review_node_llm_omits_context_section_in_no_index_mode():
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

    assert "CONTEXT:" not in captured["body_text"]


def test_review_node_llm_includes_baseline_context_and_evidence_frame():
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
        "baseline_context": "[foo.py]\ncallers validate input",
        "review_evidence_frame": "[OBLIGATION_COVERAGE]\n- callers or wrappers: covered",
        "tool_evidence": "[SUMMARY]\nextra",
    }

    review_node_llm(
        state,
        structured_node=_DummyNode(),
        fallback_node=None,
    )

    assert "BASELINE_CONTEXT:" in captured["body_text"]
    assert "REVIEW_EVIDENCE_FRAME:" in captured["body_text"]
    assert "TOOL_EVIDENCE:" in captured["body_text"]


def test_review_node_collect_baseline_context_builds_hybrid_context():
    state = {
        "file_path": "src/auth.py",
        "relative_file": "src/auth.py",
        "snippet": "def check_token(user_token):\n    return validate_token(user_token)\n",
        "mode": "file",
        "retriever_code": DummyRetriever("src/auth.py check_token validate_token"),
        "retriever_docs": DummyRetriever("security docs validate_token contract"),
        "use_retrieval_context": True,
    }

    out = review_node_collect_baseline_context(state)

    assert "Candidate symbols:" in out["baseline_context_query"]
    assert out["baseline_context"]
    assert "[OBLIGATION_COVERAGE]" in out["review_evidence_frame"]
    assert "code=" in out["baseline_context_quality"]


def test_review_node_collect_baseline_context_drops_low_signal_retrieval():
    class _StaticRetriever:
        def __init__(self, text, source):
            self._text = text
            self._source = source

        def get_relevant_documents(self, _query):
            return [_Doc(self._text, source=self._source)]

    state = {
        "file_path": "src/auth.py",
        "relative_file": "src/auth.py",
        "snippet": "def check_token(user_token):\n    return validate_token(user_token)\n",
        "mode": "file",
        "retriever_code": _StaticRetriever("completely unrelated prose", "other.txt"),
        "retriever_docs": _StaticRetriever("more unrelated prose", "docs.txt"),
        "use_retrieval_context": True,
    }

    out = review_node_collect_baseline_context(state)

    assert out["baseline_context"] == ""
    assert "low-signal" in out["baseline_context_quality"]


def test_review_context_quality_accepts_symbolic_overlap_without_filename():
    accepted, quality = assess_review_context_quality(
        "[CODE_RAG]\ncheck_token callers validate_token guard user token\n[DOCS_RAG]\nauthorization boundary",
        file_path="src/auth.py",
        symbols=["check_token", "validate_token"],
        focus_terms=["auth", "validate", "token"],
    )

    assert accepted is True
    assert "query-tokens=" in quality or "obligations=" in quality


def test_review_tool_phase_blocks_rag_in_first_stage():
    class _Toolbox:
        def has(self, name):
            return name in {"sed", "cat", "grep", "find_name", "rag_search"}

        def sed(self, path, start_line, end_line):
            return ""

        def cat(self, path):
            return ""

        def grep(self, pattern, path):
            return ""

        def find_name(self, name, max_results=20):
            return []

        def rag_search(self, query, *, retriever_code=None, retriever_docs=None):
            raise AssertionError("rag_search should be blocked in stage 1")

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
                                "args": {"query": "what validates auth.py"},
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

    assert "disabled in review stage 1" in out["tool_evidence"]
    assert "[RETRIEVAL_NOTES]" in out["tool_evidence"]


def test_review_tool_phase_shapes_and_rejects_low_signal_rag():
    captured = {}

    class _Toolbox:
        def has(self, name):
            return name in {"sed", "cat", "grep", "find_name", "rag_search"}

        def sed(self, path, start_line, end_line):
            return "local"

        def cat(self, path):
            return "local"

        def grep(self, pattern, path):
            return "lookup"

        def find_name(self, name, max_results=20):
            return []

        def rag_search(self, query, *, retriever_code=None, retriever_docs=None):
            captured["query"] = query
            return "[CODE_RAG]\ncompletely unrelated prose\n\n[DOCS_RAG]\nmore unrelated prose"

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
                                "name": "cat",
                                "id": "tool-1",
                                "args": {"path": "src/auth.py"},
                            }
                        ],
                        "content": "",
                    },
                )()
            if self.turn == 2:
                return type(
                    "Msg",
                    (),
                    {
                        "tool_calls": [
                            {
                                "name": "grep",
                                "id": "tool-2",
                                "args": {"pattern": "validate_token", "path": "src"},
                            }
                        ],
                        "content": "",
                    },
                )()
            if self.turn == 3:
                return type(
                    "Msg",
                    (),
                    {
                        "tool_calls": [
                            {
                                "name": "rag_search",
                                "id": "tool-3",
                                "args": {"query": "what validates this"},
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
        review_search_context={
            "file_path": "src/auth.py",
            "mode": "file",
            "symbols": ["check_token", "validate_token"],
            "focus_terms": ["auth", "validate"],
            "baseline_query": "baseline question",
            "uncovered_obligations": [
                "callers or wrappers",
                "trust or privilege boundary",
            ],
        },
    )

    assert "Missing obligations:" in captured["query"]
    assert "src/auth.py" in captured["query"]
    assert "[RAG_REJECTED]" in out["tool_evidence"]
    assert "[RAG_CONTEXT]" in out["tool_evidence"]


def test_review_tool_phase_emits_typed_obligation_sections():
    class _Toolbox:
        def has(self, name):
            return name in {"sed", "cat", "grep", "find_name"}

        def sed(self, path, start_line, end_line):
            return ""

        def cat(self, path):
            return "caller wrapper validate auth boundary unresolved gap"

        def grep(self, pattern, path):
            return ""

        def find_name(self, name, max_results=20):
            return []

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
                                "name": "cat",
                                "id": "tool-1",
                                "args": {"path": "src/auth.py"},
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
        review_search_context={
            "file_path": "src/auth.py",
            "mode": "file",
            "symbols": ["check_token"],
            "focus_terms": ["auth", "validate"],
            "baseline_query": "baseline question",
            "uncovered_obligations": ["callers or wrappers"],
        },
    )

    assert "[RELATED_CALLERS]" in out["tool_evidence"]
    assert "[VALIDATION_GUARDS]" in out["tool_evidence"]
    assert "[TRUST_BOUNDARY]" in out["tool_evidence"]
    assert "[UNRESOLVED]" in out["tool_evidence"]


def test_review_node_collect_tool_evidence_updates_coverage_frame():
    class _Toolbox:
        def without(self, *_names):
            return self

        def has(self, _name):
            return True

    class _ToolChat:
        def bind_tools(self, _tools):
            return self

        def invoke(self, _messages):
            return type(
                "Msg",
                (),
                {"tool_calls": [], "content": "Callers validate auth boundary none"},
            )()

    state = {
        "file_path": "src/auth.py",
        "relative_file": "src/auth.py",
        "snippet": "def check_token(user_token):\n    return validate_token(user_token)\n",
        "mode": "file",
        "use_retrieval_context": True,
        "baseline_context": "[src/auth.py]\nvalidate_token checks auth",
        "baseline_context_quality": "code=accepted, docs=empty",
    }

    out = review_node_collect_tool_evidence(
        state,
        chat_model=_ToolChat(),
        toolbox=_Toolbox(),
        tool_system_prompt="prompt",
        tool_system_prompt_no_rag="prompt",
    )

    assert "[OBLIGATION_COVERAGE]" in out["review_evidence_frame"]
    assert "[MISSING_OBLIGATIONS]" in out["review_evidence_frame"]


def test_review_obligation_coverage_prefers_typed_sections():
    coverage = compute_review_obligation_coverage(
        "[RELATED_CALLERS]\ncheck_token wrapper\n\n[VALIDATION_GUARDS]\nvalidate token guard\n\n[TRUST_BOUNDARY]\nauth privilege boundary",
        symbols=["check_token", "validate_token"],
        focus_terms=["auth", "validate"],
    )

    assert coverage["callers or wrappers"] is True
    assert coverage["validation / sanitization / authorization checks"] is True
    assert coverage["trust or privilege boundary"] is True


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
