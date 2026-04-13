# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import pytest

from metis.engine.tools import build_toolbox, get_tool_definitions, registry
from metis.engine.tools.base import ToolContext, ToolDefinition


def test_tool_definitions_expose_named_tools():
    defs = get_tool_definitions()
    names = {tool.name for tool in defs}

    assert names == {"grep", "find_name", "cat", "sed", "rag_search"}
    assert all(tool.domains == ("code_evidence", "triage_evidence") for tool in defs)


def test_build_toolbox_for_policy_exposes_list_and_invocation(tmp_path):
    codebase = tmp_path / "src" / "metis" / "sarif"
    codebase.mkdir(parents=True)
    (codebase / "a.c").write_text("alpha\nbeta\n", encoding="utf-8")

    toolbox = build_toolbox(
        policy="code_evidence", codebase_path=str(codebase), max_chars=200
    )

    assert toolbox.list_tools() == ("cat", "find_name", "grep", "rag_search", "sed")
    assert toolbox.has("grep") is True
    assert any(
        line.endswith("a.c:2:beta") for line in toolbox.grep("beta", "src").splitlines()
    )
    assert toolbox.describe("grep") == {"backend": "shell_grep"}
    assert toolbox.describe_call("grep", pattern=r"beta\b", path="src") == {
        "backend": "python_regex"
    }


def test_build_toolbox_rag_search_exposes_code_and_docs_sections(tmp_path):
    toolbox = build_toolbox(policy="code_evidence", codebase_path=str(tmp_path))

    class _Doc:
        def __init__(self, text, source):
            self.page_content = text
            self.metadata = {"source": source}

    class _Retriever:
        def __init__(self, label):
            self._label = label

        def get_relevant_documents(self, query):
            return [_Doc(f"{self._label} hit for {query}", f"{self._label}.txt")]

    output = toolbox.rag_search(
        "memory safety",
        retriever_code=_Retriever("code"),
        retriever_docs=_Retriever("docs"),
    )

    assert "[CODE_RAG]" in output
    assert "[DOCS_RAG]" in output
    assert "memory safety" in output


def test_build_toolbox_rag_search_gracefully_handles_missing_retrievers(tmp_path):
    toolbox = build_toolbox(policy="code_evidence", codebase_path=str(tmp_path))

    output = toolbox.rag_search("bounds checks")

    assert "retrieval unavailable" in output


def test_toolbox_without_hides_named_tool(tmp_path):
    toolbox = build_toolbox(policy="code_evidence", codebase_path=str(tmp_path))

    hidden = toolbox.without("rag_search")

    assert hidden.has("rag_search") is False
    assert "rag_search" not in hidden.list_tools()


def test_build_toolbox_rejects_unknown_policy(tmp_path):
    with pytest.raises(ValueError, match="Unknown tool policy"):
        build_toolbox(policy="bogus", codebase_path=str(tmp_path))


def test_validate_registry_rejects_duplicate_names(tmp_path):
    context = ToolContext(codebase_path=str(tmp_path))
    providers = registry._build_providers(context)
    defs = (
        ToolDefinition("grep", ("triage",), "static", "grep"),
        ToolDefinition("grep", ("triage",), "static", "sed"),
    )

    with pytest.raises(ValueError, match="Duplicate tool name"):
        registry._validate_registry(defs, providers)


def test_validate_registry_rejects_unknown_provider(tmp_path):
    defs = (ToolDefinition("grep", ("triage",), "missing", "grep"),)

    with pytest.raises(ValueError, match="Unknown tool provider"):
        registry._validate_registry(defs, providers={})


def test_validate_registry_rejects_missing_operation(tmp_path):
    context = ToolContext(codebase_path=str(tmp_path))
    providers = registry._build_providers(context)
    defs = (ToolDefinition("grep", ("triage",), "static", "missing_method"),)

    with pytest.raises(ValueError, match="missing operation"):
        registry._validate_registry(defs, providers)


def test_validate_policy_map_rejects_unknown_tool_name():
    defs = get_tool_definitions()
    with pytest.raises(ValueError, match="references unknown tool"):
        registry._validate_policy_map(defs, {"code_evidence": ("missing_tool",)})


def test_validate_policy_map_rejects_duplicate_tool_name():
    defs = get_tool_definitions()
    with pytest.raises(ValueError, match="contains duplicate tool"):
        registry._validate_policy_map(defs, {"code_evidence": ("grep", "grep")})
