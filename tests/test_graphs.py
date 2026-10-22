# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import json
from unittest.mock import Mock

import pytest

from metis.engine.ask import AskGraph
from metis.engine.ask.models import AskRequest
from metis.engine.llm_runner import rendered_prompt_token_count
from metis.engine.model_tool_runner import ModelInputLimitError
from metis.engine.nodes.simple_llm_review.graph import (
    ReviewGraph,
    _normalize_reviews,
    review_node_build_prompt,
    review_node_llm,
    review_node_parse,
)
from metis.engine.stages.review.models import ReviewState
from metis.providers.base import ChatProvider
from metis.sarif.triage import TRIAGE_ANNOTATION_KEYS


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


@pytest.mark.parametrize("as_text", [False, True])
@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"findings": [{"issue": "buffer overflow"}]},
        {"reviews": [], "findings": [{"issue": "buffer overflow"}]},
    ],
)
def test_review_parser_rejects_unrecognized_top_level_fields(payload, as_text):
    raw = json.dumps(payload) if as_text else payload

    assert _normalize_reviews(raw) is None


def test_review_parser_preserves_explicit_empty_and_partial_review_entries():
    assert _normalize_reviews({"reviews": []}) == []

    reviews = _normalize_reviews({"reviews": [{"issue": "buffer overflow"}]})

    assert reviews is not None and len(reviews) == 1
    assert reviews[0]["issue"] == "buffer overflow"
    assert reviews[0]["confidence"] == 0.0


@pytest.mark.parametrize("as_text", [False, True])
def test_review_parser_discards_reserved_triage_annotations(as_text):
    payload = {
        "reviews": [
            {
                "issue": "Check input",
                "customEvidence": "preserved",
                **{key: True for key in TRIAGE_ANNOTATION_KEYS},
            }
        ]
    }

    reviews = _normalize_reviews(json.dumps(payload) if as_text else payload)

    assert reviews is not None and len(reviews) == 1
    assert not TRIAGE_ANNOTATION_KEYS.intersection(reviews[0])
    assert reviews[0]["customEvidence"] == "preserved"


def test_review_body_includes_threat_model_context():
    from metis.engine.nodes.simple_llm_review.graph import _build_body_text

    body = _build_body_text(
        {
            "file_path": "src/main.c",
            "snippet": "int main(void) { return 0; }",
            "threat_model_context": [
                {
                    "summary": "Authoritative policy says images are untrusted.",
                    "metadata": {
                        "authority": "authoritative",
                        "scope_clauses": [],
                    },
                }
            ],
        }
    )

    assert "THREAT_MODEL_CONTEXT:" in body
    assert "Authoritative policy says images are untrusted." in body
    assert body.index("THREAT_MODEL_CONTEXT:") < body.index("SNIPPET:")


def test_simple_review_checkpoint_key_tracks_effective_input():
    class Provider(ChatProvider):
        def __init__(self) -> None:
            self.config = {"base_url": "https://first.example"}
            self.exact_tokens = False

        def get_chat_model(self, **_kwargs):
            return Mock()

        def count_tokens(self, text: str, model: str | None = None) -> int:
            return len(text) if self.exact_tokens else max(1, len(text) // 4)

    provider = Provider()
    graph = ReviewGraph(
        provider,
        {"general_prompts": {"security_review_report": "Report."}},
        None,
        "",
        "test-model",
        5,
        chat_model_kwargs={"reasoning_effort": "medium"},
    )
    request = {
        "file_path": "/repo/a.c",
        "snippet": "int a;",
        "language_prompts": {
            "security_review_file": "Review. [[REVIEW_SCHEMA_FIELDS]]"
        },
        "threat_model_context": [],
    }

    first = graph.checkpoint_key(request)

    assert first == graph.checkpoint_key(dict(request))
    assert first != graph.checkpoint_key({**request, "snippet": "int b;"})
    provider.config["base_url"] = "https://second.example"
    assert first != graph.checkpoint_key(request)
    provider.config["base_url"] = "https://first.example"
    provider.exact_tokens = True
    assert first != graph.checkpoint_key(request)

    graph.model_tools = (object(),)
    assert graph.checkpoint_key(request) is None


@pytest.mark.parametrize("model_tools", [(), (object(),)])
def test_patch_context_can_be_omitted_without_losing_source_anchors(model_tools):
    provider = Mock()
    provider.count_tokens.side_effect = lambda text, **_: len(text)
    graph = ReviewGraph(
        provider, {}, None, "", "test-model", 4000, model_tools=model_tools
    )
    graph._prompt_runner.invoke = Mock(
        return_value=[
            {
                "code_snippet": "int target;",
                "start_line": 1001,
                "end_line": 1001,
            }
        ]
    )
    diff = "--- a/target.c\n+++ b/target.c\n@@ -1001 +1001 @@\n-int target;\n+int target = 1;\n"

    result = graph.review(
        {
            "file_path": "target.c",
            "mode": "patch",
            "snippet": diff,
            "original_file": "int filler;\n" * 1000 + "int target;\n",
            "language_prompts": {
                "security_review_file": "Review. [[REVIEW_SCHEMA_FIELDS]]",
                "security_review_checks": "Check.",
            },
        }
    )

    graph._prompt_runner.invoke.assert_called_once()
    body = graph._prompt_runner.invoke.call_args.args[0].variables["body_text"]
    assert "FILE: target.c" in body
    assert diff in body and "int filler;" not in body
    assert result["reviews"][0]["anchor"]["start_line"] == 1001


def test_simple_review_without_tools_bounds_complete_prompts():
    provider = Mock()
    provider.count_tokens.side_effect = lambda text, **_: len(text)
    graph = ReviewGraph(provider, {}, None, "", "test-model", 4000)

    def respond(request):
        assert (
            rendered_prompt_token_count(
                graph._token_counter,
                system_prompt=request.system_prompt,
                user_prompt=request.user_prompt,
                variables=request.variables,
            )
            <= graph.max_token_length
        )
        return []

    graph._prompt_runner.invoke = Mock(side_effect=respond)
    request = {
        "file_path": "target.c",
        "snippet": "int value;\n" * 500,
        "language_prompts": {
            "security_review_file": "Review. [[REVIEW_SCHEMA_FIELDS]]",
            "security_review_checks": "Check.",
        },
    }

    assert graph.review(request)["reviews"] == []
    assert graph._prompt_runner.invoke.call_count > 1

    graph.max_token_length = 1
    graph._prompt_runner.invoke.reset_mock()
    with pytest.raises(ModelInputLimitError, match="prompt context exceeds"):
        graph.review(request)
    graph._prompt_runner.invoke.assert_not_called()
