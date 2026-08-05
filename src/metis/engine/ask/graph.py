# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from functools import partial
from typing import Any

from langgraph.graph import END
from langgraph.graph import StateGraph

from .models import AskRequest
from .models import AskState
from .retrieval import retrieve_text
from .retrieval import synthesize_context


def ask_node_retrieve(state: AskState) -> AskState:
    question = state.get("question", "")
    code = retrieve_text(state["retriever_code"], question)
    docs = retrieve_text(state["retriever_docs"], question)
    updated: AskState = dict(state)
    updated["context"] = synthesize_context(code, docs)
    updated["code"] = code
    updated["docs"] = docs
    return updated


class AskGraph:
    def __init__(self, llm_provider: object, llama_query_model: str) -> None:
        self.llm_provider = llm_provider
        self.llama_query_model = llama_query_model
        self._app: Any = None

    def _get_app(self) -> Any:
        if self._app is None:
            graph = StateGraph(AskState)
            graph.add_node("retrieve", partial(ask_node_retrieve))
            graph.set_entry_point("retrieve")
            graph.add_edge("retrieve", END)
            self._app = graph.compile()
        return self._app

    def ask(self, request: AskRequest) -> dict[str, str]:
        output = self._get_app().invoke(
            {
                "question": request["question"],
                "retriever_code": request["retriever_code"],
                "retriever_docs": request["retriever_docs"],
            }
        )
        return {
            "code": output.get("code", ""),
            "docs": output.get("docs", ""),
            "context": output.get("context", ""),
        }
