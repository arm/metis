# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import logging
from functools import partial

from langgraph.graph import StateGraph, END

from .utils import retrieve_text, synthesize_context
from .types import AskRequest, AskState


logger = logging.getLogger("metis")


def ask_node_retrieve(state: AskState) -> AskState:
    question = state.get("question", "")
    code = retrieve_text(state["retriever_code"], question)
    docs = retrieve_text(state["retriever_docs"], question)

    context = synthesize_context(code, docs)
    s: AskState = dict(state)
    s["context"] = context
    s["code"] = code or ""
    s["docs"] = docs or ""
    return s


class AskGraph:
    def __init__(self, llm_provider, llama_query_model):
        self.llm_provider = llm_provider
        self.llama_query_model = llama_query_model
        self._app = None

    def _get_app(self):
        if self._app is not None:
            return self._app
        graph = StateGraph(AskState)

        graph.add_node("retrieve", partial(ask_node_retrieve))
        graph.set_entry_point("retrieve")
        graph.add_edge("retrieve", END)
        self._app = graph.compile()
        return self._app

    def ask(self, request: AskRequest):
        app = self._get_app()
        out = app.invoke(
            {
                "question": request["question"],
                "retriever_code": request["retriever_code"],
                "retriever_docs": request["retriever_docs"],
            }
        )
        # Return separate code/docs contexts for CLI printing compatibility
        return {
            "code": out.get("code", ""),
            "docs": out.get("docs", ""),
            "context": out.get("context", ""),
        }
