# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import json
from collections.abc import Sequence
from typing import Any

from llama_index.core.node_parser import CodeSplitter
from llama_index.core.schema import BaseNode
from llama_index.core.schema import Document

from metis.plugins.base import ConfigBackedLanguagePlugin
from metis.plugins.base import build_code_splitter


class IpynbPlugin(ConfigBackedLanguagePlugin):
    NAME = "ipynb"

    def get_splitter(self) -> "NotebookCodeSplitter":
        splitting_cfg = self._plugin_section().get("splitting", {})
        return NotebookCodeSplitter(
            build_code_splitter("python", splitting_cfg),
        )


class NotebookCodeSplitter:
    def __init__(self, splitter: CodeSplitter) -> None:
        self._splitter = splitter

    def get_nodes_from_documents(
        self,
        documents: Sequence[Document],
        show_progress: bool = False,
        **kwargs: Any,
    ) -> list[BaseNode]:
        processed_docs = [self._extract_notebook_code(doc) for doc in documents]
        return self._splitter.get_nodes_from_documents(
            processed_docs,
            show_progress=show_progress,
            **kwargs,
        )

    @staticmethod
    def _extract_notebook_code(doc: Document) -> Document:
        try:
            notebook = json.loads(doc.text)
            code_cells = []
            for i, cell in enumerate(notebook.get("cells", [])):
                if cell.get("cell_type") == "code":
                    source = "".join(cell.get("source", []))
                    if source.strip():
                        code_cells.append(f"# Cell {i + 1}\n{source}")
            extracted_code = "\n\n".join(code_cells)
            return Document(text=extracted_code, metadata=doc.metadata, id_=doc.id_)
        except json.JSONDecodeError:
            return doc
