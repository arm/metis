# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import json
from llama_index.core.node_parser import CodeSplitter
from llama_index.core.schema import Document

from metis.plugins.base import BaseLanguagePlugin


class IpynbPlugin(BaseLanguagePlugin):
    def __init__(self, plugin_config):
        self.plugin_config = plugin_config

    def get_name(self):
        return "ipynb"

    def can_handle(self, extension):
        return extension.lower() == ".ipynb"

    def get_supported_extensions(self):
        return [".ipynb"]

    def get_splitter(self):
        splitting_cfg = (
            self.plugin_config.get("plugins", {})
            .get(self.get_name(), {})
            .get("splitting", {})
        )
        return NotebookCodeSplitter(
            chunk_lines=splitting_cfg["chunk_lines"],
            chunk_lines_overlap=splitting_cfg["chunk_lines_overlap"],
            max_chars=splitting_cfg["max_chars"],
        )

    def get_prompts(self):
        return (
            self.plugin_config.get("plugins", {})
            .get(self.get_name(), {})
            .get("prompts", {})
        )


class NotebookCodeSplitter(CodeSplitter):
    def __init__(self, **kwargs):
        super().__init__(language="python", **kwargs)

    def get_nodes_from_documents(self, documents, show_progress=False, **kwargs):
        processed_docs = []
        for doc in documents:
            processed_docs.append(self._extract_notebook_code(doc))
        return super().get_nodes_from_documents(processed_docs, show_progress, **kwargs)

    def _extract_notebook_code(self, doc):
        try:
            notebook = json.loads(doc.text)
            code_cells = []
            for i, cell in enumerate(notebook.get("cells", [])):
                if cell.get("cell_type") == "code":
                    source = "".join(cell.get("source", []))
                    if source.strip():
                        code_cells.append(f"# Cell {i+1}\n{source}")
            extracted_code = "\n\n".join(code_cells)
            return Document(text=extracted_code, metadata=doc.metadata, id_=doc.id_)
        except (json.JSONDecodeError, KeyError):
            return doc
