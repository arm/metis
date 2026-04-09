# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import logging
import os

import unidiff
from llama_index.core import SimpleDirectoryReader, VectorStoreIndex
from llama_index.core.schema import Document

from metis.exceptions import ParsingError
from metis.utils import read_file_content

from .diff_utils import extract_content_from_diff
from .helpers import prepare_nodes_iter
from .repository import EngineRepository
from .runtime import EngineConfig, EngineState

logger = logging.getLogger("metis")


class IndexingService:
    def __init__(
        self,
        config: EngineConfig,
        state: EngineState,
        repository: EngineRepository,
    ):
        self._config = config
        self._state = state
        self._repository = repository

    def index_codebase(self):
        self.index_prepare_nodes()
        self.index_finalize_embeddings()

    def count_index_items(self) -> int:
        docs_exts = self._config.plugin_config.get("docs", {}).get(
            "supported_extensions", [".md"]
        )
        code_count = len(self._repository.get_code_files())

        doc_count = 0
        base_path = os.path.abspath(self._config.codebase_path)
        for _, _, files in os.walk(base_path):
            for file_name in files:
                if os.path.splitext(file_name)[1].lower() in docs_exts:
                    doc_count += 1

        return code_count + doc_count

    def index_prepare_nodes_iter(self):
        docs_supported_exts = self._config.plugin_config.get("docs", {}).get(
            "supported_extensions", [".md"]
        )
        code_supported_exts = self._repository.get_all_supported_code_extensions()

        logger.info(f"Indexing codebase at: {self._config.codebase_path}")
        reader = SimpleDirectoryReader(
            input_dir=self._config.codebase_path,
            recursive=True,
            required_exts=code_supported_exts + docs_supported_exts,
            filename_as_id=True,
        )
        documents = reader.load_data()
        logger.info(
            f"Loaded {len(documents)} documents from {self._config.codebase_path}"
        )

        self._config.vector_backend.init()
        doc_splitter = self._repository.get_doc_splitter()
        metisignore_spec = self._repository.load_metisignore()
        base_path = os.path.abspath(self._config.codebase_path)
        parent_dir = os.path.dirname(base_path)
        code_docs = []
        doc_docs = []
        for doc in documents:
            ext = os.path.splitext(doc.id_)[1].lower()
            new_id = os.path.relpath(doc.id_, parent_dir)
            doc.doc_id = new_id
            doc.id_ = new_id

            if metisignore_spec and metisignore_spec.match_file(
                os.path.join(parent_dir, new_id)
            ):
                continue

            if ext in docs_supported_exts:
                doc_docs.append(doc)
            elif ext in code_supported_exts:
                code_docs.append(doc)

        nodes_code, nodes_docs = yield from prepare_nodes_iter(
            code_docs,
            doc_docs,
            self._repository.get_plugin_for_extension,
            self._repository.get_splitter_cached,
            doc_splitter,
        )

        self._state.pending_nodes = (nodes_code, nodes_docs)
        return

    def index_prepare_nodes(self):
        for _ in self.index_prepare_nodes_iter():
            pass

    def index_finalize_embeddings(self):
        pending = self._state.pending_nodes
        if not pending:
            return
        nodes_code, nodes_docs = pending
        storage_context_code, storage_context_docs = (
            self._config.vector_backend.get_storage_contexts()
        )
        VectorStoreIndex(
            nodes_code,
            storage_context=storage_context_code,
            embed_model=self._config.embed_model_code,
            **self._config.usage_runtime.hooks.embed_model_kwargs(),
        )

        VectorStoreIndex(
            nodes_docs,
            storage_context=storage_context_docs,
            embed_model=self._config.embed_model_docs,
            **self._config.usage_runtime.hooks.embed_model_kwargs(),
        )
        self._state.pending_nodes = None

    def update_index(self, patch_text):
        try:
            patch_set = unidiff.PatchSet.from_string(patch_text)
            logger.info("Parsed the provided patch string successfully.")
        except Exception as e:
            raise ParsingError(f"Error parsing patch string: {e}")
        self._config.vector_backend.init()
        storage_context_code, storage_context_docs = (
            self._config.vector_backend.get_storage_contexts()
        )

        index_code = VectorStoreIndex.from_vector_store(
            self._config.vector_backend.vector_store_code,
            storage_context=storage_context_code,
            embed_model=self._config.embed_model_code,
            **self._config.usage_runtime.hooks.embed_model_kwargs(),
        )
        index_docs = VectorStoreIndex.from_vector_store(
            self._config.vector_backend.vector_store_docs,
            storage_context=storage_context_docs,
            embed_model=self._config.embed_model_docs,
            **self._config.usage_runtime.hooks.embed_model_kwargs(),
        )

        doc_splitter = self._repository.get_doc_splitter()

        for diff_file in patch_set:
            if diff_file.is_binary_file:
                continue
            doc_id = os.path.join(
                os.path.basename(os.path.abspath(self._config.codebase_path)),
                diff_file.path,
            )
            ext = os.path.splitext(doc_id)[1].lower()
            target_index = (
                index_code
                if ext in self._repository.get_all_supported_code_extensions()
                else index_docs
            )

            if diff_file.is_removed_file:
                target_index.delete_ref_doc(doc_id, delete_from_docstore=True)
            else:
                file_path = os.path.join(self._config.codebase_path, diff_file.path)
                file_content = read_file_content(file_path)
                if not file_content and diff_file.is_added_file:
                    file_content = extract_content_from_diff(diff_file)
                if not file_content:
                    logger.warning("No content available for %s", diff_file.path)
                    continue
                doc = Document(
                    text=file_content,
                    metadata={"file_name": diff_file.path},
                    id_=doc_id,
                )

                if diff_file.is_added_file:
                    if ext in self._repository.get_all_supported_code_extensions():
                        plugin = self._repository.get_plugin_for_extension(ext)
                        if not plugin:
                            continue
                        splitter = self._repository.get_splitter_cached(plugin)
                        try:
                            nodes = splitter.get_nodes_from_documents([doc])
                        except Exception as e:
                            logger.warning(
                                f"Could not parse code with language {plugin.get_name()} for file {doc.id_} (ext {ext}): {e}"
                            )
                            continue
                    else:
                        nodes = doc_splitter.get_nodes_from_documents([doc])
                    target_index.insert_nodes(nodes)
                else:
                    target_index.refresh_ref_docs([doc])
                target_index.docstore.set_document_hash(doc.id_, doc.hash)
        logger.info("Index update complete based on the provided patch diff.")
