# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import logging
import os
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any

import unidiff
from llama_index.core import SimpleDirectoryReader
from llama_index.core.schema import Document

from metis.engine.diff_utils import extract_content_from_diff
from metis.engine.helpers import prepare_nodes_iter
from metis.engine.repository import EngineRepository
from metis.engine.runtime import EngineConfig
from metis.engine.runtime import EngineState
from metis.exceptions import ParsingError
from metis.utils import read_file_content

logger = logging.getLogger("metis")


class IndexingService:
    def __init__(
        self,
        config: EngineConfig,
        state: EngineState,
        repository: EngineRepository,
        *,
        get_embedding_models: Callable[[], tuple[Any, Any]],
        clear_retriever_cache: Callable[[], None] | None = None,
    ):
        self._config = config
        self._state = state
        self._repository = repository
        self._get_embedding_models = get_embedding_models
        self._clear_retriever_cache = clear_retriever_cache
        # Share publication/mutation ordering, including same-thread callbacks.
        self._mutation_lock = state.retriever_lock
        self._active_mutations = 0
        self._closed = False

    @contextmanager
    def _mutation(self) -> Iterator[None]:
        with self._mutation_lock:
            if self._closed:
                raise RuntimeError("Index capability is closed")
            self._active_mutations += 1
            failure: BaseException | None = None
            try:
                yield
            except BaseException as exc:
                failure = exc
                raise
            finally:
                self._active_mutations -= 1
                # A close requested from this backend call cannot wait for itself.
                if self._closed and not self._active_mutations:
                    try:
                        self._close_backend()
                    except BaseException as exc:
                        if failure is None:
                            raise
                        failure.add_note(f"Index cleanup also failed: {exc}")

    def close(self) -> None:
        with self._mutation_lock:
            if self._closed:
                return
            self._closed = True
            if self._active_mutations:
                raise RuntimeError(
                    "Cannot close the active index from its backend call"
                )
            self._close_backend()

    def _close_backend(self) -> None:
        close = getattr(self._config.vector_backend, "close", None)
        if callable(close):
            close()

    def _get_supported_input_files(
        self,
        docs_supported_exts: list[str],
    ) -> list[str]:
        base_path = os.path.abspath(self._config.codebase_path)
        docs_supported = {ext.lower() for ext in docs_supported_exts}
        metisignore_spec = self._repository.load_metisignore()
        selected = []

        for root, _, files in os.walk(base_path):
            for file_name in files:
                full_path = os.path.join(root, file_name)
                if os.path.islink(full_path) and not os.path.exists(full_path):
                    continue
                if self._repository.is_metisignored(full_path, spec=metisignore_spec):
                    continue
                ext = os.path.splitext(file_name)[1].lower()
                if (
                    ext in docs_supported
                    or self._repository.get_language_name_for_path(full_path)
                    is not None
                ):
                    selected.append(full_path)

        return selected

    def index_codebase(self) -> None:
        pending_before = self._state.pending_nodes
        try:
            self.index_prepare_nodes()
            self.index_finalize_embeddings()
        finally:
            if self._state.pending_nodes is not pending_before:
                self._state.pending_nodes = None

    def count_index_items(self) -> int:
        docs_exts = self._config.plugin_config.get("docs", {}).get(
            "supported_extensions", [".md"]
        )
        return len(self._get_supported_input_files(docs_exts))

    def index_prepare_nodes_iter(self):
        """Prepare nodes for this thread's next finalize call without changing the index."""
        if self._closed:
            raise RuntimeError("Index capability is closed")
        if self._state.pending_nodes is not None:
            raise RuntimeError(
                "Finish the pending index preparation before preparing again"
            )
        self._get_embedding_models()
        docs_supported_exts = [
            ext.lower()
            for ext in self._config.plugin_config.get("docs", {}).get(
                "supported_extensions", [".md"]
            )
        ]

        logger.info(f"Indexing codebase at: {self._config.codebase_path}")
        input_files = self._get_supported_input_files(docs_supported_exts)
        if not input_files:
            self._state.pending_nodes = ([], [])
            return
        reader = SimpleDirectoryReader(
            input_files=input_files,
            filename_as_id=True,
        )
        documents = reader.load_data()
        logger.info(
            f"Loaded {len(documents)} documents from {self._config.codebase_path}"
        )

        doc_splitter = self._repository.get_doc_splitter()
        base_path = os.path.abspath(self._config.codebase_path)
        parent_dir = os.path.dirname(base_path)
        code_docs = []
        doc_docs = []
        for doc in documents:
            file_path = doc.metadata.get("file_path") or doc.id_
            ext = os.path.splitext(file_path)[1].lower()
            new_id = os.path.relpath(doc.id_, parent_dir)
            doc.doc_id = new_id
            doc.id_ = new_id

            language_name = self._repository.get_language_name_for_path(file_path)
            if ext in docs_supported_exts:
                doc_docs.append(doc)
            elif language_name is not None:
                code_docs.append(doc)

        nodes_code, nodes_docs = yield from prepare_nodes_iter(
            code_docs,
            doc_docs,
            self._repository.get_plugin_for_path,
            self._repository.get_splitter_cached,
            doc_splitter,
        )

        self._state.pending_nodes = (nodes_code, nodes_docs)

    def index_prepare_nodes(self):
        for _ in self.index_prepare_nodes_iter():
            pass

    def index_finalize_embeddings(self):
        pending = self._state.pending_nodes
        if pending is None:
            raise RuntimeError("No pending index preparation for this thread")
        self._state.pending_nodes = None
        with self._mutation():
            embed_model_code, embed_model_docs = self._get_embedding_models()
            nodes_code, nodes_docs = pending
            self._config.vector_backend.init()
            reset_index = getattr(self._config.vector_backend, "reset_index", None)
            if callable(reset_index):
                if self._clear_retriever_cache is not None:
                    self._clear_retriever_cache()
                try:
                    reset_index()
                finally:
                    if self._clear_retriever_cache is not None:
                        self._clear_retriever_cache()
            self._config.vector_backend.index_nodes(
                nodes_code,
                nodes_docs,
                embed_model_code=embed_model_code,
                embed_model_docs=embed_model_docs,
                **self._config.usage_runtime.hooks.embed_model_kwargs(),
            )

    def update_index(self, patch_text):
        with self._mutation():
            embed_model_code, embed_model_docs = self._get_embedding_models()
            try:
                patch_set = unidiff.PatchSet.from_string(patch_text)
                logger.info("Parsed the provided patch string successfully.")
            except Exception as e:
                raise ParsingError(f"Error parsing patch string: {e}")
            self._config.vector_backend.init()

            index_code, index_docs = self._config.vector_backend.get_index_handles(
                embed_model_code=embed_model_code,
                embed_model_docs=embed_model_docs,
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
                language_name = self._repository.get_language_name_for_path(doc_id)
                target_index = index_code if language_name is not None else index_docs

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
                        if language_name is not None:
                            plugin = self._repository.get_plugin_for_path(doc_id)
                            if not plugin:
                                continue
                            splitter = self._repository.get_splitter_cached(plugin)
                            try:
                                nodes = splitter.get_nodes_from_documents([doc])
                            except Exception as e:
                                logger.warning(
                                    "Could not parse code with language %s for file %s: %s",
                                    plugin.get_name(),
                                    doc.id_,
                                    e,
                                )
                                continue
                        else:
                            nodes = doc_splitter.get_nodes_from_documents([doc])
                        target_index.insert_nodes(nodes)
                    else:
                        target_index.update_ref_doc(doc)
                    target_index.docstore.set_document_hash(doc.id_, doc.hash)
            logger.info("Index update complete based on the provided patch diff.")
