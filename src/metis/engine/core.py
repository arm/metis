# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import logging
import os
import unidiff
import pathspec

from llama_index.core import SimpleDirectoryReader, VectorStoreIndex
from llama_index.core.node_parser import SentenceSplitter
from llama_index.core.schema import Document

from concurrent.futures import ThreadPoolExecutor, as_completed
from metis.configuration import load_plugin_config
from metis.exceptions import (
    PluginNotFoundError,
    QueryEngineInitError,
    ParsingError,
)
from metis.vector_store.base import BaseVectorStore
from metis.plugin_loader import load_plugins, discover_supported_language_names
from metis.utils import (
    read_file_content,
)

from .helpers import (
    summarize_changes,
    prepare_nodes_iter,
    apply_custom_guidance,
)
from .diff_utils import extract_content_from_diff, process_diff_file
from .graphs.types import ReviewRequest
from .graphs.types import AskRequest
from metis.engine.graphs import ReviewGraph, AskGraph


logger = logging.getLogger("metis")


class MetisEngine:

    _SUPPORTED_LANGUAGES = None

    def __init__(
        self,
        codebase_path=".",
        vector_backend=BaseVectorStore,
        llm_provider=None,
        **kwargs,
    ):
        self.codebase_path = codebase_path
        self.vector_backend = vector_backend

        required_keys = [
            "max_workers",
            "max_token_length",
            "llama_query_model",
            "similarity_top_k",
            "response_mode",
        ]
        missing = [k for k in required_keys if k not in kwargs or kwargs[k] is None]
        if missing:
            raise ValueError(f"Missing required config: {', '.join(missing)}")

        for k in required_keys:
            setattr(self, k, kwargs[k])

        self.llm_provider = llm_provider
        self.doc_chunk_size = kwargs.get("doc_chunk_size", 1024)
        self.doc_chunk_overlap = kwargs.get("doc_chunk_overlap", 200)
        # Optional user-provided guidance to be appended to system prompts
        self.custom_prompt_text = kwargs.get("custom_prompt_text")
        self.plugin_config = load_plugin_config()

        # Load precedence note from general prompts
        self.custom_guidance_precedence = self.plugin_config.get(
            "general_prompts", {}
        ).get("custom_guidance_precedence", "")
        self.plugins = load_plugins(self.plugin_config)

        # Cache splitters and extension/plugin lookups
        self._splitter_cache = {}
        self.code_exts = set()
        self.ext_plugin_map = {}

        for plugin in self.plugins:
            for e in plugin.get_supported_extensions():
                e_lower = e.lower()
                self.code_exts.add(e_lower)
                self.ext_plugin_map[e_lower] = plugin

        # Graphs are built lazily on first use
        self._review_graph = None
        self._ask_graph = None
        self.metisignore_file = kwargs.get("metisignore_file") or ".metisignore"

    def load_metisignore(self):
        """
        Load metisignore file and return a PathSpec matcher.

        Args:
            metisignore: Path to a file that have the ignore regex ( use the .gitignore syntax )

        Returns:
            pathspec.PathSpec object or None if file doesn't exist
        """
        try:
            if not self.metisignore_file:
                logger.info("No MetisIgnore file provided")
                return None
            with open(self.metisignore_file, "r") as f:
                spec = pathspec.PathSpec.from_lines("gitwildmatch", f)
                logger.info(f"MetisIgnore file loaded: {self.metisignore_file}")
            return spec
        except FileNotFoundError:
            logger.info(f"MetisIgnore file not loaded {self.metisignore_file}")
            return None

    def _get_review_graph(self):
        if self._review_graph is None:
            self._review_graph = ReviewGraph(
                llm_provider=self.llm_provider,
                plugin_config=self.plugin_config,
                custom_prompt_text=self.custom_prompt_text,
                custom_guidance_precedence=self.custom_guidance_precedence,
                llama_query_model=self.llama_query_model,
                max_token_length=self.max_token_length,
            )
        return self._review_graph

    def _get_ask_graph(self):
        if self._ask_graph is None:
            self._ask_graph = AskGraph(
                llm_provider=self.llm_provider,
                llama_query_model=self.llama_query_model,
            )
        return self._ask_graph

    @classmethod
    def supported_languages(cls):
        """
        Returns the list of supported languages by the Metis engine.
        """
        # Cache to avoid repeated plugin instantiation in repeated calls
        if cls._SUPPORTED_LANGUAGES is None:
            plugin_config = load_plugin_config()
            cls._SUPPORTED_LANGUAGES = discover_supported_language_names(plugin_config)
        return cls._SUPPORTED_LANGUAGES

    def get_plugin_from_name(self, name):
        for plugin in self.plugins:
            if (
                hasattr(plugin, "get_name")
                and plugin.get_name().lower() == name.lower()
            ):
                return plugin
        logger.error(f"Plugin '{name}' not found.")
        raise PluginNotFoundError(name)

    def _get_plugin_for_extension(self, extension):
        return self.ext_plugin_map.get(extension.lower())

    def _get_all_supported_code_extensions(self):
        return sorted(self.code_exts)

    def _get_splitter_cached(self, plugin):
        key = plugin.get_name()
        if key in self._splitter_cache:
            return self._splitter_cache[key]
        splitter = plugin.get_splitter()
        self._splitter_cache[key] = splitter
        return splitter

    def _get_doc_splitter(self):
        if not hasattr(self, "_doc_splitter") or self._doc_splitter is None:
            self._doc_splitter = SentenceSplitter(
                chunk_size=self.doc_chunk_size,
                chunk_overlap=self.doc_chunk_overlap,
            )
        return self._doc_splitter

    def _rel_to_base(self, path):
        base_path = os.path.abspath(self.codebase_path)
        return base_path, os.path.relpath(path, base_path)

    def ask_question(self, question):
        """
        Loads the indexes and queries them for an answer using the AskGraph.
        """
        qe_code, qe_docs = self._init_and_get_query_engines()
        logger.info("Querying codebase for your question...")
        req: AskRequest = {
            "question": question,
            "retriever_code": qe_code,
            "retriever_docs": qe_docs,
        }
        return self._get_ask_graph().ask(req)

    def index_codebase(self):
        """
        Reads files from the codebase, splits documents using language-specific
        splitters, builds vector indexes for code and documentation, and persists them.
        """

        self.index_prepare_nodes()
        self.index_finalize_embeddings()

    def index_prepare_nodes_iter(self):
        """
        Parse documents and prepare nodes for indexing, yielding one step per file.
        Stores prepared nodes internally for a subsequent call to
        `index_finalize_embeddings`.
        """
        # Read docs and code supported extensions from config
        docs_supported_exts = self.plugin_config.get("docs", {}).get(
            "supported_extensions", [".md"]
        )
        code_supported_exts = self._get_all_supported_code_extensions()

        logger.info(f"Indexing codebase at: {self.codebase_path}")
        reader = SimpleDirectoryReader(
            input_dir=self.codebase_path,
            recursive=True,
            required_exts=code_supported_exts + docs_supported_exts,
            filename_as_id=True,
        )
        documents = reader.load_data()
        logger.info(f"Loaded {len(documents)} documents from {self.codebase_path}")

        self.vector_backend.init()
        doc_splitter = self._get_doc_splitter()
        metisignore_spec = self.load_metisignore()
        base_path = os.path.abspath(self.codebase_path)
        parent_dir = os.path.dirname(base_path)
        code_docs = []
        doc_docs = []
        for doc in documents:
            ext = os.path.splitext(doc.id_)[1].lower()
            new_id = os.path.relpath(doc.id_, parent_dir)
            doc.doc_id = new_id
            doc.id_ = new_id

            if metisignore_spec and metisignore_spec.match_file(os.path.join(parent_dir, new_id)):
                continue

            if ext in docs_supported_exts:
                doc_docs.append(doc)
            elif ext in code_supported_exts:
                code_docs.append(doc)

        nodes_code, nodes_docs = yield from prepare_nodes_iter(
            code_docs,
            doc_docs,
            self._get_plugin_for_extension,
            self._get_splitter_cached,
            doc_splitter,
        )

        # Store nodes for embedding phase
        self._pending_nodes = (nodes_code, nodes_docs)
        return

    def index_prepare_nodes(self):
        """
        Prepare nodes without exposing an iterator.
        Consumes the iterator so non-verbose callers avoid a no-op loop.
        """
        for _ in self.index_prepare_nodes_iter():
            pass

    def index_finalize_embeddings(self):
        """Build vector indexes from previously prepared nodes."""
        pending = getattr(self, "_pending_nodes", None)
        if not pending:
            # Nothing to do
            return
        nodes_code, nodes_docs = pending
        storage_context_code, storage_context_docs = (
            self.vector_backend.get_storage_contexts()
        )
        VectorStoreIndex(
            nodes_code,
            storage_context=storage_context_code,
            embed_model=self.llm_provider.get_embed_model_code(),
        )

        VectorStoreIndex(
            nodes_docs,
            storage_context=storage_context_docs,
            embed_model=self.llm_provider.get_embed_model_docs(),
        )
        # Clear pending nodes
        self._pending_nodes = None

    def review_file(self, file_path):
        """
        Review a single source file. Detects plugin by extension, retrieves
        relevant context from code/docs indexes, runs the security review,
        and returns a result dict or None
        if the file is unsupported or empty.
        """
        qe_code, qe_docs = self._init_and_get_query_engines()
        base_path = os.path.abspath(self.codebase_path)
        snippet = read_file_content(file_path)
        if not snippet:
            return None

        ext = os.path.splitext(file_path)[1].lower()
        plugin = self._get_plugin_for_extension(ext)
        if not plugin:
            return None

        language_prompts = plugin.get_prompts()
        context_prompt_template = self.plugin_config.get("general_prompts", {}).get(
            "retrieve_context", ""
        )

        formatted_context_prompt = context_prompt_template.format(file_path=file_path)
        relative_path = os.path.relpath(file_path, base_path)

        try:
            req: ReviewRequest = {
                "file_path": file_path,
                "snippet": snippet,
                "retriever_code": qe_code,
                "retriever_docs": qe_docs,
                "context_prompt": formatted_context_prompt,
                "language_prompts": language_prompts,
                "default_prompt_key": "security_review_file",
                "relative_file": relative_path,
                "mode": "file",
            }
            return self._get_review_graph().review(req)
        except Exception as e:
            logger.error(f"Error processing file {file_path}: {e}")
            return None

    def get_code_files(self):
        """
        Return a list of file names in the self.codebase_path folder.
        Evaulate the path with metisignore file if requested
        """
        base_path = os.path.abspath(self.codebase_path)
        metisignore_spec = self.load_metisignore()
        file_list = []
        for root, _, files in os.walk(base_path):
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext in self.code_exts and (
                    not metisignore_spec
                    or not metisignore_spec.match_file(os.path.join(root, file))
                ):
                    file_list.append(os.path.join(root, file))
        return file_list

    def review_code(self):
        """
        Iterate all supported code files under `codebase_path` and yield
        per-file review results. Uses a thread pool and continues on errors.
        """
        files = self.get_code_files()
        if not files:
            return
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_path = {
                executor.submit(self.review_file, path): path for path in files
            }
            for future in as_completed(future_to_path):
                path = future_to_path[future]
                try:
                    result = future.result()
                except Exception as e:
                    logger.error(f"Error reviewing file {path}: {e}")
                    yield None
                    continue
                if result:
                    yield result
                else:
                    yield None

    def review_patch(self, patch_file):
        """
        Reviews a patch/diff file by processing each file change.
        """
        qe_code, qe_docs = self._init_and_get_query_engines()
        patch_text = read_file_content(patch_file)
        try:
            diff = unidiff.PatchSet.from_string(patch_text)
            logger.info("Parsed the patch file successfully.")
        except Exception as e:
            logger.error(f"Error parsing patch file: {e}")
            return {"reviews": [], "overall_changes": ""}
        file_reviews = []
        overall_summaries = []
        base_path = os.path.abspath(self.codebase_path)
        for file_diff in diff:
            if file_diff.is_removed_file or file_diff.is_binary_file:
                continue
            ext = os.path.splitext(file_diff.path)[1].lower()
            plugin = self._get_plugin_for_extension(ext)
            if not plugin:
                continue
            snippet = process_diff_file(
                self.codebase_path, file_diff, self.max_token_length
            )
            if not snippet:
                continue
            context_prompt = self.plugin_config.get("general_prompts", {}).get(
                "retrieve_context", ""
            )
            formatted_context = context_prompt.format(file_path=file_diff.path)

            language_prompts = plugin.get_prompts()
            relative_path = os.path.relpath(file_diff.path, base_path)
            try:
                file_abs = os.path.join(base_path, file_diff.path)
                original_content = read_file_content(file_abs)
                req: ReviewRequest = {
                    "file_path": file_abs,
                    "snippet": snippet,
                    "retriever_code": qe_code,
                    "retriever_docs": qe_docs,
                    "context_prompt": formatted_context,
                    "language_prompts": language_prompts,
                    "default_prompt_key": "security_review",
                    "relative_file": relative_path,
                    "mode": "patch",
                    "original_file": original_content or "",
                }
                review_dict = self._get_review_graph().review(req)
            except Exception as e:
                logger.error(f"Error processing review for {file_diff.path}: {e}")
                review_dict = None
            if review_dict:
                file_reviews.append(review_dict)
                issues = "\n".join(
                    issue.get("issue", "") for issue in review_dict.get("reviews", [])
                )
                summary_prompt = language_prompts["snippet_security_summary"]
                summary_prompt = apply_custom_guidance(
                    summary_prompt,
                    self.custom_prompt_text,
                    self.custom_guidance_precedence,
                )
                changes_summary = summarize_changes(
                    self.llm_provider, file_diff.path, issues, summary_prompt
                )
                if changes_summary:
                    overall_summaries.append(changes_summary)
        overall_changes = "\n\n".join(overall_summaries)
        return {"reviews": file_reviews, "overall_changes": overall_changes}

    def update_index(self, patch_text):
        """
        Updates the existing index by comparing two git commits.
        """
        try:
            patch_set = unidiff.PatchSet.from_string(patch_text)
            logger.info("Parsed the provided patch string successfully.")
        except Exception as e:
            raise ParsingError(f"Error parsing patch string: {e}")
        self.vector_backend.init()
        storage_context_code, storage_context_docs = (
            self.vector_backend.get_storage_contexts()
        )

        index_code = VectorStoreIndex.from_vector_store(
            self.vector_backend.vector_store_code,
            storage_context=storage_context_code,
            embed_model=self.llm_provider.get_embed_model_code(),
        )
        index_docs = VectorStoreIndex.from_vector_store(
            self.vector_backend.vector_store_docs,
            storage_context=storage_context_docs,
            embed_model=self.llm_provider.get_embed_model_docs(),
        )

        doc_splitter = self._get_doc_splitter()

        for diff_file in patch_set:
            if diff_file.is_binary_file:
                continue
            doc_id = os.path.join(
                os.path.basename(os.path.abspath(self.codebase_path)), diff_file.path
            )
            ext = os.path.splitext(doc_id)[1].lower()
            target_index = (
                index_code
                if ext in self._get_all_supported_code_extensions()
                else index_docs
            )

            if diff_file.is_removed_file:
                target_index.delete_ref_doc(doc_id, delete_from_docstore=True)
            else:
                file_path = os.path.join(self.codebase_path, diff_file.path)
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
                    if ext in self._get_all_supported_code_extensions():
                        plugin = self._get_plugin_for_extension(ext)
                        if not plugin:
                            continue
                        splitter = self._get_splitter_cached(plugin)
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

    def _init_and_get_query_engines(self):
        self.vector_backend.init()
        qe_code, qe_docs = self.vector_backend.get_query_engines(
            self.llm_provider,
            self.similarity_top_k,
            self.response_mode,
        )
        if not qe_code or not qe_docs:
            raise QueryEngineInitError()
        return qe_code, qe_docs
