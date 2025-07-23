# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import logging
import unidiff
import os

from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed
from llama_index.core import SimpleDirectoryReader, VectorStoreIndex
from llama_index.core.node_parser import SentenceSplitter
from llama_index.core.schema import Document

from metis.configuration import load_plugin_config
from metis.exceptions import (
    PluginNotFoundError,
    QueryEngineInitError,
    ParsingError,
)

from metis.vector_store.base import BaseVectorStore
from metis.plugins.c_plugin import CPlugin
from metis.plugins.python_plugin import PythonPlugin
from metis.plugins.rust_plugin import RustPlugin
from metis.utils import (
    count_tokens,
    llm_call,
    parse_json_output,
    read_file_content,
    split_snippet,
    find_snippet_line,
)

logger = logging.getLogger("metis")


class MetisEngine:

    plugin_config = load_plugin_config("plugins.yaml")
    plugins = [CPlugin(plugin_config), PythonPlugin(plugin_config), RustPlugin(plugin_config)]

    def __init__(
        self,
        codebase_path=".",
        vector_backend=BaseVectorStore,
        language_plugin=None,
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

        self.language_plugin = language_plugin or "c"
        self.llm_provider = llm_provider
        self.set_code_plugin(self.language_plugin)

    @staticmethod
    def supported_languages():
        """
        Returns the list of supported languages by the Metis engine.
        """
        supported_langs = []
        for plugin in MetisEngine.plugins:
            supported_langs.append(plugin.get_name())

        return supported_langs

    def get_plugin_from_name(self, name):
        """Return a plugin instance matching the given name (via its get_name() method)."""
        for plugin in self.plugins:
            if (
                hasattr(plugin, "get_name")
                and plugin.get_name().lower() == name.lower()
            ):
                return plugin

        logger.error(f"Plugin '{name}' not found.")
        raise PluginNotFoundError(name)

    def set_code_plugin(self, plugin_name):
        """
        Update the code splitter plugin.
        """
        plugin = self.get_plugin_from_name(plugin_name)
        if plugin:
            self.code_plugin = plugin
            logger.info(f"Code splitter plugin set to '{plugin_name}'.")
        else:
            logger.error(f"Requested splitter plugin '{plugin_name}' not found.")
            raise ValueError(f"Requested splitter plugin '{plugin_name}' not found.")

    def ask_question(self, question):
        """
        Loads the indexes and queries them for an answer.
        """
        query_engine_code, query_engine_docs = self._init_and_get_query_engines()

        logger.info("Querying codebase for your question...")
        result_code = self._query_engine(query_engine_code, question)
        result_docs = self._query_engine(query_engine_docs, question)

        combined_result = {}
        if result_code:
            combined_result["code"] = str(result_code)
        if result_docs:
            combined_result["docs"] = str(result_docs)
        logger.info("Answer:")
        logger.info(combined_result)

        return combined_result

    def index_codebase(self, verbose=False):
        """
        Reads files from the codebase, splits documents using language-specific
        splitters, builds vector indexes for code and documentation, and persists them.
        """
        # Read docs and code supported extensions from config
        docs_supported_exts = self.code_plugin.plugin_config.get("docs", {}).get(
            "supported_extensions", [".md"]
        )
        code_supported_exts = self.code_plugin.get_supported_extensions()

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

        # Use the dynamically selected splitter plugin.
        code_splitter = self.code_plugin.get_splitter()
        doc_splitter = SentenceSplitter()

        base_path = os.path.abspath(self.codebase_path)
        parent_dir = os.path.dirname(base_path)
        code_docs = []
        doc_docs = []
        for doc in documents:
            ext = os.path.splitext(doc.id_)[1].lower()
            new_id = os.path.relpath(doc.id_, parent_dir)
            doc.doc_id = new_id
            doc.id_ = new_id

            if ext in docs_supported_exts:
                doc_docs.append(doc)
            elif ext in code_supported_exts:
                code_docs.append(doc)

        nodes_code = code_splitter.get_nodes_from_documents(code_docs)
        nodes_docs = doc_splitter.get_nodes_from_documents(doc_docs)
        logger.info(
            f"Created {len(nodes_code)} code nodes and {len(nodes_docs)} documentation nodes."
        )

        storage_context_code, storage_context_docs = (
            self.vector_backend.get_storage_contexts()
        )

        # Build and persist the VectorStoreIndex
        VectorStoreIndex(
            nodes_code, storage_context=storage_context_code, show_progress=verbose
        )
        logger.info("Code indexing complete.")
        VectorStoreIndex(
            nodes_docs, storage_context=storage_context_docs, show_progress=verbose
        )
        logger.info("Documentation indexing complete.")

    def review_file(self, file_path, validate=False):
        query_engine_code, query_engine_docs = self._init_and_get_query_engines()

        base_path = os.path.abspath(self.codebase_path)
        snippet = read_file_content(file_path)
        if not snippet:
            return None

        language_prompts = self.code_plugin.get_prompts()
        context_prompt_template = self.code_plugin.plugin_config.get(
            "general_prompts", {}
        ).get("retrieve_context", "")
        formatted_context_prompt = context_prompt_template.format(file_path=file_path)

        combined_context = self._retrieve_context(
            file_path, query_engine_code, query_engine_docs, formatted_context_prompt
        )
        relative_path = os.path.relpath(file_path, base_path)

        try:
            return self._process_file_reviews(
                file_path,
                snippet,
                combined_context,
                language_prompts,
                validate,
                default_prompt_key="security_review_file",
                relative_path=relative_path,
            )
        except Exception as e:
            logger.error(f"Error processing file {file_path}: {e}")
            return None

    def review_code(self, validate=False, verbose=False):
        base_path = os.path.abspath(self.codebase_path)
        code_supported_exts = self.code_plugin.get_supported_extensions()

        file_list = []
        for root, _, files in os.walk(base_path):
            for file in files:
                if os.path.splitext(file)[1].lower() in code_supported_exts:
                    file_list.append(os.path.join(root, file))

        file_reviews = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self.review_file, path, validate): path
                for path in file_list
            }

            future_iterator = as_completed(futures)
            if verbose:
                future_iterator = tqdm(
                    future_iterator,
                    total=len(futures),
                    desc="Reviewing files",
                    unit="file",
                )

            for future in future_iterator:
                result = future.result()
                if result:
                    file_reviews.append(result)

        return {"reviews": file_reviews}

    def review_patch(self, patch_file, validate=False):
        """
        Reviews a patch/diff file by processing each file change.
        """
        query_engine_code, query_engine_docs = self._init_and_get_query_engines()
        patch_text = read_file_content(patch_file)
        try:
            diff = unidiff.PatchSet.from_string(patch_text)
            logger.info("Parsed the patch file successfully.")
        except Exception as e:
            logger.error(f"Error parsing patch file: {e}")
            return {"reviews": [], "overall_changes": ""}

        file_reviews = []
        overall_changes = ""
        language_prompts = self.code_plugin.get_prompts()
        base_path = os.path.abspath(self.codebase_path)

        for file_diff in diff:
            if file_diff.is_removed_file or file_diff.is_binary_file:
                continue

            snippet = self._process_diff_file(file_diff)
            if not snippet:
                continue

            context_prompt = self.code_plugin.plugin_config.get(
                "general_prompts", {}
            ).get("retrieve_context", "")
            formatted_context = context_prompt.format(file_path=file_diff.path)
            combined_context = self._retrieve_context(
                file_diff.path, query_engine_code, query_engine_docs, formatted_context
            )
            default_prompt_key = "security_review"

            # Extract the relative path for the file
            relative_path = os.path.relpath(file_diff.path, base_path)

            review_dict = self._process_file_reviews(
                file_diff.path,
                snippet,
                combined_context,
                language_prompts,
                validate,
                default_prompt_key=default_prompt_key,
                relative_path=relative_path,
            )
            if review_dict:
                file_reviews.append(review_dict)
                issues = "\n".join(
                    issue.get("issue", "") for issue in review_dict.get("reviews", [])
                )
                summary_prompt = language_prompts["snippet_security_summary"]
                changes_summary = self._summarize_changes(
                    file_diff.path, issues, summary_prompt
                )
                overall_changes = changes_summary

        return {"reviews": file_reviews, "overall_changes": overall_changes}

    def update_index(self, file_diff, verbose=False):
        """
        Updates the existing index by comparing two git commits.
        """
        try:
            patch_set = unidiff.PatchSet(file_diff)
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
            show_progress=verbose,
        )

        index_docs = VectorStoreIndex.from_vector_store(
            self.vector_backend.vector_store_docs,
            storage_context=storage_context_docs,
            show_progress=verbose,
        )

        for file_diff in patch_set:
            if file_diff.is_binary_file:
                continue

            # Use file_diff.path as the document ID.
            doc_id = os.path.join(
                os.path.basename(os.path.abspath(self.codebase_path)), file_diff.path
            )
            ext = os.path.splitext(doc_id)[1].lower()

            # Decide which index to use based on supported extensions.
            target_index = (
                index_code
                if ext in self.code_plugin.get_supported_extensions()
                else index_docs
            )

            if file_diff.is_removed_file:
                target_index.delete_ref_doc(doc_id, delete_from_docstore=True)
            else:
                file_path = os.path.join(self.codebase_path, file_diff.path)
                file_content = read_file_content(file_path)
                # For added files not found on disk, extract content from the diff.
                if not file_content and file_diff.is_added_file:
                    file_content = self._extract_content_from_diff(file_diff)
                if not file_content:
                    logger.warning("No content available for %s", file_diff.path)
                    continue

                doc = Document(
                    text=file_content,
                    metadata={"file_name": file_diff.path},
                    id_=doc_id,
                )

                if file_diff.is_added_file:
                    if ext in self.code_plugin.get_supported_extensions():
                        nodes = (
                            self.code_plugin.get_splitter().get_nodes_from_documents(
                                [doc]
                            )
                        )
                    else:
                        nodes = SentenceSplitter().get_nodes_from_documents([doc])
                    target_index.insert_nodes(nodes)
                else:
                    target_index.refresh_ref_docs([doc])
                target_index.docstore.set_document_hash(doc.id_, doc.hash)

        logger.info("Index update complete based on the provided patch diff.")

    def _init_and_get_query_engines(self):
        self.vector_backend.init()
        query_engine_code, query_engine_docs = self.vector_backend.get_query_engines(
            self.llm_provider,
            self.similarity_top_k,
            self.response_mode,
        )
        if not query_engine_code or not query_engine_docs:
            raise QueryEngineInitError()
        return query_engine_code, query_engine_docs

    def _process_file_reviews(
        self,
        file_path,
        snippet,
        combined_context,
        language_prompts,
        validate,
        default_prompt_key="security_review_file",
        relative_path="",
    ):

        chunks = split_snippet(snippet, self.max_token_length)
        accumulated = {"reviews": []}
        validations = []

        report_prompt = self.code_plugin.plugin_config.get("general_prompts", {}).get(
            "security_review_report", ""
        )
        for chunk in chunks:
            system_prompt = f"{language_prompts[default_prompt_key]} \n {language_prompts['security_review_checks']} \n {report_prompt}"
            review = self._perform_security_review(
                file_path, chunk, combined_context, system_prompt
            )
            if not review:
                continue
            parsed_review = parse_json_output(review)
            if "reviews" not in parsed_review:
                continue

            # Add line numbers to issues
            for issue in parsed_review["reviews"]:
                snippet_text = issue.get("code_snippet", "").strip()
                line_number = find_snippet_line(snippet_text, file_path)
                issue["line_number"] = line_number

            if validate:
                system_prompt_validation = language_prompts["validation_review"]
                validation_output = self._validate_review(
                    file_path, chunk, combined_context, review, system_prompt_validation
                )
                if validation_output:
                    parsed_validation = parse_json_output(validation_output)
                    if parsed_validation:
                        validations.extend(parsed_validation.get("validations", []))

            accumulated["reviews"].extend(parsed_review["reviews"])

        if not accumulated["reviews"]:
            return None

        result = {
            "file": relative_path,
            "file_path": file_path,
            "reviews": accumulated["reviews"],
        }
        if validate and validations:
            result["validation"] = validations
        return result

    def _process_diff_file(self, file_diff):
        """
        Extracts changed lines from the diff and attempts to include the original file content
        if available.
        """
        changed_lines = []
        for hunk in file_diff:
            for line in hunk:
                if line.is_added:
                    changed_lines.append("+" + line.value)
                elif line.is_removed:
                    changed_lines.append("-" + line.value)
        snippet = "".join(changed_lines)
        original_file_path = os.path.join(self.codebase_path, file_diff.path)
        original_content = read_file_content(original_file_path)
        if original_content:
            logger.info(f"Fetched original content for {file_diff.path}.")
            total_tokens = count_tokens(original_content) + count_tokens(snippet)
            if total_tokens <= self.max_token_length:
                snippet = (
                    f"ORIGINAL_FILE:\n{original_content}\n\nFILE_CHANGES:\n{snippet}"
                )
            else:
                snippet = f"FILE_CHANGES:\n{snippet}"
        return snippet

    def _query_engine(self, engine, question):
        """
        Helper method to query a given engine with error handling.
        """
        try:
            return engine.query(question)
        except Exception as e:
            logger.error(f"Error querying index: {e}")
            return ""

    def _validate_review(
        self, file_path, snippet, combined_context, review, system_prompt_validation
    ):

        prompt_text = (
            f"SNIPPET: {snippet}\nCONTEXT:\n{combined_context}\nREVIEW:\n{review}\n"
        )
        validation_response = llm_call(
            self.llm_provider,
            system_prompt_validation,
            prompt_text,
            model=self.llama_query_model,
        )
        parsed_response = parse_json_output(validation_response)
        logger.info(f"Final validation for {file_path}: {parsed_response}")
        return parsed_response

    def _summarize_changes(self, file_path, issues, summary_prompt):
        try:
            answer = llm_call(self.llm_provider, summary_prompt, issues)
            return answer
        except Exception as e:
            logger.error(f"Error summarizing changes for {file_path}: {e}")
            return ""

    def _retrieve_context(
        self, file_path, query_engine_code, query_engine_docs, context_prompt
    ):
        """
        Queries code and documentation indexes for context on the file.
        """

        result_code = self._query_engine(query_engine_code, context_prompt)
        if result_code:
            logger.info(f"Retrieved context from code index for {file_path}.")
        result_docs = self._query_engine(query_engine_docs, context_prompt)
        if result_docs:
            logger.info(f"Retrieved context from documentation index for {file_path}.")
        return f"{result_code}\n{result_docs}"

    def _perform_security_review(
        self, file_path, snippet, combined_context, system_prompt
    ):
        prompt_text = (
            f"FILE: {file_path}\nSNIPPET: {snippet}\nCONTEXT:\n{combined_context}\n"
        )

        try:
            answer = llm_call(self.llm_provider, system_prompt, prompt_text)
            logger.info(f"Received security review response for {file_path}.")
            return answer
        except Exception as e:
            logger.error(f"Error during security review for {file_path}: {e}")
            return ""

    def _extract_content_from_diff(self, file_diff):
        """
        Extracts content from a file diff by concatenating all added lines.
        This is used when a file marked as added is not found on disk.

        Args:
            file_diff: A file diff object from unidiff.

        Returns:
            str: The reconstructed file content.
        """
        content_lines = []
        for hunk in file_diff:
            for line in hunk:
                if line.is_added:
                    content_lines.append(line.value)
        return "".join(content_lines)
