# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import inspect
import logging
import os
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import unidiff

from metis.usage import submit_with_current_context
from metis.utils import read_file_content

from .diff_utils import process_diff_file
from .graphs.types import ReviewRequest
from .helpers import apply_custom_guidance, summarize_changes
from .options import ReviewOptions, coerce_review_options
from .repository import EngineRepository
from .runtime import EngineConfig

logger = logging.getLogger("metis")


class ReviewService:
    def __init__(
        self,
        config: EngineConfig,
        repository: EngineRepository,
        get_query_engines: Callable[[], tuple[Any, Any]],
        review_graph_factory: Callable[[], Any],
    ):
        self._config = config
        self._repository = repository
        self._get_query_engines = get_query_engines
        self._review_graph_factory = review_graph_factory

    def get_code_files(self):
        return self._repository.get_code_files()

    def review_file(
        self,
        file_path,
        options: ReviewOptions | None = None,
        *,
        use_retrieval_context: bool | None = None,
    ):
        options = coerce_review_options(
            options,
            use_retrieval_context=use_retrieval_context,
        )
        qe_code = qe_docs = None
        if options.use_retrieval_context:
            qe_code, qe_docs = self._get_query_engines()
        base_path = os.path.abspath(self._config.codebase_path)
        snippet = read_file_content(file_path)
        if not snippet:
            return None

        ext = os.path.splitext(file_path)[1].lower()
        plugin = self._repository.get_plugin_for_extension(ext)
        if not plugin:
            return None

        language_prompts = plugin.get_prompts()
        relative_path = os.path.relpath(file_path, base_path)

        try:
            req: ReviewRequest = {
                "file_path": file_path,
                "snippet": snippet,
                "retriever_code": qe_code,
                "retriever_docs": qe_docs,
                "language_prompts": language_prompts,
                "default_prompt_key": "security_review_file",
                "relative_file": relative_path,
                "mode": "file",
                "use_retrieval_context": options.use_retrieval_context,
                "debug_callback": options.debug_callback,
            }
            return self._review_graph_factory().review(req)
        except Exception as e:
            logger.error(f"Error processing file {file_path}: {e}")
            return None

    def _invoke_review_file(
        self,
        review_fn,
        path: str,
        options: ReviewOptions,
    ):
        try:
            signature = inspect.signature(review_fn)
        except (TypeError, ValueError):
            signature = None

        if signature is not None:
            params = signature.parameters
            if "options" in params or any(
                p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values()
            ):
                return review_fn(path, options=options)
            if "use_retrieval_context" in params:
                return review_fn(
                    path,
                    use_retrieval_context=options.use_retrieval_context,
                )

        if options.use_retrieval_context:
            return review_fn(path)

        raise TypeError(
            "review_file_func must accept 'options' or 'use_retrieval_context' "
            "when retrieval context is disabled"
        )

    def review_code(
        self,
        review_file_func=None,
        get_code_files_func=None,
        options: ReviewOptions | None = None,
        *,
        use_retrieval_context: bool | None = None,
    ) -> Iterator[dict | None]:
        options = coerce_review_options(
            options,
            use_retrieval_context=use_retrieval_context,
        )
        files = (get_code_files_func or self.get_code_files)()
        if not files:
            return
        review_fn = review_file_func or self.review_file
        with ThreadPoolExecutor(max_workers=self._config.max_workers) as executor:
            future_to_path = {
                submit_with_current_context(
                    executor,
                    self._invoke_review_file,
                    review_fn,
                    path,
                    options,
                ): path
                for path in files
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

    def review_patch(
        self,
        patch_file,
        options: ReviewOptions | None = None,
        *,
        use_retrieval_context: bool | None = None,
    ):
        options = coerce_review_options(
            options,
            use_retrieval_context=use_retrieval_context,
        )
        qe_code = qe_docs = None
        if options.use_retrieval_context:
            qe_code, qe_docs = self._get_query_engines()
        patch_text = read_file_content(patch_file)
        try:
            diff = unidiff.PatchSet.from_string(patch_text)
            logger.info("Parsed the patch file successfully.")
        except Exception as e:
            logger.error(f"Error parsing patch file: {e}")
            return {"reviews": [], "overall_changes": ""}
        file_reviews = []
        overall_summaries = []
        base_path = os.path.abspath(self._config.codebase_path)
        metisignore_spec = self._repository.load_metisignore()
        for file_diff in diff:
            if file_diff.is_removed_file or file_diff.is_binary_file:
                continue
            abs_path = (
                file_diff.path
                if os.path.isabs(file_diff.path)
                else os.path.join(base_path, file_diff.path)
            )
            relative_path = self._repository.normalize_match_path(abs_path)
            if self._repository.is_metisignored(abs_path, spec=metisignore_spec):
                continue
            ext = os.path.splitext(file_diff.path)[1].lower()
            plugin = self._repository.get_plugin_for_extension(ext)
            if not plugin:
                continue
            snippet = process_diff_file(
                self._config.codebase_path, file_diff, self._config.max_token_length
            )
            if not snippet:
                continue
            language_prompts = plugin.get_prompts()
            try:
                original_content = read_file_content(abs_path)
                req: ReviewRequest = {
                    "file_path": abs_path,
                    "snippet": snippet,
                    "retriever_code": qe_code,
                    "retriever_docs": qe_docs,
                    "language_prompts": language_prompts,
                    "default_prompt_key": "security_review",
                    "relative_file": relative_path,
                    "mode": "patch",
                    "original_file": original_content or "",
                    "use_retrieval_context": options.use_retrieval_context,
                    "debug_callback": options.debug_callback,
                }
                review_dict = self._review_graph_factory().review(req)
            except Exception as e:
                logger.error(f"Error processing review for {file_diff.path}: {e}")
                review_dict = None
            if review_dict:
                file_reviews.append(review_dict)
                issues = "\n".join(
                    issue.get("issue", "") for issue in review_dict.get("reviews", [])
                )
                if not issues.strip():
                    continue
                summary_prompt = language_prompts["snippet_security_summary"]
                summary_prompt = apply_custom_guidance(
                    summary_prompt,
                    self._config.custom_prompt_text,
                    self._config.custom_guidance_precedence,
                )
                changes_summary = summarize_changes(
                    self._config.llm_provider,
                    file_diff.path,
                    issues,
                    summary_prompt,
                    callbacks=self._config.usage_runtime.hooks.callbacks,
                )
                if changes_summary:
                    overall_summaries.append(changes_summary)
        overall_changes = "\n\n".join(overall_summaries)
        return {"reviews": file_reviews, "overall_changes": overall_changes}
