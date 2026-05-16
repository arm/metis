# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import inspect
import logging
import os
import threading
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
from .reachability_service_modular.c_family_rules import C_FAMILY_PLUGIN_NAMES
from .runtime import EngineConfig

logger = logging.getLogger("metis")


class ReviewService:
    def __init__(
        self,
        config: EngineConfig,
        repository: EngineRepository,
        get_query_engines: Callable[[], tuple[Any, Any]],
        review_graph_factory: Callable[[], Any],
        reachability_service=None,
        reachability_settings: dict[str, Any] | None = None,
    ):
        self._config = config
        self._repository = repository
        self._get_query_engines = get_query_engines
        self._review_graph_factory = review_graph_factory
        self._reachability_service = reachability_service
        self._reachability_settings = dict(reachability_settings or {})
        self._reachability_cache = None
        self._reachability_lock = threading.Lock()

    def get_code_files(self, options: ReviewOptions | None = None):
        options = coerce_review_options(options)
        return self._repository.get_code_files(
            include_suffixed_sources=not options.use_retrieval_context
        )

    def _get_reachability_reviews(self, *, progress_callback=None):
        if self._reachability_cache is not None:
            return list(self._reachability_cache)

        with self._reachability_lock:
            if self._reachability_cache is None:
                settings = dict(self._reachability_settings)
                settings.setdefault("analysis_profile", "review")
                if not int(settings.get("max_paths") or 0):
                    settings.setdefault("confirm_paths", False)
                if progress_callback is not None:
                    settings["progress_callback"] = progress_callback
                self._reachability_cache = self._reachability_service.review_codebase(
                    **settings
                )
        return list(self._reachability_cache)

    def review_file(
        self,
        file_path,
        options: ReviewOptions | None = None,
        *,
        use_retrieval_context: bool | None = None,
        progress_callback=None,
    ):
        options = coerce_review_options(
            options,
            use_retrieval_context=use_retrieval_context,
        )
        if (
            self._reachability_service is not None
            and self._is_file_in_codebase(file_path)
            and self._is_c_cpp_file(file_path)
        ):
            try:
                result = self._reachability_service.review_file(
                    file_path,
                    confirmation_model=self._reachability_settings.get(
                        "confirmation_model"
                    ),
                    max_workers=int(self._reachability_settings.get("max_workers", 8)),
                    max_paths=int(self._reachability_settings.get("max_paths", 0)),
                    max_paths_per_sink=int(
                        self._reachability_settings.get("max_paths_per_sink", 3)
                    ),
                    max_path_length=int(
                        self._reachability_settings.get("max_path_length", 25)
                    ),
                    reasoning_effort=self._reachability_settings.get(
                        "reasoning_effort"
                    ),
                    security_functions=self._reachability_settings.get(
                        "security_functions"
                    ),
                    domain_hints=self._reachability_settings.get("domain_hints"),
                    domain_profiles=self._reachability_settings.get("domain_profiles"),
                    progress_callback=progress_callback,
                )
            except Exception as e:
                logger.exception("Tree-sitter file review failed for %s", file_path)
                if progress_callback is not None:
                    progress_callback(
                        {
                            "event": "treesitter_file_review_error",
                            "file": file_path,
                            "error": f"{type(e).__name__}: {e}",
                        }
                    )
            else:
                if result is not None:
                    return result
        qe_code = qe_docs = None
        if options.use_retrieval_context:
            qe_code, qe_docs = self._get_query_engines()
        base_path = os.path.abspath(self._config.codebase_path)
        snippet = read_file_content(file_path)
        if not snippet:
            return None

        plugin = self._repository.get_plugin_for_path(file_path)
        if not plugin:
            return None

        language_prompts = plugin.get_prompts()
        context_prompt_template = self._config.plugin_config.get(
            "general_prompts", {}
        ).get("retrieve_context", "")

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
                "use_retrieval_context": options.use_retrieval_context,
            }
            return self._review_graph_factory().review(req)
        except Exception as e:
            logger.error(f"Error processing file {file_path}: {e}")
            return {
                "file": relative_path,
                "file_path": file_path,
                "reviews": [],
                "errors": [f"{type(e).__name__}: {e}"],
            }

    def _is_file_in_codebase(self, file_path):
        try:
            base = os.path.abspath(self._config.codebase_path)
            target = os.path.abspath(str(file_path))
            return os.path.commonpath([base, target]) == base
        except (OSError, ValueError):
            return False

    def _is_c_cpp_file(self, file_path):
        return self._repository.is_path_supported_by_plugins(
            str(file_path), C_FAMILY_PLUGIN_NAMES
        )

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
            accepts_kwargs = any(
                p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values()
            )
            kwargs = {}
            if "options" in params or accepts_kwargs:
                kwargs["options"] = options
            if "use_retrieval_context" in params:
                kwargs["use_retrieval_context"] = options.use_retrieval_context
            if kwargs:
                return review_fn(path, **kwargs)

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
        progress_callback=None,
    ) -> Iterator[dict | None]:
        options = coerce_review_options(
            options,
            use_retrieval_context=use_retrieval_context,
        )
        files = (
            get_code_files_func()
            if get_code_files_func is not None
            else self.get_code_files(options=options)
        )
        if not files:
            yield {
                "file": "",
                "file_path": self._config.codebase_path,
                "reviews": [],
                "errors": [
                    "No supported code files found under codebase_path. "
                    "Check --codebase-path and the configured language plugins."
                ],
            }
            return

        run_codebase_reachability = (
            self._reachability_service is not None
            and review_file_func is None
            and any(self._is_c_cpp_file(path) for path in files)
        )
        if run_codebase_reachability:
            results = self._get_reachability_reviews(
                progress_callback=progress_callback
            )
            for result in results:
                yield result
            files = [path for path in files if not self._is_c_cpp_file(path)]
            if not files:
                return

        review_fn = self.review_file if review_file_func is None else review_file_func
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
                    yield {
                        "file": os.path.relpath(
                            path, os.path.abspath(self._config.codebase_path)
                        ),
                        "file_path": path,
                        "reviews": [],
                        "errors": [f"{type(e).__name__}: {e}"],
                    }
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
            plugin = self._repository.get_plugin_for_path(file_diff.path)
            if not plugin:
                continue
            snippet = process_diff_file(
                self._config.codebase_path, file_diff, self._config.max_token_length
            )
            if not snippet:
                continue
            context_prompt = self._config.plugin_config.get("general_prompts", {}).get(
                "retrieve_context", ""
            )
            formatted_context = context_prompt.format(file_path=file_diff.path)

            language_prompts = plugin.get_prompts()
            try:
                original_content = read_file_content(abs_path)
                req: ReviewRequest = {
                    "file_path": abs_path,
                    "snippet": snippet,
                    "retriever_code": qe_code,
                    "retriever_docs": qe_docs,
                    "context_prompt": formatted_context,
                    "language_prompts": language_prompts,
                    "default_prompt_key": "security_review",
                    "relative_file": relative_path,
                    "mode": "patch",
                    "original_file": original_content or "",
                    "use_retrieval_context": options.use_retrieval_context,
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
