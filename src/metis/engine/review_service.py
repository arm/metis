# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import inspect
import json
import logging
import os
import threading
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from langchain_core.messages import SystemMessage
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from pydantic import BaseModel, ConfigDict, Field
import unidiff

from metis.plugins.c_family import is_c_family_plugin
from metis.usage import submit_with_current_context
from metis.utils import parse_json_output, read_file_content

from .diff_utils import process_diff_file
from .graphs.types import ReviewRequest
from .helpers import apply_custom_guidance, summarize_changes
from .options import ReviewOptions, coerce_review_options
from .reachability import FindingConsolidator, VulnerabilityFinding
from .reachability.llm_runner import _chat_model_kwargs
from .reachability.source_context import _read_line_context, _read_named_function_body
from .repository import EngineRepository
from .runtime import EngineConfig

logger = logging.getLogger("metis")

_REACHABILITY_REASONING_METADATA_PREFIXES = (
    "Primary location:",
    "Reviewed file participates via:",
    "Connected functions:",
    "Reachability path:",
    "Root cause:",
    "Analysis type:",
    "Canonical key:",
)
_REVIEW_VALIDATION_BATCH_SIZE = 5
_REVIEW_VALIDATION_DUPLICATE_RESCUE_FAMILIES = frozenset(
    {
        "authorization",
        "command_injection",
        "credential_storage",
        "format_string",
        "information_disclosure",
        "integer_overflow",
        "lifetime",
        "memory_bounds",
        "path_traversal",
        "sql_injection",
        "unsafe_deserialization",
    }
)
_REVIEW_VALIDATION_SEVERITY_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
}
_REVIEW_VALIDATION_CWE_FAMILIES = {
    "CWE-22": "path_traversal",
    "CWE-78": "command_injection",
    "CWE-89": "sql_injection",
    "CWE-120": "memory_bounds",
    "CWE-125": "memory_bounds",
    "CWE-134": "format_string",
    "CWE-190": "integer_overflow",
    "CWE-191": "integer_overflow",
    "CWE-200": "information_disclosure",
    "CWE-252": "unchecked_error",
    "CWE-256": "credential_storage",
    "CWE-285": "authorization",
    "CWE-287": "authentication",
    "CWE-404": "lifetime",
    "CWE-415": "lifetime",
    "CWE-416": "lifetime",
    "CWE-787": "memory_bounds",
    "CWE-798": "credential_storage",
    "CWE-862": "authorization",
    "CWE-863": "authorization",
    "CWE-911": "lifetime",
}
_REVIEW_VALIDATION_SYSTEM_PROMPT = """You validate reachability security review findings before the final report.

You receive candidate findings from an automated review. Be strict and reduce
noise. Keep only findings that are plausible, independently useful security
issues supported by the supplied evidence and code context.

For each candidate:
- keep=true only when the finding describes a credible security bug, not just a
  generic code-quality concern, theoretical style issue, or unsupported guess.
- keep=false for false positives, weak/speculative reports, missing-prerequisite
  reports, reliability-only bugs without security impact, and duplicates already
  represented by a stronger candidate in the same batch.
- Calibrate confidence as a number from 0.0 to 1.0 based on evidence quality,
  source/sink specificity, exploitability prerequisites, and code support.
- Do not add findings or rewrite the report. Only decide keep/drop and
  confidence for the provided indexes.

Return JSON only:
{
  "decisions": [
    {
      "index": 0,
      "keep": true,
      "confidence": 0.82,
      "reason": "Concise validation reason."
    }
  ]
}"""


class _ReviewValidationDecisionModel(BaseModel):
    index: int = Field(description="Candidate index from the input.")
    keep: bool = Field(description="Whether this candidate should remain reported.")
    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="Calibrated confidence from 0.0 to 1.0.",
    )
    reason: str = Field("", description="Concise validation reason.")

    model_config = ConfigDict(extra="ignore")


class _ReviewValidationResponseModel(BaseModel):
    decisions: list[_ReviewValidationDecisionModel] = Field(default_factory=list)

    model_config = ConfigDict(extra="ignore")


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
                settings = self._reachability_call_settings(
                    progress_callback=progress_callback,
                    codebase=True,
                )
                self._reachability_cache = self._reachability_service.review_codebase(
                    **settings
                )
        return list(self._reachability_cache)

    def _reachability_call_settings(self, *, progress_callback=None, codebase=False):
        settings = dict(self._reachability_settings)
        if codebase:
            settings.setdefault("lens_profile", "review")
            if not settings.get("max_paths"):
                settings.setdefault("confirm_paths", False)
        if progress_callback is not None:
            settings["progress_callback"] = progress_callback
        return settings

    def _finalize_single_review_result(self, result):
        if result is None:
            return None
        finalized = self.aggregate_review_results({"reviews": [result]})
        groups = finalized.get("reviews") if isinstance(finalized, dict) else None
        if isinstance(groups, list) and groups:
            return groups[0]
        return result

    def aggregate_review_results(self, results):
        """Run final reachability dedup and validation across review groups."""
        if self._reachability_service is None or not isinstance(results, dict):
            return results

        review_groups = results.get("reviews")
        if not isinstance(review_groups, list):
            return results

        refs, findings = self._reachability_findings_from_review_groups(review_groups)
        if not findings:
            return results

        aggregated = self._deduplicate_review_groups(results, refs, findings)
        return self._validate_review_groups(aggregated)

    def _deduplicate_review_groups(self, results, refs, findings):
        if len(findings) < 2:
            return results

        review_groups = results.get("reviews")
        if not isinstance(review_groups, list):
            return results

        adjudicator = getattr(
            self._reachability_service, "_adjudicate_final_findings", None
        )
        if not callable(adjudicator):
            return results

        model = (
            self._reachability_settings.get("confirmation_model")
            or self._config.llama_query_model
        )
        reasoning_effort = self._reachability_settings.get("reasoning_effort")
        deduped, total, removed = FindingConsolidator.deduplicate(
            findings,
            final_adjudicator=lambda candidates: adjudicator(
                candidates,
                model=model,
                reasoning_effort=reasoning_effort,
            ),
            representative_scope=None,
        )
        if removed <= 0:
            return results

        kept_ids = {finding.id for finding in deduped}
        finding_id_by_ref = {ref: finding.id for ref, finding in zip(refs, findings)}
        aggregated_groups = []
        for group_index, group in enumerate(review_groups):
            if not isinstance(group, dict):
                aggregated_groups.append(group)
                continue
            items = group.get("reviews")
            if not isinstance(items, list):
                aggregated_groups.append(group)
                continue

            had_reachability_items = False
            kept_items = []
            for item_index, item in enumerate(items):
                finding_id = finding_id_by_ref.get((group_index, item_index))
                if finding_id is None:
                    kept_items.append(item)
                    continue
                had_reachability_items = True
                if finding_id in kept_ids:
                    kept_items.append(item)

            if kept_items or not had_reachability_items:
                aggregated_group = dict(group)
                aggregated_group["reviews"] = kept_items
                aggregated_groups.append(aggregated_group)

        aggregated = dict(results)
        aggregated["reviews"] = aggregated_groups
        logger.info(
            "Final reachability aggregation removed %d duplicate findings from %d candidates",
            removed,
            total,
        )
        return aggregated

    def _validate_review_groups(self, results):
        review_groups = results.get("reviews") if isinstance(results, dict) else None
        if not isinstance(review_groups, list):
            return results

        candidates = []
        candidate_refs = []
        for group_index, group in enumerate(review_groups):
            if not isinstance(group, dict):
                continue
            items = group.get("reviews")
            if not isinstance(items, list):
                continue
            for item_index, item in enumerate(items):
                if not _needs_reachability_validation(item):
                    continue
                candidate_refs.append((group_index, item_index))
                candidates.append(
                    _review_validation_payload(
                        len(candidates),
                        item,
                        codebase_path=self._config.codebase_path,
                    )
                )

        if not candidates:
            return results

        decisions = self._validate_review_candidates(candidates)
        if not decisions:
            return results

        decisions_by_index = {
            int(decision["index"]): decision
            for decision in decisions
            if isinstance(decision, dict) and _safe_int(decision.get("index"), -1) >= 0
        }
        if not decisions_by_index:
            return results

        ref_to_candidate_index = {
            ref: candidate_index
            for candidate_index, ref in enumerate(candidate_refs)
        }
        validated_groups = []
        kept_count = 0
        filtered_count = 0
        for group_index, group in enumerate(review_groups):
            if not isinstance(group, dict):
                validated_groups.append(group)
                continue
            items = group.get("reviews")
            if not isinstance(items, list):
                validated_groups.append(group)
                continue

            kept_items = []
            filtered_items = list(group.get("review_validation_filtered_reviews") or [])
            for item_index, item in enumerate(items):
                candidate_index = ref_to_candidate_index.get((group_index, item_index))
                if candidate_index is None:
                    kept_items.append(item)
                    continue
                decision = decisions_by_index.get(candidate_index)
                if decision is None:
                    kept_items.append(item)
                    continue
                item_copy = dict(item)
                confidence = _normalised_confidence(
                    decision.get("confidence"),
                    fallback=item_copy.get("confidence"),
                )
                item_copy["confidence"] = confidence
                item_copy["review_validation_reason"] = str(
                    decision.get("reason") or ""
                ).strip()
                keep = bool(decision.get("keep", True))
                item_copy["review_validation_keep"] = keep
                if keep:
                    kept_count += 1
                    kept_items.append(item_copy)
                else:
                    filtered_count += 1
                    item_copy["review_validation_filtered"] = True
                    filtered_items.append(item_copy)

            validated_group = dict(group)
            validated_group["reviews"] = kept_items
            if filtered_items:
                validated_group["review_validation_filtered_reviews"] = filtered_items
            if kept_items or filtered_items:
                validated_groups.append(validated_group)

        validated = dict(results)
        validated["reviews"] = validated_groups
        validated["review_validation_summary"] = {
            "total_candidates": len(candidates),
            "kept": kept_count,
            "filtered": filtered_count,
        }
        logger.info(
            "Review validation kept %d and filtered %d reachability findings",
            kept_count,
            filtered_count,
        )
        return validated

    def _validate_review_candidates(self, candidates):
        model = (
            self._reachability_settings.get("validation_model")
            or self._reachability_settings.get("confirmation_model")
            or self._config.llama_query_model
        )
        reasoning_effort = self._reachability_settings.get("reasoning_effort")
        decisions = []
        for batch in _validation_batches(candidates):
            parsed = self._invoke_review_validation_batch(
                batch,
                model=model,
                reasoning_effort=reasoning_effort,
            )
            if not parsed:
                continue
            batch_decisions = parsed.get("decisions")
            if isinstance(batch_decisions, list):
                decisions.extend(batch_decisions)
        return _rescue_filtered_duplicate_cluster_representatives(candidates, decisions)

    def _invoke_review_validation_batch(self, batch, *, model, reasoning_effort=None):
        last_failure = "unknown review validation failure"
        for attempt in range(2):
            try:
                chat = self._config.llm_provider.get_chat_model(
                    model=model,
                    max_tokens=6000,
                    temperature=0.0,
                    **_chat_model_kwargs(
                        self._config.usage_runtime,
                        reasoning_effort=reasoning_effort,
                    ),
                )
                prompt = ChatPromptTemplate.from_messages(
                    [
                        SystemMessage(content=_REVIEW_VALIDATION_SYSTEM_PROMPT),
                        (
                            "user",
                            "Candidate findings JSON:\n{candidate_findings}\n\n"
                            "Return exactly one JSON object with a top-level "
                            '"decisions" array. Do not return markdown or prose.',
                        ),
                    ]
                )
                variables = {
                    "candidate_findings": json.dumps(batch, separators=(",", ":"))
                }
                parsed = None
                structured_output = getattr(chat, "with_structured_output", None)
                if callable(structured_output):
                    try:
                        raw_structured = (
                            prompt
                            | structured_output(
                                _ReviewValidationResponseModel,
                                method="function_calling",
                            )
                        ).invoke(variables)
                        parsed = _review_validation_structured_payload(raw_structured)
                    except Exception as exc:
                        last_failure = f"structured validation failed: {exc}"
                if parsed is None:
                    raw = (prompt | chat | StrOutputParser()).invoke(variables)
                    parsed = _parse_review_validation_response(raw)
                if parsed is not None:
                    return parsed
                last_failure = (
                    "expected structured validation payload or JSON object with "
                    "decisions list"
                )
            except Exception as exc:
                last_failure = str(exc)
            if attempt == 0:
                logger.warning(
                    "Review validation failed for %d candidates; retrying once: %s",
                    len(batch),
                    last_failure,
                )
        logger.warning(
            "Review validation failed for %d candidates; keeping batch unchanged: %s",
            len(batch),
            last_failure,
        )
        return None

    def _reachability_findings_from_review_groups(self, review_groups):
        refs = []
        findings = []
        for group_index, group in enumerate(review_groups):
            if not isinstance(group, dict):
                continue
            items = group.get("reviews")
            if not isinstance(items, list):
                continue
            for item_index, item in enumerate(items):
                if not _is_reachability_review_item(item):
                    continue
                finding = _review_item_to_reachability_finding(
                    item,
                    finding_id=f"review-aggregate-{len(findings)}",
                )
                refs.append((group_index, item_index))
                findings.append(finding)
        return refs, findings

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
            and self._is_c_family_file(file_path)
        ):
            try:
                if self._reachability_cache is not None:
                    result = self._get_global_reachability_review_for_file(file_path)
                else:
                    settings = self._reachability_call_settings(
                        progress_callback=progress_callback
                    )
                    result = self._reachability_service.review_file(
                        file_path, **settings
                    )
            except Exception:
                logger.debug(
                    "Tree-sitter file review failed for %s; falling back to standard review",
                    file_path,
                    exc_info=True,
                )
            else:
                if result is not None:
                    return self._finalize_single_review_result(result)
        return self._finalize_single_review_result(
            self._review_file_standard(file_path, options=options)
        )

    def _get_global_reachability_review_for_file(
        self,
        file_path,
        *,
        progress_callback=None,
    ):
        abs_path = os.path.abspath(str(file_path))
        relative_path = self._repository.normalize_match_path(abs_path)
        for review in self._get_reachability_reviews(
            progress_callback=progress_callback
        ):
            if self._same_review_file(review.get("file"), relative_path):
                return review
        return {"file": relative_path, "file_path": abs_path, "reviews": []}

    @staticmethod
    def _same_review_file(left, right):
        return os.path.normcase(os.path.normpath(str(left or ""))) == os.path.normcase(
            os.path.normpath(str(right or ""))
        )

    def _review_file_standard(
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
            return None

    def _is_file_in_codebase(self, file_path):
        try:
            base = os.path.abspath(self._config.codebase_path)
            target = os.path.abspath(str(file_path))
            return os.path.commonpath([base, target]) == base
        except (OSError, ValueError):
            return False

    def _is_c_family_file(self, file_path):
        return is_c_family_plugin(self._repository.get_plugin_for_path(str(file_path)))

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
            return

        run_codebase_reachability = (
            self._reachability_service is not None
            and review_file_func is None
            and any(self._is_c_family_file(path) for path in files)
        )
        reachability_failed = False
        if run_codebase_reachability:
            try:
                results = self._get_reachability_reviews(
                    progress_callback=progress_callback
                )
            except Exception:
                logger.debug(
                    "Tree-sitter codebase review failed; falling back to standard review",
                    exc_info=True,
                )
                reachability_failed = True
            else:
                results = self.aggregate_review_results({"reviews": results}).get(
                    "reviews", results
                )
                for result in results:
                    yield result
                files = [path for path in files if not self._is_c_family_file(path)]
                if not files:
                    return

        review_fn = (
            self._review_file_standard
            if review_file_func is None and reachability_failed
            else review_file_func or self.review_file
        )
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


def _is_reachability_review_item(item):
    if not isinstance(item, dict):
        return False
    if not item.get("primary_file") or not item.get("primary_function"):
        return False
    reasoning = str(item.get("reasoning") or "")
    return bool(item.get("analysis_type") or "Root cause:" in reasoning)


def _parse_review_validation_response(raw):
    parsed = parse_json_output(raw)
    for _ in range(2):
        if isinstance(parsed, dict):
            decisions = parsed.get("decisions")
            return parsed if isinstance(decisions, list) else None
        if isinstance(parsed, list):
            return {"decisions": parsed}
        if isinstance(parsed, str):
            try:
                parsed = json.loads(parsed)
                continue
            except (TypeError, ValueError):
                return None
        return None
    if isinstance(parsed, dict) and isinstance(parsed.get("decisions"), list):
        return parsed
    if isinstance(parsed, list):
        return {"decisions": parsed}
    return None


def _review_validation_structured_payload(raw):
    if hasattr(raw, "model_dump"):
        payload = raw.model_dump()
    elif isinstance(raw, dict):
        payload = raw
    else:
        return None
    decisions = payload.get("decisions")
    if not isinstance(decisions, list):
        return None
    return {"decisions": [dict(decision) for decision in decisions]}


def _needs_reachability_validation(item):
    if not _is_reachability_review_item(item):
        return False
    return "review_validation_keep" not in item


def _review_validation_payload(index, item, *, codebase_path=""):
    root_cause, evidence = _split_reachability_reasoning(item.get("reasoning"))
    payload = {
        "index": index,
        "issue": str(item.get("issue") or "")[:500],
        "primary_file": str(item.get("primary_file") or ""),
        "primary_function": str(item.get("primary_function") or ""),
        "line_number": _safe_int(item.get("line_number"), 0),
        "severity": str(item.get("severity") or ""),
        "confidence": item.get("confidence"),
        "cwe": str(item.get("cwe") or ""),
        "analysis_type": str(item.get("analysis_type") or ""),
        "root_cause": root_cause[:900],
        "evidence": evidence[:1200],
        "code_snippet": str(item.get("code_snippet") or "")[:1400],
        "mitigation": str(item.get("mitigation") or "")[:600],
    }
    code_context = _review_validation_code_context(codebase_path, item)
    if code_context:
        payload["code_context"] = code_context
    return payload


def _review_validation_code_context(codebase_path, item):
    primary_file = str(item.get("primary_file") or "")
    primary_function = _short_function_name(item.get("primary_function"))
    line_number = _safe_int(item.get("line_number"), 1)
    if not codebase_path or not primary_file:
        return ""

    parts = []
    line_context = _read_line_context(
        codebase_path,
        primary_file,
        line_number,
        context=4,
        max_chars=1800,
    )
    if line_context:
        parts.append(f"Nearby lines:\n{line_context}")

    function_body = _read_named_function_body(
        codebase_path,
        primary_file,
        primary_function,
        near_line=line_number,
        max_chars=3000,
    )
    if function_body and function_body not in line_context:
        parts.append(f"Primary function body:\n{function_body}")

    return "\n\n".join(parts)[:3600]


def _rescue_filtered_duplicate_cluster_representatives(candidates, decisions):
    decisions_by_index = {
        _safe_int(decision.get("index"), -1): dict(decision)
        for decision in decisions
        if isinstance(decision, dict) and _safe_int(decision.get("index"), -1) >= 0
    }
    if not decisions_by_index:
        return decisions

    clusters = {}
    duplicate_signal = {}
    for candidate in candidates:
        candidate_index = _safe_int(candidate.get("index"), -1)
        if candidate_index < 0:
            continue
        family = _review_validation_issue_family(candidate)
        if family not in _REVIEW_VALIDATION_DUPLICATE_RESCUE_FAMILIES:
            continue
        if not _is_strong_review_validation_candidate(candidate, family):
            continue
        key = (
            _normalised_review_file(candidate.get("primary_file")),
            _short_function_name(candidate.get("primary_function")),
            _safe_int(candidate.get("line_number"), 0),
            family,
        )
        clusters.setdefault(key, []).append(candidate)
        decision = decisions_by_index.get(candidate_index, {})
        duplicate_signal[key] = duplicate_signal.get(
            key, False
        ) or _review_validation_duplicate_signal(decision)

    changed = False
    for key, cluster in clusters.items():
        if len(cluster) < 2 or not duplicate_signal.get(key):
            continue
        if any(
            _review_validation_decision_keeps(
                decisions_by_index.get(_safe_int(candidate.get("index"), -1))
            )
            for candidate in cluster
        ):
            continue
        if any(
            _safe_int(candidate.get("index"), -1) not in decisions_by_index
            for candidate in cluster
        ):
            continue

        representative = max(cluster, key=_review_validation_strength_key)
        representative_index = _safe_int(representative.get("index"), -1)
        decision = decisions_by_index[representative_index]
        original_reason = str(decision.get("reason") or "").strip()
        decision["keep"] = True
        decision["confidence"] = max(
            _normalised_confidence(
                decision.get("confidence"),
                fallback=representative.get("confidence"),
            ),
            _normalised_confidence(representative.get("confidence")),
            0.7,
        )
        rescue_reason = (
            "Rescued as the strongest representative of a duplicate cluster "
            "so validation does not drop every copy of a credible finding."
        )
        decision["reason"] = (
            f"{original_reason} {rescue_reason}".strip()
            if original_reason
            else rescue_reason
        )
        decisions_by_index[representative_index] = decision
        changed = True

    if not changed:
        return decisions

    merged = []
    emitted = set()
    for decision in decisions:
        if not isinstance(decision, dict):
            merged.append(decision)
            continue
        decision_index = _safe_int(decision.get("index"), -1)
        replacement = decisions_by_index.get(decision_index)
        if replacement is None:
            merged.append(decision)
            continue
        merged.append(replacement)
        emitted.add(decision_index)

    for decision_index, decision in sorted(decisions_by_index.items()):
        if decision_index not in emitted:
            merged.append(decision)
    return merged


def _review_validation_duplicate_signal(decision):
    reason = str((decision or {}).get("reason") or "").lower()
    return (
        "duplicate" in reason
        or "same issue" in reason
        or "same root cause" in reason
        or "already represented" in reason
    )


def _review_validation_decision_keeps(decision):
    return bool(decision) and bool(decision.get("keep", True))


def _is_strong_review_validation_candidate(candidate, family):
    severity = str(candidate.get("severity") or "").strip().lower()
    confidence = _normalised_confidence(candidate.get("confidence"))
    if severity in {"critical", "high"} and confidence >= 0.70:
        return True
    return confidence >= 0.90 and bool(family)


def _review_validation_strength_key(candidate):
    severity = str(candidate.get("severity") or "").strip().lower()
    return (
        -_REVIEW_VALIDATION_SEVERITY_RANK.get(severity, 99),
        _normalised_confidence(candidate.get("confidence")),
        -_safe_int(candidate.get("line_number"), 0),
        str(candidate.get("issue") or ""),
    )


def _review_validation_issue_family(candidate):
    cwe = str(candidate.get("cwe") or "").upper()
    if cwe in _REVIEW_VALIDATION_CWE_FAMILIES:
        return _REVIEW_VALIDATION_CWE_FAMILIES[cwe]

    text = " ".join(
        str(candidate.get(field) or "")
        for field in (
            "issue",
            "analysis_type",
            "root_cause",
            "evidence",
            "mitigation",
        )
    ).lower()
    keyword_families = (
        ("sql", "sql_injection"),
        ("command injection", "command_injection"),
        ("path traversal", "path_traversal"),
        ("deserialize", "unsafe_deserialization"),
        ("format string", "format_string"),
        ("use-after-free", "lifetime"),
        ("use after free", "lifetime"),
        ("refcount", "lifetime"),
        ("out-of-bounds", "memory_bounds"),
        ("out of bounds", "memory_bounds"),
        ("buffer overflow", "memory_bounds"),
        ("integer overflow", "integer_overflow"),
        ("wraparound", "integer_overflow"),
        ("auth", "authorization"),
        ("permission", "authorization"),
        ("credential", "credential_storage"),
        ("secret", "credential_storage"),
        ("information disclosure", "information_disclosure"),
    )
    for keyword, family in keyword_families:
        if keyword in text:
            return family
    return ""


def _normalised_review_file(value):
    return str(value or "").replace("\\", "/").lstrip("./")


def _short_function_name(value):
    text = str(value or "").strip()
    return text.rsplit("::", 1)[-1] if text else ""


def _validation_batches(candidates, batch_size=_REVIEW_VALIDATION_BATCH_SIZE):
    sorted_candidates = sorted(
        candidates,
        key=lambda item: (
            str(item.get("primary_file") or ""),
            str(item.get("primary_function") or ""),
            _safe_int(item.get("index"), 0),
        ),
    )
    return [
        sorted_candidates[index : index + batch_size]
        for index in range(0, len(sorted_candidates), batch_size)
    ]


def _review_item_to_reachability_finding(item, *, finding_id):
    root_cause, evidence = _split_reachability_reasoning(item.get("reasoning"))
    primary_file = str(item.get("primary_file") or "")
    primary_function = str(item.get("primary_function") or "")
    line_number = _safe_int(item.get("line_number"), 0)
    return VulnerabilityFinding(
        id=finding_id,
        vulnerability_type="other",
        severity=str(item.get("severity") or "medium").lower(),
        confidence=_safe_float(item.get("confidence"), 0.0),
        source_function=primary_function,
        source_file=primary_file,
        source_line=line_number,
        sink_function=primary_function,
        sink_file=primary_file,
        sink_line=line_number,
        path=_safe_string_list(item.get("path")),
        description=str(item.get("issue") or ""),
        root_cause=root_cause,
        evidence=evidence,
        mitigation=str(item.get("mitigation") or ""),
        cwe=str(item.get("cwe") or ""),
        analysis_type=str(item.get("analysis_type") or "reachability"),
        primary_file=primary_file,
        primary_function=primary_function,
        primary_line=line_number,
        canonical_key=str(item.get("canonical_key") or ""),
    )


def _split_reachability_reasoning(reasoning):
    root_cause = ""
    evidence_lines = []
    for raw_line in str(reasoning or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("Root cause:"):
            root_cause = line.removeprefix("Root cause:").strip()
            continue
        if line.startswith(_REACHABILITY_REASONING_METADATA_PREFIXES):
            continue
        evidence_lines.append(line)
    return root_cause, "\n".join(evidence_lines)


def _safe_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe_float(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _normalised_confidence(value, *, fallback=0.0):
    if isinstance(value, str):
        word = value.strip().lower()
        if word in {"critical", "certain"}:
            return 0.98
        if word == "high":
            return 0.85
        if word == "medium":
            return 0.6
        if word == "low":
            return 0.35
    parsed = _safe_float(value, _safe_float(fallback, 0.0))
    if parsed > 1.0 and parsed <= 100.0:
        parsed = parsed / 100.0
    return max(0.0, min(1.0, parsed))


def _safe_string_list(value):
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if item]
