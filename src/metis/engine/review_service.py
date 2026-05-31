# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import inspect
import json
import logging
import os
import threading
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from pydantic import BaseModel, Field
import unidiff

from metis.plugins.c_family import is_c_family_plugin
from metis.usage import submit_with_current_context
from metis.utils import parse_json_output, read_file_content

from .diff_utils import process_diff_file
from .graphs.types import ReviewRequest
from .helpers import apply_custom_guidance, summarize_changes
from .options import ReviewOptions, coerce_review_options
from .reachability import FindingConsolidator, VulnerabilityFinding
from .reachability.finding_normalization import _safe_int
from .reachability.llm_runner import invoke_json_prompt_with_retry
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
    "authorization command_injection credential_storage format_string information_disclosure "
    "integer_overflow lifetime memory_bounds path_traversal race_condition resource_exhaustion "
    "sql_injection unsafe_deserialization unchecked_error".split()
)
_REVIEW_VALIDATION_SEVERITY_RANK = dict(
    zip("critical high medium low".split(), range(4), strict=True)
)
_REVIEW_VALIDATION_FALSE_POSITIVE_MARKERS = tuple(
    marker
    for group in (
        "false positive|already validated|already checked|already bounds-checked|"
        "bounds checked before|validated before|guarded before|checked before|"
        "unreachable|not reachable|cannot reach|no reachable path|"
        "wrong function|wrong file|wrong line|different object|different allocation|"
        "different resource|not dereferenced|not indexed|not freed|not released|"
        "not user-controlled|attacker cannot control|input is trusted|"
        "evidence contradicts|code contradicts|snippet contradicts|snippet shows no|code shows no",
    )
    for marker in group.split("|")
)
_REVIEW_VALIDATION_KEYWORD_FAMILIES = tuple(
    item.rsplit(":", 1)
    for group in (
        "sql:sql_injection|command injection:command_injection|path traversal:path_traversal",
        "deserialize:unsafe_deserialization|format string:format_string|use-after-release:lifetime|"
        "use-after-free:lifetime|use after free:lifetime|dangling:lifetime|stale pointer:lifetime|"
        "refcount:lifetime|callback:lifetime",
        "out-of-bounds:memory_bounds|out of bounds:memory_bounds",
        "bounds check:memory_bounds|array access:memory_bounds|array index:memory_bounds",
        "index:memory_bounds|buffer overflow:memory_bounds|fixed buffer:memory_bounds",
        "integer overflow:integer_overflow|unchecked arithmetic:integer_overflow",
        "unchecked addition:integer_overflow|wraparound:integer_overflow|wrap:integer_overflow",
        "race:race_condition|concurrent:race_condition|toctou:race_condition|"
        "lock:race_condition|workqueue:race_condition",
        "resource exhaustion:resource_exhaustion|denial of service:resource_exhaustion",
        "descriptor:resource_exhaustion| fd :resource_exhaustion|leak:resource_exhaustion",
        "not released:resource_exhaustion|not freed:resource_exhaustion",
        "not dropped:resource_exhaustion|not unpinned:resource_exhaustion",
        "pinned:resource_exhaustion|accounting:resource_exhaustion",
        "cleanup:lifetime|unwind:lifetime|rollback:lifetime|unregister:lifetime|"
        "cancel:lifetime|flush:lifetime|unchecked error:unchecked_error|"
        "missing validation:memory_bounds|auth:authorization|permission:authorization|"
        "credential:credential_storage|secret:credential_storage|information disclosure:information_disclosure",
    )
    for item in group.split("|")
)
_DROP_REVIEW_ITEM = object()
_REVIEW_VALIDATION_SYSTEM_PROMPT = """You validate reachability security review findings before the final report.

You receive candidate findings from an automated review. Be conservative when
dropping findings: this pass should reduce obvious fakes, weak speculation, and
duplicates while preserving plausible security bug candidates.

For each candidate:
- keep=true when the finding describes a plausible security bug candidate
  supported by the supplied evidence and code context.
- Do not drop credible memory-safety, bounds, arithmetic, lifetime, race,
  resource-exhaustion, cleanup, or accounting findings merely because practical
  exploitability is not fully proven.
- keep=false only for clear false positives, unsupported speculation, generic
  style issues, missing-prerequisite reports, or duplicates already represented
  by a stronger candidate in the same batch.
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


class _ReviewValidationResponseModel(BaseModel):
    decisions: list[_ReviewValidationDecisionModel] = Field(default_factory=list)


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
        item_replacements = {
            ref: _DROP_REVIEW_ITEM
            for ref, finding in zip(refs, findings)
            if finding.id not in kept_ids
        }
        aggregated = dict(results)
        aggregated["reviews"] = _rewrite_review_groups(review_groups, item_replacements)
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
        for group_index, item_index, item in _iter_review_items(review_groups):
            if _needs_reachability_validation(item):
                candidate_refs.append((group_index, item_index))
                candidates.append(
                    _review_validation_payload(
                        len(candidates), item, codebase_path=self._config.codebase_path
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

        kept_count = 0
        filtered_count = 0
        item_replacements = {}
        filtered_by_group = {}
        for candidate_index, ref in enumerate(candidate_refs):
            decision = decisions_by_index.get(candidate_index)
            if decision is None:
                continue
            group_index, item_index = ref
            item = review_groups[group_index]["reviews"][item_index]
            item_copy = dict(item)
            item_copy["confidence"] = _normalised_confidence(
                decision.get("confidence"),
                fallback=item_copy.get("confidence"),
            )
            item_copy["review_validation_reason"] = str(
                decision.get("reason") or ""
            ).strip()
            model_keep = bool(decision.get("keep", True))
            keep = _review_validation_final_keep(candidates[candidate_index], decision)
            item_copy["review_validation_keep"] = keep
            if keep != model_keep:
                item_copy["review_validation_model_keep"] = model_keep
                item_copy["review_validation_override_reason"] = (
                    "Kept by conservative review guardrails."
                )
            if keep:
                kept_count += 1
                item_replacements[ref] = item_copy
            else:
                filtered_count += 1
                item_copy["review_validation_filtered"] = True
                item_replacements[ref] = _DROP_REVIEW_ITEM
                filtered_by_group.setdefault(group_index, []).append(item_copy)

        validated = dict(results)
        validated["reviews"] = _rewrite_review_groups(
            review_groups,
            item_replacements,
            filtered_by_group,
        )
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
        return invoke_json_prompt_with_retry(
            self._config.llm_provider,
            self._config.usage_runtime,
            model=model,
            max_tokens=6000,
            temperature=0.0,
            system_prompt=_REVIEW_VALIDATION_SYSTEM_PROMPT,
            user_prompt=(
                "Candidate findings JSON:\n{candidate_findings}\n\n"
                "Return exactly one JSON object with a top-level "
                '"decisions" array. Do not return markdown or prose.'
            ),
            variables={"candidate_findings": json.dumps(batch, separators=(",", ":"))},
            parse=_parse_review_validation_response,
            logger=logger,
            label="Review validation",
            batch_size=len(batch),
            invalid_message=(
                "expected structured validation payload or JSON object with "
                "decisions list"
            ),
            final_keep_message="keeping batch unchanged",
            response_model=_ReviewValidationResponseModel,
            reasoning_effort=reasoning_effort,
        )

    def _reachability_findings_from_review_groups(self, review_groups):
        refs = []
        findings = []
        for group_index, item_index, item in _iter_review_items(review_groups):
            if not _is_reachability_review_item(item):
                continue
            finding = _review_item_to_reachability_finding(
                item, finding_id=f"review-aggregate-{len(findings)}"
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


def _iter_review_items(review_groups):
    for group_index, group in enumerate(review_groups):
        items = group.get("reviews") if isinstance(group, dict) else None
        if isinstance(items, list):
            for item_index, item in enumerate(items):
                yield group_index, item_index, item


def _rewrite_review_groups(review_groups, item_replacements, filtered_by_group=None):
    filtered_by_group = filtered_by_group or {}
    rewritten = []
    for group_index, group in enumerate(review_groups):
        if not isinstance(group, dict):
            rewritten.append(group)
            continue
        items = group.get("reviews")
        if not isinstance(items, list):
            rewritten.append(group)
            continue

        touched = False
        kept_items = []
        for item_index, item in enumerate(items):
            replacement = item_replacements.get((group_index, item_index), item)
            if replacement is _DROP_REVIEW_ITEM:
                touched = True
                continue
            touched = touched or replacement is not item
            kept_items.append(replacement)

        filtered_items = list(group.get("review_validation_filtered_reviews") or [])
        filtered_items.extend(filtered_by_group.get(group_index, ()))
        if kept_items or filtered_items or not touched:
            rewritten_group = dict(group) if touched or filtered_items else group
            if touched or filtered_items:
                rewritten_group["reviews"] = kept_items
            if filtered_items:
                rewritten_group["review_validation_filtered_reviews"] = filtered_items
            rewritten.append(rewritten_group)
    return rewritten


def _parse_review_validation_response(raw):
    structured = _review_validation_structured_payload(raw)
    if structured is not None:
        return structured
    parsed = parse_json_output(raw)
    for _ in range(3):
        if isinstance(parsed, str):
            try:
                parsed = json.loads(parsed)
                continue
            except (TypeError, ValueError):
                return None
        if isinstance(parsed, list):
            return {"decisions": parsed}
        if isinstance(parsed, dict) and isinstance(parsed.get("decisions"), list):
            return parsed
        return None
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
        codebase_path, primary_file, line_number, context=4, max_chars=1800
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
    duplicate_signal = set()
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
            str(candidate.get("primary_file") or "").replace("\\", "/").lstrip("./"),
            _short_function_name(candidate.get("primary_function")),
            _safe_int(candidate.get("line_number"), 0),
            family,
        )
        clusters.setdefault(key, []).append(candidate)
        if _review_validation_duplicate_signal(decisions_by_index.get(candidate_index)):
            duplicate_signal.add(key)

    changed = False
    for key, cluster in clusters.items():
        if len(cluster) < 2 or key not in duplicate_signal:
            continue
        indexes = [_safe_int(candidate.get("index"), -1) for candidate in cluster]
        if any(index not in decisions_by_index for index in indexes):
            continue
        if any(decisions_by_index[index].get("keep", True) for index in indexes):
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

    return [
        (
            decisions_by_index.get(_safe_int(decision.get("index"), -1), decision)
            if isinstance(decision, dict)
            else decision
        )
        for decision in decisions
    ]


def _review_validation_duplicate_signal(decision):
    reason = str((decision or {}).get("reason") or "").lower()
    return any(
        marker in reason
        for marker in (
            "duplicate",
            "same issue",
            "same root cause",
            "already represented",
        )
    )


def _review_validation_final_keep(candidate, decision):
    if not isinstance(decision, dict):
        return True
    if bool(decision.get("keep", True)):
        return True
    if _review_validation_duplicate_signal(decision):
        return False
    if _review_validation_concrete_false_positive_signal(decision):
        return False
    return not _is_weak_review_validation_candidate(candidate)


def _is_weak_review_validation_candidate(candidate):
    severity = str(candidate.get("severity") or "").strip().lower()
    confidence = _normalised_confidence(candidate.get("confidence"))
    family = _review_validation_issue_family(candidate)
    return confidence < 0.70 or severity == "low" or not family


def _review_validation_concrete_false_positive_signal(decision):
    reason = str((decision or {}).get("reason") or "").lower()
    if not reason:
        return False
    return any(marker in reason for marker in _REVIEW_VALIDATION_FALSE_POSITIVE_MARKERS)


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
    for keyword, family in _REVIEW_VALIDATION_KEYWORD_FAMILIES:
        if keyword in text:
            return family
    return ""


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
        finding_id,
        "other",
        str(item.get("severity") or "medium").lower(),
        _safe_float(item.get("confidence"), 0.0),
        primary_function,
        primary_file,
        line_number,
        primary_function,
        primary_file,
        line_number,
        path=(
            [str(path_item) for path_item in item.get("path") if path_item]
            if isinstance(item.get("path"), list)
            else []
        ),
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


def _safe_float(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _normalised_confidence(value, *, fallback=0.0):
    if isinstance(value, str):
        word = value.strip().lower()
        if word in {"critical", "certain"}:
            word = "certain"
        if word in {"certain", "high", "medium", "low"}:
            return {"certain": 0.98, "high": 0.85, "medium": 0.6, "low": 0.35}[word]
    parsed = _safe_float(value, _safe_float(fallback, 0.0))
    if parsed > 1.0 and parsed <= 100.0:
        parsed = parsed / 100.0
    return max(0.0, min(1.0, parsed))
