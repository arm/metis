# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import logging
import os

from .reachability import FindingConsolidator, VulnerabilityFinding
from .reachability.finding_values import _safe_int
from .review_validation import (
    ReviewFindingValidator,
    is_reachability_review_item,
    needs_reachability_validation,
    normalised_confidence,
    review_validation_drop_reason,
    review_validation_final_keep,
    review_validation_payload,
    safe_float,
    split_reachability_reasoning,
)

logger = logging.getLogger("metis")

_DROP_REVIEW_ITEM = object()


class ReviewResultAggregator:
    def __init__(self, config, reachability_settings, final_adjudicator=None):
        self._config = config
        self._reachability_settings = dict(reachability_settings or {})
        self._final_adjudicator = final_adjudicator
        self._validator = ReviewFindingValidator(config, self._reachability_settings)

    def aggregate(self, results, *, validate_candidates=None):
        if not isinstance(results, dict):
            return results

        review_groups = results.get("reviews")
        if not isinstance(review_groups, list):
            return results

        refs, findings = self._reachability_findings_from_review_groups(review_groups)
        if not findings:
            return results

        aggregated = self._deduplicate_review_groups(results, refs, findings)
        return self._validate_review_groups(
            aggregated,
            validate_candidates=validate_candidates,
        )

    def _deduplicate_review_groups(self, results, refs, findings):
        if len(findings) < 2:
            return results

        review_groups = results.get("reviews")
        if not isinstance(review_groups, list):
            return results

        if not callable(self._final_adjudicator):
            return results

        model = (
            self._reachability_settings.get("confirmation_model")
            or self._config.llama_query_model
        )
        reasoning_effort = self._reachability_settings.get("reasoning_effort")
        deduped, total, removed = FindingConsolidator.deduplicate(
            findings,
            final_adjudicator=lambda candidates: self._final_adjudicator(
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

    def _validate_review_groups(self, results, *, validate_candidates=None):
        review_groups = results.get("reviews") if isinstance(results, dict) else None
        if not isinstance(review_groups, list):
            return results

        candidates = []
        candidate_refs = []
        for group_index, item_index, item in _iter_review_items(review_groups):
            if needs_reachability_validation(item):
                candidate_refs.append((group_index, item_index))
                candidates.append(
                    review_validation_payload(
                        len(candidates), item, codebase_path=self._config.codebase_path
                    )
                )

        if not candidates:
            return results

        validate = validate_candidates or self._validator.validate_candidates
        decisions = validate(candidates)
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
            item_copy["confidence"] = normalised_confidence(
                decision.get("confidence"),
                fallback=item_copy.get("confidence"),
            )
            item_copy["review_validation_reason"] = str(
                decision.get("reason") or ""
            ).strip()
            drop_reason = review_validation_drop_reason(decision)
            if drop_reason:
                item_copy["review_validation_drop_reason"] = drop_reason
            model_keep = bool(decision.get("keep", True))
            keep = review_validation_final_keep(candidates[candidate_index], decision)
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

    def _reachability_findings_from_review_groups(self, review_groups):
        refs = []
        findings = []
        for group_index, item_index, item in _iter_review_items(review_groups):
            if not is_reachability_review_item(item):
                continue
            finding = _review_item_to_reachability_finding(
                item, finding_id=f"review-aggregate-{len(findings)}"
            )
            refs.append((group_index, item_index))
            findings.append(finding)
        return refs, findings


def same_review_file(left, right):
    return os.path.normcase(os.path.normpath(str(left or ""))) == os.path.normcase(
        os.path.normpath(str(right or ""))
    )


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


def _review_item_to_reachability_finding(item, *, finding_id):
    root_cause, evidence = split_reachability_reasoning(item.get("reasoning"))
    primary_file = str(item.get("primary_file") or "")
    primary_function = str(item.get("primary_function") or "")
    line_number = _safe_int(item.get("line_number"), 0)
    return VulnerabilityFinding(
        finding_id,
        "other",
        str(item.get("severity") or "medium").lower(),
        safe_float(item.get("confidence"), 0.0),
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
