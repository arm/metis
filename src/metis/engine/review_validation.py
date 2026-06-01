# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import json
import logging
from typing import Any

from pydantic import BaseModel, Field

from metis.engine.review_finding_adapter import (
    safe_float as _safe_float,
    split_reachability_reasoning as _split_reachability_reasoning,
)
from metis.utils import parse_json_output

from .llm_runner import JsonPromptRequest, JsonPromptRunner
from .reachability.finding_values import _safe_int
from .reachability.source_context import _read_line_context, _read_named_function_body

logger = logging.getLogger("metis")

_REVIEW_VALIDATION_BATCH_SIZE = 5
_REVIEW_VALIDATION_SEVERITY_RANK = dict(
    zip("critical high medium low".split(), range(4), strict=True)
)
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
- When keep=false, set drop_reason to a concise snake_case reason. Use
  drop_reason=duplicate for duplicate drops. Leave drop_reason empty when
  keep=true or when the only concern is that practical exploitability is not
  fully proven.
- Calibrate confidence as a number from 0.0 to 1.0 based on evidence quality,
  source/sink specificity, exploitability prerequisites, and code support.
- Do not add findings or rewrite the report. Only decide keep/drop and
  confidence/drop_reason for the provided indexes.

Return JSON only:
{
  "decisions": [
    {
      "index": 0,
      "keep": true,
      "confidence": 0.82,
      "drop_reason": "",
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
    drop_reason: str = Field(
        "",
        description=(
            "Concise snake_case reason when keep=false; empty when keep=true "
            "or the drop is not based on a concrete validation category."
        ),
    )
    reason: str = Field("", description="Concise validation reason.")


class _ReviewValidationResponseModel(BaseModel):
    decisions: list[_ReviewValidationDecisionModel] = Field(default_factory=list)


class ReviewFindingValidator:
    def __init__(self, config, reachability_settings: dict[str, Any] | None = None):
        self._config = config
        self._reachability_settings = dict(reachability_settings or {})
        self._runner = JsonPromptRunner(config.llm_provider, config.usage_runtime)

    def validate_candidates(self, candidates):
        model = (
            self._reachability_settings.get("validation_model")
            or self._reachability_settings.get("confirmation_model")
            or self._config.llama_query_model
        )
        reasoning_effort = self._reachability_settings.get("reasoning_effort")
        decisions = []
        for batch in _validation_batches(candidates):
            parsed = self.invoke_batch(
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

    def invoke_batch(self, batch, *, model, reasoning_effort=None):
        return self._runner.invoke(
            JsonPromptRequest(
                model=model,
                max_tokens=6000,
                temperature=0.0,
                system_prompt=_REVIEW_VALIDATION_SYSTEM_PROMPT,
                user_prompt=(
                    "Candidate findings JSON:\n{candidate_findings}\n\n"
                    "Return exactly one JSON object with a top-level "
                    '"decisions" array. Do not return markdown or prose.'
                ),
                variables={
                    "candidate_findings": json.dumps(batch, separators=(",", ":"))
                },
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
        )


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
        if not _is_strong_review_validation_candidate(candidate):
            continue
        key = (
            str(candidate.get("primary_file") or "").replace("\\", "/").lstrip("./"),
            _short_function_name(candidate.get("primary_function")),
            _safe_int(candidate.get("line_number"), 0),
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


def _review_validation_final_keep(candidate, decision):
    if not isinstance(decision, dict):
        return True
    if bool(decision.get("keep", True)):
        return True
    if _review_validation_drop_reason(decision):
        return False
    return not _is_weak_review_validation_candidate(candidate)


def _review_validation_drop_reason(decision):
    drop_reason = str((decision or {}).get("drop_reason") or "").strip().lower()
    return "" if drop_reason in {"", "none", "null", "n/a"} else drop_reason


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


def _needs_reachability_validation(item):
    if not _is_reachability_review_item(item):
        return False
    return "review_validation_keep" not in item


def _is_reachability_review_item(item):
    if not isinstance(item, dict):
        return False
    if not item.get("primary_file") or not item.get("primary_function"):
        return False
    reasoning = str(item.get("reasoning") or "")
    return bool(item.get("analysis_type") or "Root cause:" in reasoning)


def _review_validation_duplicate_signal(decision):
    return _review_validation_drop_reason(decision) == "duplicate"


def _is_weak_review_validation_candidate(candidate):
    severity = str(candidate.get("severity") or "").strip().lower()
    confidence = _normalised_confidence(candidate.get("confidence"))
    return confidence < 0.70 or severity == "low"


def _is_strong_review_validation_candidate(candidate):
    severity = str(candidate.get("severity") or "").strip().lower()
    confidence = _normalised_confidence(candidate.get("confidence"))
    if severity in {"critical", "high"} and confidence >= 0.70:
        return True
    return confidence >= 0.90


def _review_validation_strength_key(candidate):
    severity = str(candidate.get("severity") or "").strip().lower()
    return (
        -_REVIEW_VALIDATION_SEVERITY_RANK.get(severity, 99),
        _normalised_confidence(candidate.get("confidence")),
        -_safe_int(candidate.get("line_number"), 0),
        str(candidate.get("issue") or ""),
    )


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


parse_review_validation_response = _parse_review_validation_response
rescue_filtered_duplicate_cluster_representatives = (
    _rescue_filtered_duplicate_cluster_representatives
)
review_validation_final_keep = _review_validation_final_keep
review_validation_payload = _review_validation_payload
review_validation_drop_reason = _review_validation_drop_reason
split_reachability_reasoning = _split_reachability_reasoning
normalised_confidence = _normalised_confidence
needs_reachability_validation = _needs_reachability_validation
is_reachability_review_item = _is_reachability_review_item
safe_float = _safe_float
