# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import asdict
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any
from uuid import uuid4

from metis.sarif.triage import apply_triage_result
from metis.sarif.triage import load_sarif_file
from metis.sarif.triage import save_sarif_file
from metis.sarif.writer import SARIF_VERSION

from .runner import ExternalStageProcessResult
from .runner import ExternalStageExecutionError
from .runner import ExternalStageRunner
from .runner import command_placeholders
from .schemas import AnalysisRequestModel
from .schemas import ExternalStageCommandModel
from .schemas import ExternalStagesConfigModel
from .schemas import ValidationRequestModel
from .schemas import ValidationResultModel


@dataclass(frozen=True, slots=True)
class ExternalAnalysisResult:
    run_dir: Path
    request_path: Path
    output_sarif: Path
    process: ExternalStageProcessResult


@dataclass(frozen=True, slots=True)
class ExternalValidationResult:
    run_dir: Path
    request_path: Path
    input_sarif: Path
    output_decision: Path
    validated_sarif: Path
    process: ExternalStageProcessResult


@dataclass(frozen=True, slots=True)
class ExternalPipelineResult:
    run_dir: Path
    analysis: ExternalAnalysisResult
    validation: ExternalValidationResult | None

    @property
    def final_sarif(self) -> Path:
        if self.validation is not None:
            return self.validation.validated_sarif
        return self.analysis.output_sarif


class ExternalStageService:
    def __init__(
        self,
        *,
        codebase_path: str,
        config: dict[str, Any] | None,
        runner: ExternalStageRunner | None = None,
    ):
        self.codebase_path = codebase_path
        self.config = ExternalStagesConfigModel.model_validate(config or {})
        self.runner = runner or ExternalStageRunner()

    def run_pipeline(
        self,
        *,
        analysis: str,
        validation: str | None = None,
        prompt: str,
        codebase_path: str | Path | None = None,
        scope: list[str] | None = None,
        run_dir: str | Path | None = None,
    ) -> ExternalPipelineResult:
        resolved_run_dir = _resolve_run_dir(run_dir)
        analysis_result = self.run_analysis(
            analysis,
            prompt=prompt,
            codebase_path=codebase_path,
            scope=scope,
            run_dir=resolved_run_dir,
        )
        validation_result = None
        if validation:
            validation_result = self.run_validation(
                validation,
                input_sarif=analysis_result.output_sarif,
                codebase_path=codebase_path,
                run_dir=resolved_run_dir,
            )
        return ExternalPipelineResult(
            run_dir=resolved_run_dir,
            analysis=analysis_result,
            validation=validation_result,
        )

    def run_analysis(
        self,
        name: str,
        *,
        prompt: str,
        codebase_path: str | Path | None = None,
        scope: list[str] | None = None,
        run_dir: str | Path | None = None,
    ) -> ExternalAnalysisResult:
        stage = self._analysis_stage(name)
        _validate_analysis_bindings(name, stage)
        resolved_run_dir = _resolve_run_dir(run_dir)
        resolved_run_dir.mkdir(parents=True, exist_ok=True)
        codebase = _resolve_codebase_path(codebase_path or self.codebase_path)
        output_sarif = resolved_run_dir / "analysis.sarif"
        if output_sarif.exists():
            raise FileExistsError(
                f"External stage output already exists: {output_sarif}"
            )
        request_path = resolved_run_dir / "analysis-request.json"
        request = AnalysisRequestModel(
            run_id=resolved_run_dir.name,
            codebase_path=str(codebase),
            commit=None,
            scope=list(scope or []),
            prompt=prompt,
            output_sarif=str(output_sarif),
        )
        _write_json(request_path, request.model_dump(mode="json"), exclusive=True)
        bindings = {
            "codebase_path": codebase,
            "request_path": request_path,
            "output_sarif": output_sarif,
            "run_dir": resolved_run_dir,
            "prompt": prompt,
        }
        process = _run_stage_and_log(
            self.runner,
            stage,
            bindings=bindings,
            log_path=resolved_run_dir / "analysis-process.json",
        )
        _require_file(output_sarif, "analysis SARIF")
        validate_metis_sarif(load_sarif_file(output_sarif))
        return ExternalAnalysisResult(
            run_dir=resolved_run_dir,
            request_path=request_path,
            output_sarif=output_sarif,
            process=process,
        )

    def run_validation(
        self,
        name: str,
        *,
        input_sarif: str | Path,
        codebase_path: str | Path | None = None,
        run_dir: str | Path | None = None,
    ) -> ExternalValidationResult:
        stage = self._validation_stage(name)
        _validate_validation_bindings(name, stage)
        resolved_run_dir = _resolve_run_dir(run_dir)
        resolved_run_dir.mkdir(parents=True, exist_ok=True)
        codebase = _resolve_codebase_path(codebase_path or self.codebase_path)
        input_sarif_path = Path(input_sarif).resolve()
        validate_metis_sarif(load_sarif_file(input_sarif_path))
        output_decision = resolved_run_dir / "validation-decision.json"
        validated_sarif = resolved_run_dir / "validated.sarif"
        for output in (output_decision, validated_sarif):
            if output.exists():
                raise FileExistsError(f"External stage output already exists: {output}")
        request_path = resolved_run_dir / "validation-request.json"
        request = ValidationRequestModel(
            run_id=resolved_run_dir.name,
            codebase_path=str(codebase),
            input_sarif=str(input_sarif_path),
            commit=None,
            output_decision=str(output_decision),
        )
        _write_json(request_path, request.model_dump(mode="json"), exclusive=True)
        bindings = {
            "codebase_path": codebase,
            "input_sarif": input_sarif_path,
            "request_path": request_path,
            "output_decision": output_decision,
            "run_dir": resolved_run_dir,
        }
        process = _run_stage_and_log(
            self.runner,
            stage,
            bindings=bindings,
            log_path=resolved_run_dir / "validation-process.json",
        )
        _require_file(output_decision, "validation decision")
        decisions = _load_validation_result(output_decision)
        payload = load_sarif_file(input_sarif_path)
        validate_metis_sarif(payload)
        for decision in decisions.decisions:
            applied = apply_triage_result(
                payload,
                run_index=decision.run_index,
                result_index=decision.result_index,
                status=decision.status,
                reason=decision.reason,
                metadata=decision.triage_decision_metadata(),
            )
            if not applied:
                raise ValueError(
                    "Validation decision references missing SARIF result: "
                    f"run={decision.run_index} result={decision.result_index}"
                )
        save_sarif_file(validated_sarif, payload)
        return ExternalValidationResult(
            run_dir=resolved_run_dir,
            request_path=request_path,
            input_sarif=input_sarif_path,
            output_decision=output_decision,
            validated_sarif=validated_sarif,
            process=process,
        )

    def _analysis_stage(self, name: str) -> ExternalStageCommandModel:
        try:
            return self.config.analysis[name]
        except KeyError as exc:
            available = ", ".join(sorted(self.config.analysis)) or "<none>"
            raise ValueError(
                f"Unknown external analysis stage {name!r}; available: {available}"
            ) from exc

    def _validation_stage(self, name: str) -> ExternalStageCommandModel:
        try:
            return self.config.validation[name]
        except KeyError as exc:
            available = ", ".join(sorted(self.config.validation)) or "<none>"
            raise ValueError(
                f"Unknown external validation stage {name!r}; available: {available}"
            ) from exc


def validate_metis_sarif(payload: dict[str, Any]) -> None:
    if payload.get("version") != SARIF_VERSION:
        raise ValueError(f"Metis SARIF must use version {SARIF_VERSION}")
    runs = payload.get("runs")
    if not isinstance(runs, list):
        raise ValueError("Metis SARIF must contain a runs array")
    for run_index, run in enumerate(runs):
        if not isinstance(run, dict):
            raise ValueError(f"Metis SARIF run {run_index} must be an object")
        _validate_run(run, run_index)


def _validate_run(run: dict[str, Any], run_index: int) -> None:
    tool = run.get("tool")
    if not isinstance(tool, dict):
        raise ValueError(f"Metis SARIF run {run_index} missing tool object")
    driver = tool.get("driver")
    if not isinstance(driver, dict) or not str(driver.get("name") or "").strip():
        raise ValueError(f"Metis SARIF run {run_index} missing tool.driver.name")
    results = run.get("results")
    if not isinstance(results, list):
        raise ValueError(f"Metis SARIF run {run_index} missing results array")
    for result_index, result in enumerate(results):
        _validate_result(result, run_index, result_index)


def _validate_result(result: Any, run_index: int, result_index: int) -> None:
    prefix = f"Metis SARIF result {run_index}:{result_index}"
    if not isinstance(result, dict):
        raise ValueError(f"{prefix} must be an object")
    if not str(result.get("ruleId") or "").strip():
        raise ValueError(f"{prefix} missing ruleId")
    message = result.get("message")
    if not isinstance(message, dict) or not str(message.get("text") or "").strip():
        raise ValueError(f"{prefix} missing message.text")
    locations = result.get("locations")
    if not isinstance(locations, list) or not locations:
        raise ValueError(f"{prefix} missing locations")
    first = locations[0]
    if not isinstance(first, dict):
        raise ValueError(f"{prefix} first location must be an object")
    physical = first.get("physicalLocation")
    if not isinstance(physical, dict):
        raise ValueError(f"{prefix} missing physicalLocation")
    artifact = physical.get("artifactLocation")
    if not isinstance(artifact, dict) or not str(artifact.get("uri") or "").strip():
        raise ValueError(f"{prefix} missing artifactLocation.uri")
    region = physical.get("region")
    if not isinstance(region, dict):
        raise ValueError(f"{prefix} missing region")
    try:
        line = int(region.get("startLine"))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{prefix} missing numeric region.startLine") from exc
    if line < 1:
        raise ValueError(f"{prefix} region.startLine must be positive")


def _validate_analysis_bindings(name: str, stage: ExternalStageCommandModel) -> None:
    placeholders = command_placeholders(stage.command)
    if "request_path" in placeholders:
        return
    required = {"codebase_path", "output_sarif"}
    missing = sorted(required - placeholders)
    if missing:
        raise ValueError(
            f"External analysis stage {name!r} must reference {{request_path}} "
            "or placeholders: "
            + ", ".join(f"{{{item}}}" for item in sorted(required))
            + f"; missing {', '.join(missing)}"
        )


def _validate_validation_bindings(name: str, stage: ExternalStageCommandModel) -> None:
    placeholders = command_placeholders(stage.command)
    if "request_path" in placeholders:
        return
    required = {"codebase_path", "input_sarif", "output_decision"}
    missing = sorted(required - placeholders)
    if missing:
        raise ValueError(
            f"External validation stage {name!r} must reference {{request_path}} "
            "or placeholders: "
            + ", ".join(f"{{{item}}}" for item in sorted(required))
            + f"; missing {', '.join(missing)}"
        )


def _load_validation_result(path: Path) -> ValidationResultModel:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    return ValidationResultModel.model_validate(payload)


def _run_stage_and_log(
    runner: ExternalStageRunner,
    stage: ExternalStageCommandModel,
    *,
    bindings: dict[str, object],
    log_path: Path,
) -> ExternalStageProcessResult:
    try:
        result = runner.run_sync(stage, bindings=bindings)
    except ExternalStageExecutionError as exc:
        if exc.result is not None:
            _write_json(log_path, asdict(exc.result))
        raise
    _write_json(log_path, asdict(result))
    return result


def _resolve_codebase_path(path: str | Path) -> Path:
    resolved = Path(path).resolve()
    if not resolved.exists():
        raise FileNotFoundError(f"Codebase path does not exist: {resolved}")
    return resolved


def _resolve_run_dir(run_dir: str | Path | None) -> Path:
    if run_dir is not None:
        return Path(run_dir).resolve()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return (
        Path.cwd() / "results" / "external_stages" / f"{stamp}_{uuid4().hex}"
    ).resolve()


def _write_json(
    path: Path, payload: dict[str, Any], *, exclusive: bool = False
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x" if exclusive else "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)


def _require_file(path: Path, label: str) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"External stage did not write {label}: {path}")
