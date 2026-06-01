# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0


import logging
import os
from collections import defaultdict

from metis.engine.llm_runner import JsonPromptRequest, JsonPromptRunner

from .llm_runner import reachability_response_payload
from .domain_hints import format_domain_hints_for_prompt, normalize_domain_hints
from .graph_utils import _emit_progress
from .llm_schemas import ReachabilityFindingResponseModel
from .options import ReachabilityReviewOptions
from .progress import ReachabilityProgress as Progress
from . import supplementary_runners
from .supplementary_lenses import (
    _COMBINED_GRAPH_LENS_NOTES,
    build_supplementary_lenses,
)
from .workers import ReachabilityWorkerBudget, run_reachability_jobs

logger = logging.getLogger("metis")


class SupplementaryAnalyzer:
    def __init__(
        self,
        llm_provider,
        model,
        usage_runtime,
        codebase_path,
        *,
        audit_max_tokens=8192,
        strong_max_tokens=16384,
        options=None,
    ):
        self._p = llm_provider
        self._m = model
        self._u = usage_runtime
        self._cb = os.path.abspath(codebase_path)
        self._at = audit_max_tokens
        self._st = strong_max_tokens
        self._reasoning_effort = options.reasoning_effort if options else None
        self._runner = JsonPromptRunner(llm_provider, usage_runtime)
        self._domain_hints = normalize_domain_hints(
            options.domain_hints if options else None,
            options.domain_profiles if options else None,
        )
        self._domain_keywords = self._domain_hints["keywords"]
        self._domain_prompt_hints = format_domain_hints_for_prompt(self._domain_hints)

    def _with_domain_hints(self, prompt):
        return (
            f"{prompt}\n\n{self._domain_prompt_hints}"
            if self._domain_prompt_hints
            else prompt
        )

    def analyze(
        self,
        graph,
        *,
        options=None,
        max_workers=1,
        progress_callback=None,
        lens_profile="all",
    ):
        if options is None:
            options = ReachabilityReviewOptions(
                max_workers=max_workers,
                progress_callback=progress_callback,
                lens_profile=lens_profile,
            )
        max_workers = options.max_workers
        progress_callback = options.progress_callback
        lens_profile = options.lens_profile
        lenses = build_supplementary_lenses(str(lens_profile or "all"))
        if not lenses:
            return []
        findings = []
        worker_budget = ReachabilityWorkerBudget.from_value(max_workers)
        lens_parallelism, lens_workers = worker_budget.split(len(lenses), phase_cap=8)
        lens_options = options.with_max_workers(lens_workers) if options else None

        def _run_lens(lens):
            try:
                return lens.run(
                    self,
                    graph,
                    lens_options,
                )
            except KeyboardInterrupt:
                raise
            except Exception as exc:
                name = lens.name
                logger.warning("%s lens fail: %s", name, exc)
                _emit_progress(
                    progress_callback,
                    f"{name}_error",
                    error=f"{type(exc).__name__}: {exc}",
                )
                return []

        if lens_parallelism == 1:
            for lens in lenses:
                findings.extend(_run_lens(lens))
        else:
            lens_results = run_reachability_jobs(
                lenses,
                _run_lens,
                max_workers=lens_parallelism,
                label="Supplementary lens",
                result_key=lambda lens: lens.name,
            )
            for lens_result in lens_results:
                findings.extend(lens_result)
        if progress_callback:
            by_type = defaultdict(int)
            for f in findings:
                by_type[f.analysis_type] += 1
            _emit_progress(
                progress_callback,
                Progress.SUPPLEMENTARY_DONE,
                **dict(by_type),
                total=len(findings),
            )
        return findings

    def _combined_prompt_variables(self, analysis_types, code):
        analysis_types = list(analysis_types)
        lens_instructions = "\n".join(
            _COMBINED_GRAPH_LENS_NOTES.get(analysis_type, analysis_type)
            for analysis_type in analysis_types
        )
        if self._domain_prompt_hints:
            lens_instructions = f"{lens_instructions}\n\n{self._domain_prompt_hints}"
        return {
            "all_functions_code": code,
            "allowed_analysis_types": ", ".join(analysis_types),
            "lens_instructions": lens_instructions,
        }

    def _invoke_findings(
        self, system_prompt, user_prompt, variables, *, max_tokens=None
    ):
        return self._runner.invoke(
            JsonPromptRequest(
                model=self._m,
                max_tokens=max_tokens or self._st,
                temperature=0.1,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                variables=variables,
                parse=reachability_response_payload,
                logger=logger,
                label="Supplementary reachability analysis",
                batch_size=1,
                invalid_message="expected findings list",
                final_keep_message="keeping this supplementary batch empty",
                response_model=ReachabilityFindingResponseModel,
                reasoning_effort=self._reasoning_effort,
            )
        )

    def run_combined_graph_lenses(self, specs, graph, options):
        return supplementary_runners.run_combined_graph_lenses(
            self,
            specs,
            graph,
            options,
        )

    def _lens_intra(self, graph, options):
        return supplementary_runners.run_intra_lens(self, graph, options)

    def run_candidate_lens(
        self,
        graph,
        spec,
        options,
    ):
        return supplementary_runners.run_candidate_lens(self, graph, spec, options)

    def _lens_global_lifecycle(self, graph, options):
        return supplementary_runners.run_global_lifecycle_lens(self, graph, options)

    def _lens_lock_order(self, graph, options):
        return supplementary_runners.run_lock_order_lens(self, graph, options)
