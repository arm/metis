# SARIF Triage Flow

Triage accepts SARIF from Metis or other tools and annotates existing findings;
it does not discover new findings. The packaged graph supplies Review's SARIF.
A triage-only run uses existing SARIF without running Review.
The interactive command also accepts Metis review and SARIF `.json` files,
preserving their structure, decisions, and evidence. Completed findings are skipped
unless `--include-triaged` is set. Invalid input fails before model calls or output
replacement; source reads stay within the codebase.

JSON/SARIF imports and exports have no size, count, or
nesting caps. JSON validation and atomic writes remain enforced. Available memory
and parser limits still apply. External stages use the same uncapped file handling.

## Large JSON reports

The built-in `triage` and `result` nodes always stream JSON/SARIF through the
same persisted workflow, including when Triage follows Review in the packaged
graph. HTML and CSV are derived from that persisted report at export time. The
file API returns paths and counts rather than a whole-report dictionary:

```python
result = engine.execute_triage_file("findings.sarif", "triaged.sarif")
print(result["sarif_path"], result["processed"], result["total"])
```

Metis review JSON written to JSON uses `json_path`. Unknown fields and existing
annotations survive; whitespace may change. Reads use bounded batches of at least
64 findings, growing to fit the node's worker limit. Each finding is a separate
job; a batch finishes before the next is loaded.
Models, grants, callbacks, and worker limits still apply. Prerequisite stages and
external nodes do not run for the standalone file API; incompatible triage graphs
are rejected before execution. Existing dictionary APIs stay unchanged; callbacks
receive `SarifFinding` values with exported SARIF coordinates.

Completed decisions are appended to the shared journal automatically. There are
no periodic full-report rewrites or configurable checkpoint intervals.

## Output

`--output-file` selects destinations and formats; otherwise the result node's
`filename` is used, falling back to updating the input file. No separate
`.checkpoint.sarif` is produced. Remove `triage_checkpoint_every` from existing
configuration files. Journal batching is automatic.

Journal write failures propagate without replacing a prior readable report.
Post-review triage failure or cancellation also preserves completed Review output.

## End-to-end flow
1. Read SARIF findings.
2. Read a bounded source window, with optional CodeGraph context.
3. Let the model inspect missing context with navigation tools and decide.
4. Validate the decision and its citations, then annotate SARIF:
   - `metisTriaged`
   - `metisTriageStatus`
   - `metisTriageReason`
   - `metisTriageTimestamp`
   - conditional `metisEvidenceRequirements` (list),
     `metisEvidenceCoverage` (mapping), `metisMissingEvidence` (list), and
     `metisThreatModelPolicy` (mapping) when available
   - optional `metisTriageEvidence`, `metisTriageResolutionChain`, and
     `metisTriageUnresolvedHops` (lists)
   - optional `metisTriageDecisionSource` (`model`, `validation_failure`,
     `execution_failure`, or `policy`) and `metisTriageValidationErrors` (list)

## Evidence collection

Each finding starts with one bounded `sed` window around its reported location.
The model chooses further source reads or symbol searches to follow the reported
path and check relevant defenses. Navigation can correct an inaccurate location;
missing source alone does not refute a finding.

Language plugins can add navigation guidance. When the optional CodeGraph
covers the finding, the evidence pack also includes the containing function,
its direct callers and callees, unresolved calls, and available entrypoint,
source, and sink annotations. The same workflow runs without that section when
the graph does not cover the file.

## Source-aware behavior (Metis SARIF vs external SARIF)
Metis findings can reuse their original explanation (`reasoning/why/mitigation`)
and start with a slightly wider source window. External SARIF uses a narrower
window. Finding text is context, not verified source evidence.

## Model decisions and source validation

The model decides whether source evidence supports the finding (`valid`),
refutes it (`invalid`), or cannot settle it (`inconclusive`). Verdicts are not
overridden by keyword rules.

Both decisive statuses require citations and a resolution chain in the built-in
workflow. Citations use `file:line` or `file:start-end`. They must refer to source
lines actually displayed in the initial evidence or successful navigation-tool
results for that finding, remain inside the codebase, and match current source.
These checks verify provenance, not the semantic truth of the model's reasoning.
Validated citations are exported as sorted, deduplicated codebase-relative paths;
single-line ranges use `file:line`.
Triage enforces `max_token_length` and the configured tool-round limit.

Unusable citations produce `inconclusive` with
`metisTriageDecisionSource: validation_failure` and machine-readable errors.
The finding remains in SARIF. Validated model decisions use source `model`.
Provider errors and exhausted retries use source `execution_failure`, leave
`metisTriaged: false`, and emit `triage.finding_failed`. Reruns retry these findings.
The CLI saves partial annotations and reports failure; graph runs exit nonzero.
Missing evidence or unusable citations alone do not fail the command.
`MetisEngine.execute_triage()` raises `ExecutionGraphError` with partial SARIF in
`result.outputs["triage"]["sarif"]` on execution failure.
Existing document-backed threat-model scope exclusions retain their policy
behavior, are attributed with source `policy`, and preserve
`metisThreatModelPolicy`.

Citation validation applies to the built-in workflow; external classifiers use
their own response schemas.

## Analyzer support
- Packaged CodeGraph support currently covers C and C++ through their shared
  Tree-sitter provider. Other files follow the same triage workflow without
  graph evidence.
- Macro expansion and concurrency semantics are not standalone triage stages.
  A model may identify an unresolved macro, wrapper, or build gate and use
  available navigation tools to inspect it, but Metis does not currently claim
  a separate deterministic macro-expansion or concurrency-semantics analyzer.
