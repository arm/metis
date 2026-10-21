# SARIF Triage Flow

Triage accepts SARIF from Metis or other tools and annotates existing findings;
it does not discover new findings. The packaged graph supplies Review's SARIF.
A triage-only run uses existing SARIF without running Review.

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
   - optional `metisTriageDecisionSource` (`model`, `validation_failure`, or
     `policy`) and `metisTriageValidationErrors` (list)

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

Unusable citations or an unparseable response produce `inconclusive` with
`metisTriageDecisionSource: validation_failure` and machine-readable errors.
The finding remains in SARIF. Validated model decisions use source `model`.
Existing document-backed threat-model scope exclusions retain their policy
behavior, are attributed with source `policy`, and preserve
`metisThreatModelPolicy`.

Legacy evidence-coverage properties and external classifier schemas remain
compatible. Existing status names, finding identities, and CLI exit behavior
are unchanged; the stronger citation checks apply only to the built-in workflow.

## Analyzer support
- Packaged CodeGraph support currently covers C and C++ through their shared
  Tree-sitter provider. Other files follow the same triage workflow without
  graph evidence.
- Macro expansion and concurrency semantics are not standalone triage stages.
  A model may identify an unresolved macro, wrapper, or build gate and use
  available navigation tools to inspect it, but Metis does not currently claim
  a separate deterministic macro-expansion or concurrency-semantics analyzer.
