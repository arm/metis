# SARIF Triage Flow

The Triage stage is a fixed workflow boundary whose selected nodes come from
YAML. During a run, model calls may use a bounded number of navigation-tool
rounds, but the model cannot change those nodes or their ordering.

The stage contract is SARIF in and SARIF out. In the packaged graph, Review
publishes SARIF to the Triage stage. A standalone `triage` command supplies
Metis or third-party SARIF directly, so Review does not run. File loading,
checkpoint persistence, and output-path selection remain at the CLI boundary.

## End-to-end flow
1. Read SARIF findings.
2. Attach compact CodeGraph context when the optional graph covers the reported
   file.
3. Collect evidence around the reported location with navigation tools,
   starting with line-local context and following concrete symbol definitions
   and use sites.
4. Build a bounded evidence pack.
5. Record the source lines actually supplied to the model, after output limits.
6. Ask the model for a structured decision:
   - `status`: `valid` | `invalid` | `inconclusive`
   - `reason`
   - `evidence` (`file:line`)
   - `resolution_chain`
   - `unresolved_hops`
7. Validate the structured response and its source citations, then annotate SARIF:
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

```text
SARIF finding
    |
    v
Source-aware evidence collection
(optional CodeGraph context plus navigation evidence)
    |
    v
Bounded evidence pack
    |
    v
LLM structured decision
    |
    v
Structured response and source-citation validation
    |
    v
SARIF annotations
```

## Evidence collection

The triage workflow collects:

1. File-local context via `sed`:
   - reported line
   - bounded nearby window
2. Concrete symbol candidates from the finding, snippet, explanation, and
   reported-line context.
3. Symbol definition and use-site probes with bounded `grep`.
4. Context windows around located hits via `sed`.

Language plugins can add navigation guidance. When the optional CodeGraph
covers the finding, the evidence pack also includes the containing function,
its direct callers and callees, unresolved calls, and available entrypoint,
source, and sink annotations. The same workflow runs without that section when
the graph does not cover the file.

## Source-aware behavior (Metis SARIF vs external SARIF)
Metis accepts SARIF from Metis itself and from external tools.

- External SARIF:
  - prioritizes strict line-local evidence first.
  - uses narrower defaults.
- Metis SARIF:
  - can include Metis explanation text (`reasoning/why/mitigation`) as extra context.
  - uses slightly broader but still bounded local collection.

This keeps triage generic while allowing richer reuse of Metis-native hints when present.

## Model decisions and source validation

The model decides whether source evidence supports the finding (`valid`),
refutes it (`invalid`), or cannot settle it (`inconclusive`). Python does not
change that judgment based on words in the explanation, unresolved-hop labels,
macro-resolution text, or counts of evidence sections.

Both decisive statuses require citations and a resolution chain in the built-in
workflow. Citations use `file:line` or `file:start-end`. They must refer to source
lines actually displayed in the initial evidence or successful navigation-tool
results for that finding, remain inside the codebase, and match current source.
These checks verify provenance, not the semantic truth of the model's reasoning.
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

## Scope note
This flow is focused on static triage decisions for SARIF findings.

## Analyzer support
- Triage always uses plugin-guided navigation evidence.
- When the optional CodeGraph covers a finding, triage also receives its
  deterministic function and call relationships.
- Packaged CodeGraph support currently covers C and C++ through their shared
  Tree-sitter provider. Other files follow the same triage workflow without
  graph evidence.
- Macro expansion and concurrency semantics are not standalone triage stages.
  A model may identify an unresolved macro, wrapper, or build gate and use
  available navigation tools to inspect it, but Metis does not currently claim
  a separate deterministic macro-expansion or concurrency-semantics analyzer.
