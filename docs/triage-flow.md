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
5. Derive evidence obligations and coverage from the collected sections.
6. Ask the model for a structured decision:
   - `status`: `valid` | `invalid` | `inconclusive`
   - `reason`
   - `evidence` (`file:line`)
   - `resolution_chain`
   - `unresolved_hops`
7. Apply deterministic validation rules, then annotate SARIF:
   - `metisTriaged`
   - `metisTriageStatus`
   - `metisTriageReason`
   - `metisTriageTimestamp`
   - conditional `metisEvidenceRequirements` (list),
     `metisEvidenceCoverage` (mapping), `metisMissingEvidence` (list), and
     `metisThreatModelPolicy` (mapping) when available

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
Deterministic validation and triage adjudication
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

## Evidence obligations and gate
The triage node computes obligation coverage from its collected
sections and unresolved symbol hops before the model decision is finalized.

If required obligations are missing, triage forces `inconclusive` via deterministic gate instead of accepting an overconfident status.

## Adjudication (deterministic guardrail)
The triage node does not accept model output blindly.

Deterministic rules then decide the final status:
- Contradiction signals can force `invalid`.
- Critical unresolved hops force `inconclusive`.
- Strong evidence + clear resolution chain can remain `valid` when uncertainty is non-critical.
- Invalid-to-valid direct upgrades are blocked by invariant checks.
- Status-specific obligation checks can downgrade `valid`/`invalid` to `inconclusive` when coverage is insufficient.

This prevents overconfident status flips while avoiding unnecessary `inconclusive` outcomes when evidence is complete.

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
