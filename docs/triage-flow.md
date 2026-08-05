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
2. Select Reachability triage when Reachability supports the reported file;
   otherwise use the simple LLM triage fallback.
3. Collect deterministic evidence around the reported location:
   - CodeGraph reachability context includes the target function, callers,
     callees, paths, related functions, and globals available from the graph.
   - The simple LLM fallback starts with line-local file windows and follows
     concrete symbols with `sed` and `grep`.
4. Build a bounded evidence pack.
5. Derive evidence obligations and coverage where the selected path provides
   them.
6. Ask the model for a structured decision:
   - `status`: `valid` | `invalid` | `inconclusive`
   - `reason`
   - `evidence` (`file:line`)
   - `resolution_chain`
   - `unresolved_hops`
7. Apply the selected path's validation and fallback rules, then annotate SARIF:
   - `metisTriaged`
   - `metisTriageStatus`
   - `metisTriageReason`
   - `metisTriageTimestamp`
   - conditional `metisEvidenceRequirements` (list),
     `metisEvidenceCoverage` (mapping), `metisMissingEvidence` (list), and
     `metisThreatModelPolicy` (mapping) when the selected triage path produces
     them

```text
SARIF finding
    |
    v
Source-aware evidence collection
(CodeGraph reachability or line-local sed/grep)
    |
    v
Bounded evidence pack
    |
    v
Path-specific evidence validation
    |
    v
LLM structured decision
    |
    v
Simple-LLM adjudication or Reachability decision
    |
    v
SARIF annotations
```

## Evidence collection

For files supported by Reachability, Metis loads the language-neutral CodeGraph
produced by the matching provider, applies the matching deterministic semantics,
then anchors the finding to a nearby function. The evidence contains the
reported line, target function, direct graph relationships, available incoming
and outgoing paths, related functions, and relevant globals. The model can use
the engine's model-callable tools to resolve concrete gaps.

The simple LLM triage route, whether selected directly or used as the
Reachability fallback, collects:

1. File-local context via `sed`:
   - reported line
   - bounded nearby window
2. Concrete symbol candidates from the finding, snippet, explanation, and
   reported-line context.
3. Symbol definition and use-site probes with bounded `grep`.
4. Context windows around located hits via `sed`.

Language plugins can add navigation guidance to the simple LLM route, but it
does not claim CodeGraph-backed analysis when Reachability is unavailable for
the reported file. Metis uses this text-evidence fallback instead.

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
The simple LLM triage node computes obligation coverage from its collected
sections and unresolved symbol hops before the model decision is finalized.

If required obligations are missing, triage forces `inconclusive` via deterministic gate instead of accepting an overconfident status.

## Adjudication (deterministic guardrail)
The simple LLM triage node does not accept model output blindly.

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
- Reachability triage applies when a language has matching manifest, CodeGraph
  provider, and deterministic semantics support.
- Packaged Reachability support currently covers C and C++; their shared
  CodeGraph provider uses Tree-sitter internally.
- Unsupported files use the plugin-guided `simple_llm_triage` fallback and
  deterministic text-tool evidence.
- Macro expansion and concurrency semantics are not standalone triage stages.
  A model may identify an unresolved macro, wrapper, or build gate and use
  available navigation tools to inspect it, but Metis does not currently claim
  a separate deterministic macro-expansion or concurrency-semantics analyzer.
