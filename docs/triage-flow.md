# Deterministic SARIF Triage Flow

Metis triage is deterministic orchestration, not an agent loop.

## End-to-end flow
1. Read SARIF findings.
2. Retrieve repository context from the vector index.
3. Collect deterministic evidence around the reported location:
   - Tree-sitter scope/symbol extraction (when supported for the file).
   - Line-local file windows and symbol probes with local tools (`sed`, `grep`).
   - C/C++ macro/include-aware expansion and definition lookup.
4. Build a bounded evidence pack.
5. Derive evidence obligations and coverage from collected sections/unresolved hops.
6. Ask the model for a structured decision:
   - `status`: `valid` | `invalid` | `inconclusive`
   - `reason`
   - `evidence` (`file:line`)
   - `resolution_chain`
   - `unresolved_hops`
7. Apply deterministic gating and adjudication, then annotate SARIF:
   - `metisTriaged`
   - `metisTriageStatus`
   - `metisTriageReason`
   - `metisTriageTimestamp`

```text
SARIF finding
    |
    v
Retrieve context (RAG)
    |
    v
Source-aware evidence collection
(Tree-sitter + line-local sed/grep + macro/include resolution)
    |
    v
Bounded evidence pack
    |
    v
Evidence obligations + coverage gate
    |
    v
LLM structured decision
    |
    v
Deterministic adjudication rules
    |
    v
SARIF annotations
```

## Evidence collection (primary path)
For supported languages, the analyzer parses the file and anchors analysis near the reported line.

Evidence is collected in this order:
1. Analyzer summary/citations/resolution chain/flow chain (if available).
2. File-local context via `sed`:
   - reported line
   - bounded nearby window
3. Tree-sitter scope symbols near/above the reported line.
4. Symbol definition probing with bounded `grep` in local/fallback paths.
5. Context windows around located hits via `sed`.
6. C/C++ only: macro definition/semantics collection and include-name resolution.

If parser initialization/parsing fails, triage still runs with deterministic text-tool evidence.

## Source-aware behavior (Metis SARIF vs external SARIF)
Metis accepts SARIF from Metis itself and from external tools.

- External SARIF:
  - prioritizes strict line-local evidence first.
  - uses narrower defaults.
- Metis SARIF:
  - can include Metis explanation text (`reasoning/why/mitigation`) as extra context.
  - uses slightly broader but still bounded local collection.

This keeps triage generic while allowing richer reuse of Metis-native hints when present.

## C/C++ macro/include resolution
For C/C++ files, triage adds macro-aware evidence:
- detects macro-like calls from Tree-sitter scope near the finding.
- resolves `#define` sites with bounded `grep`/`sed`.
- resolves include names through indexed name lookup when headers are not directly local.
- records semantic macro resolution in the evidence pack (for example mapping to `alloca`/assertion/assumption behavior).

Resolved macro semantics can neutralize corresponding unresolved-hop noise during adjudication.

## Evidence obligations and gate
Before the model decision is finalized, triage computes obligation coverage from evidence sections and unresolved hops.

If required obligations are missing, triage forces `inconclusive` via deterministic gate instead of accepting an overconfident status.

## Adjudication (deterministic guardrail)
Model output is not accepted blindly.

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
- C/C++ triage uses a dedicated Tree-sitter analyzer with richer semantic evidence collection (flow hops, guards, macro/include resolution).
- Python/JavaScript/TypeScript/Go/Rust/Ruby/PHP/Solidity triage uses a generic Tree-sitter analyzer (structural pass around the finding with lightweight flow hints), then deterministic tool probing.
- If parser initialization/parsing fails, triage remains operational with deterministic text-tool evidence.

Analysis terms:
- `Flow Analysis`: follows source/guard/sink hops with stronger definition/reference/call resolution, including cross-file and macro/include-aware evidence chaining.
- `Structural Analysis`: uses AST-local structure around the finding (enclosing blocks, call-like nodes, local checks) and relies more on deterministic tools for deeper cross-file evidence.
