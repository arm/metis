# Deterministic SARIF Triage Flow

Metis triage is deterministic orchestration, not an agent loop.

## End-to-end flow
1. Read SARIF findings.
2. Retrieve repository context from the vector index.
3. Run language analyzer evidence collection (Tree-sitter for supported languages).
4. Always add a deterministic local-tool baseline (`sed`, `cat`, `grep`, `find`) to avoid missing cross-file evidence.
5. Build a bounded evidence pack.
6. Ask the model for a structured decision:
   - `status`: `valid` | `invalid` | `inconclusive`
   - `reason`
   - `evidence` (`file:line`)
   - `resolution_chain`
   - `unresolved_hops`
7. Apply deterministic adjudication and annotate SARIF:
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
Tree-sitter analyzer
    |
    +-----------------------------+
    |                             |
    v                             v
Deterministic tool baseline   Targeted recovery (if unresolved/fallback targets)
(sed/cat/grep/find)           (focused grep/sed around symbols/paths)
    |                             |
    |                             +--> expands to repo-wide scope for cross-boundary unresolved hops
    |                             |
    +--------------+--------------+
                   |
                   v
            Bounded evidence pack
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

## Tree-sitter evidence (primary path)
For supported languages, the analyzer parses the full file and anchors analysis near the reported line.

It extracts structural evidence such as:
- Enclosing function/block around the finding.
- Definitions, references, and calls near the anchor.
- Guard/precondition nodes and flow hops (bounded up/down traversal).
- Macro and cross-file symbol resolution attempts.
- Structured citations and unresolved hops.

## Why local tools still run
Tree-sitter is precise but bounded. It can miss evidence outside current AST hops (for example: dispatcher/caller paths, macro chains across headers, build-specific paths, assembly labels, or far cross-file references).

Local tools provide broad deterministic recovery:
- `sed`: fixed line windows (`line-40..line+40`, exact line, and small windows around hits).
- `cat`: file head/full text slices to expose includes/macros/definitions.
- `grep`: repo-wide lexical lookup for symbols/patterns.
- `find`: resolve referenced files by name.

In practice this is a hybrid flow: AST structure first, then text-tool recovery for completeness.

When unresolved hops indicate cross-module boundaries (for example unresolved external call/definition chains), targeted recovery automatically broadens from local paths to repository scope in a bounded way.

## Adjudication (deterministic guardrail)
Model output is not accepted blindly.

Deterministic rules then decide the final status:
- Contradiction signals can force `invalid`.
- Critical unresolved hops force `inconclusive`.
- Strong evidence + clear resolution chain can remain `valid` even if non-critical uncertainty text appears.

This prevents overconfident status flips while avoiding unnecessary `inconclusive` outcomes when evidence is complete.

## Scope note
This flow is focused on static triage decisions for SARIF findings.

## Analyzer support
- C/C++ triage uses a dedicated Tree-sitter analyzer with richer semantic evidence collection (flow hops, guards, macro/include resolution, and stronger cross-file recovery targets).
- Python/JavaScript/TypeScript/Go/Rust/Ruby/PHP/Solidity triage uses a generic Tree-sitter analyzer (structural pass around the finding with lightweight flow hints), then deterministic tool recovery.
- If parser initialization/parsing fails, triage remains operational with deterministic text-tool evidence collection.

Analysis terms:
- `Flow Analysis`: follows source/guard/sink hops with stronger definition/reference/call resolution, including cross-file and macro/include-aware evidence chaining.
- `Structural Analysis`: uses AST-local structure around the finding (enclosing blocks, call-like nodes, local checks) and relies more on deterministic tools for deeper cross-file evidence.
