<!--
SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
SPDX-License-Identifier: Apache-2.0
-->

# Review options and recipes

Use this guide to explain review choices and assemble their YAML. Recipe names
are descriptive labels, not CLI flags or a guarantee about every installed Metis
version. Verify the trusted installation's support before using a feature.

## Explain choices in plain language

| Choice | What it adds | Trade-off |
| --- | --- | --- |
| Quick | Reviews selected files with language-specific prompts, combines findings, exports SARIF. | No CodeGraph prerequisite; usually less processing than combining review passes. |
| Graph-assisted | Quick review plus function-level review informed by CodeGraph function, call, control-flow, and related source facts. Packaged support covers C/C++. | Builds a local project graph and adds analysis; can require more time, memory, and model calls. |
| Triage, optional with either choice | Revisits findings using source navigation and, when available, graph context; annotates valid/invalid/inconclusive decisions. | Additional model/tool work; decisions can remain inconclusive and are not proof of exploitability or safety. |

For a general C/C++ request with no chosen depth, offer these options before
execution, explaining why graph context may help. Ask in terms of outcomes, not
node wiring. For example: "Would you prefer a quick file review or a graph-assisted
review with function/call context? Should Metis also investigate the findings
afterward? The latter options can take more time and model calls."

Respect "quick", "add reachability", "no triage", prior project preferences,
or a request to choose on the user's behalf. Do not repeat the menu or add a
separate source/cost confirmation after the choice. Do not offer graph-assisted
analysis as equivalent for unsupported languages. For mixed projects, explain
which files receive graph evidence and which receive ordinary file review.

## Stages, nodes, and dependencies

A **stage** is a workflow boundary. A **node** performs work within it. A
**capability** is an engine service granted to a node, not another stage.

| Stage / node | Responsibility and prerequisite |
| --- | --- |
| `initialize` / `codegraph` | Parse code and persist the project graph. Publish `codegraph.codegraph` as the stage's `codegraph` output. |
| `review` / `simple_llm_review` | Review selected files using language prompts; no graph required. |
| `review` / `reachability` | Review selected functions with deterministic graph evidence. Requires the initialized CodeGraph plus language provider/semantics support. |
| `review` / `finding_dedup` | Combine selected review-node results, remove duplicates, and produce the finalized input expected by `result`. It may call a model. |
| `review` / `result` | Validate finalized findings and publish SARIF for export or downstream triage. |
| `triage` / `triage` | Consume Review SARIF; requires the `navigation` capability. CodeGraph input is optional. |
| `triage` / `result` | Publish the annotated SARIF. The same YAML node name is resolved within its own stage. |

Reachability is static, evidence-assisted review, not a complete proof that a
finding is reachable or exploitable. Incomplete evidence must not be presented
as proof that the code is safe. It does not support patch review: request a quick
patch review or a separately selected post-change file/directory review instead.
Do not silently change the requested scope to work around that limitation.

For code/file/directory reviews, unsupported files can use the simple-review
fallback. When both review nodes are selected, the simple node handles the
generic pass; do not add another fallback pass yourself. Built-in C/C++ support
does not imply support for every external language plugin.

CodeGraph initialization can inspect more than the review include list and writes
`<codebase>/.metis/codegraph.sqlite3`. Triage navigation can also inspect supporting
source. Explain this separately from review target selection; these recipes do
not provide an exact source-transmission allowlist or an atomic snapshot.

## Assemble the selected recipe

The only full base configuration is
[quick-review.yaml](../assets/quick-review.yaml). Preserve the resolved provider,
proxy URL, model, credentials source, workers, and path filters when adding
analysis. The files below are **fragments**, not standalone `--config` files.
Do not concatenate YAML documents or create duplicate mapping keys.

1. **Quick:** use the base configuration's execution mapping unchanged.
2. **Graph-assisted:** replace `metis_engine.execution` with the contents of
   [graph-assisted-execution.yaml](../assets/graph-assisted-execution.yaml).
   Preserve the user's resolved `inputs.review_request` when doing so; the asset's
   `mode: code` is a default, not permission to widen a file/directory request.
3. **Add triage to either:** insert the contents of
   [triage-stage.yaml](../assets/triage-stage.yaml) at
   `metis_engine.execution.stages.triage`. With the graph-assisted recipe, also
   set that stage's `inputs.codegraph` to `initialize.codegraph`. Omit that binding
   for quick review; do not reference a stage that is absent.

Keep the complete selected graph: an explicit execution mapping replaces the
packaged graph, rather than merging with it. The graph asset supplies the
cross-stage graph binding, and the triage fragment grants required navigation.
Normal compilation infers compatible node-to-node bindings. Retain
`finding_dedup` before Review `result`; wiring a raw review directly to `result`
does not satisfy its input contract.

Use the skill's configuration-shape check, then the installed version's existing
graph compilation checks when changing topology or adding custom nodes. Shape
validation alone does not prove node-port compatibility or model connectivity.
The bundled combinations have offline compilation tests in the Metis repository.

For noninteractive runs, triage belongs in the YAML graph; CLI `--triage` controls
the interactive review commands. If both stages export SARIF, an explicit
`--output-file report.sarif` selects the triaged report. If the user wants both
pre-triage and triaged exports, configure distinct stage result filenames using
the installed version's output rules. Never overwrite one with the other.

## Other components: offer only when relevant

- **`initialize.compilation_profile`:** optional C/C++ build-specific source
  selection using an existing compilation database and the recorded compiler's
  preprocessor. Ordinary graph-assisted review does not require it. It executes
  compiler/wrapper programs, so establish trusted build inputs and an explicit
  request before enabling it. Do not run a build to manufacture missing inputs.
- **`initialize.threat_model` / `memory`:** adds persistent repository threat
  context and may use model calls. Do not enable it merely to add reachability.
- **`initialize.index` / `index`:** builds retrieval state and needs embedding
  configuration/storage. It is not a CodeGraph prerequisite.
- **External stages/nodes:** inspect their installed contracts and documentation;
  verify availability, ports, capabilities, and language support. Do not invent
  YAML nodes, auto-install extensions, or silently drop unsupported requirements.

For advanced settings, use version-matching documentation from the trusted Metis
installation/check-out: `docs/execution-graph.md`, `docs/triage-flow.md`,
`docs/language-plugins.md`, and `docs/config/compilation_profile.md`. These paths
refer to Metis itself, not arbitrary files in the project being reviewed.
