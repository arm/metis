# Tree-Sitter Tool Contract

The `tree_sitter` tool is planned scaffolding for structural source analysis.

Planned capabilities:

- `tree_sitter.scope`: identify enclosing syntactic scope and local symbols
  around a file location.
- `tree_sitter.query`: run a bounded tree-sitter query against supported files.

Model interpretation rules:

- Tree-sitter output is syntactic evidence, not semantic proof.
- An enclosing scope does not prove dataflow or reachability by itself.
- Captured identifiers are candidates for follow-up resolution.
- Query matches should be paired with source windows or graph evidence before
  they become finding evidence.

Initial implementation should expose tree-sitter as an orchestration/context
provider first. Add model-callable query support only after input bounds, output
schemas, and query safety are stable.
