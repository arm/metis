# Language plugins

Metis discovers language support from lightweight manifests. It imports a plugin
class only after a file path matches that language.

## File Layout

| Path | Purpose |
| --- | --- |
| `src/metis/plugins/config/global.yaml` | Shared prompts and documentation extensions for the docs/RAG index. |
| `src/metis/plugins/manifests/<language>.yaml` | Cheap language metadata used for startup discovery and path matching. |
| `src/metis/plugins/languages/<language>.yaml` | Per-language splitter settings and prompts. Loaded when the language is used. |
| `src/metis/plugins/profiles/*.yaml` | Optional shared language config merged into language YAML files. |

## Manifest

A manifest tells Metis how to recognize a language without importing the plugin.

```yaml
name: verilog
aliases:
- verilog
extensions:
- .v
- .vh
filename_patterns:
- .v.*
- .vh.*
config_resource: languages/verilog.yaml
capabilities: {}
priority: 0
```

Fields:

| Field | Required | Meaning |
| --- | --- | --- |
| `name` | yes | Stable language id. |
| `aliases` | no | Alternate lookup names. |
| `extensions` | no | Exact final file extensions used for path matching, such as `.py` or `.v`. |
| `source_extensions` | no | Extensions treated as source files by language-aware providers. Also list them in `extensions` for path matching. |
| `header_extensions` | no | Extensions treated as headers by language-aware providers. Also list them in `extensions` for path matching. |
| `filename_patterns` | no | Basename patterns for generated files, such as `.v.*`. |
| `implementation` | no | `module:ClassOrFactory` import path when custom runtime behavior is required. Built-ins otherwise use `ConfigBackedLanguagePlugin`. |
| `config_resource` | yes | Per-language YAML resource that defines or inherits prompts and splitter settings. |
| `capabilities` | no | Feature flags Metis can check without importing the plugin. |
| `prompt_profile` | no | Shared profile to merge before language-specific config. |
| `priority` | no | Tie-breaker for overlapping matches. Higher wins. |

## File Matching

Use `extensions` for real final extensions:

- `top.v` matches `.v`
- `defs.vh` matches `.vh`

Use `filename_patterns` when the language marker appears before another suffix:

- `top.v.pp` matches `.v.*`
- `defs.vh.generated` matches `.vh.*`

Keep exact extensions and filename patterns separate. A discoverable manifest
needs at least one entry across those matching fields. `source_extensions` and
`header_extensions` add file-role metadata; they do not replace `extensions`
for matching.

## Language YAML

The language YAML contains the heavier runtime settings: splitter parameters and
prompts.

```yaml
splitting:
  chunk_lines: 60
  chunk_lines_overlap: 20
  max_chars: 2500
prompts:
  security_review_file: |-
    ...
  security_review: |-
    ...
  security_review_checks: |-
    ...
  validation_review: |-
    ...
  snippet_security_summary: |-
    ...
```

Required prompt keys:

| Key | Used for |
| --- | --- |
| `security_review_file` | Single-file review. |
| `security_review` | Patch review. |
| `security_review_checks` | Review rubric. |
| `validation_review` | Candidate finding validation. |
| `snippet_security_summary` | Patch summary generation. |

## Global Config

`global.yaml` has two responsibilities:

- `docs.supported_extensions` controls which documentation files are indexed into
  the docs/RAG collection. These files are not reviewed as code.
- `general_prompts` contains shared prompt fragments used by review and triage.

## Add A Built-In Language

1. Add `src/metis/plugins/manifests/<language>.yaml`.
2. Add `src/metis/plugins/languages/<language>.yaml`.
3. Add a plugin class and `implementation` manifest field only when the language
   needs custom runtime behavior.
4. If the language supports CodeGraph analysis, implement its provider and
   deterministic semantics, then register both in the `MetisEngine`
   composition root under the manifest's language name.
5. Add the YAML resources to `pyproject.toml` package data if needed.
6. Add tests for manifest matching, lazy import, prompt loading, exact
   CodeGraph file coverage, persisted semantics, and unsupported-file fallback.

Built-in languages without custom runtime behavior omit `implementation` and use
the manifest name with `ConfigBackedLanguagePlugin`. Custom implementations can
subclass it and override the behavior they need.

## Add An External Language Plugin

Expose a cheap manifest through the `metis.language_plugins` entry point:

```toml
[project.entry-points."metis.language_plugins"]
java = "metis_java_plugin:manifest"
```

The entry point may return a `dict`, a `LanguagePluginManifest`, or a zero-argument
callable that returns either. It should not import the plugin class just to return
metadata.

Example:

```python
def manifest():
    return {
        "name": "java",
        "aliases": ["java"],
        "extensions": [".java"],
        "filename_patterns": [],
        "implementation": "metis_java_plugin:JavaPlugin",
        "config_resource": "metis_java_plugin:java.yaml",
        "capabilities": {"codegraph": True},
        "priority": 0,
    }
```

When the manifest enables CodeGraph construction, expose the matching provider factory in
the same distribution. The entry-point name must match the language manifest name:

```toml
[project.entry-points."metis.codegraph_providers"]
java = "metis_java_plugin:create_codegraph_provider"
```

```python
from metis.execution_nodes import CodeGraphProvider
from metis.execution_nodes import CodeGraphProviderContext


def create_codegraph_provider(
    context: CodeGraphProviderContext,
) -> CodeGraphProvider:
    return JavaCodeGraphProvider(context)
```

`CodeGraphProviderContext` provides
`get_language_name_for_path(path)` and
`has_language_file_role(path, role)`. The provider must return an internally
resolved `CodeGraphResult` for exactly the requested files. The reachability
algorithm consumes this language-neutral graph; the provider may use any
language-appropriate parser or analysis engine.

Languages that support advanced review also expose deterministic CodeGraph
semantics under the same language name:

```toml
[project.entry-points."metis.codegraph_semantics"]
java = "metis_java_plugin.semantics:JavaSemantics"
```

The semantics provider receives immutable symbol and call facts and returns
source/sink annotations. Metis persists those annotations in the canonical
CodeGraph under the scanned project's `.metis/` directory. Reachability is a
consumer of that contract and does not require a particular parser such as
tree-sitter.

The manifest only declares the capability. Provider and semantics implementation
details belong to the plugin package and are discovered through entry points,
not configured in YAML.

See the [CodeGraph provider and semantics contracts](execution-graph.md#codegraph-provider-contract)
for the validation and persistence requirements shared by built-in and external
languages.

## Replace A Language

Provide the replacement implementation explicitly:

```yaml
language_plugins:
  verilog:
    implementation: external_metis_verilog:VerilogPlugin
    config_resource: external_metis_verilog:verilog.yaml
```

Replacement is explicit. A third-party entry point does not override a built-in
only because it was discovered first.
