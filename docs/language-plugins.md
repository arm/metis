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
Metis tries exact final-extension matches before filename patterns. Within the
applicable group, higher `priority` wins and equal-priority cross-language
matches are ambiguous.

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
| `validation_review` | Reserved compatibility prompt; currently not consumed at runtime. |
| `snippet_security_summary` | Patch summary generation. |

`prompts.triage_navigation` is optional and overrides the navigation-assisted
triage prompt. A language YAML may use `inherits: <profile>`; the manifest's
`prompt_profile` supplies the profile when the YAML does not name one.

## Global Config

`global.yaml` has two responsibilities:

- `docs.supported_extensions` controls which documentation files are indexed into
  the docs/RAG collection. These files are not reviewed as code.
- `general_prompts` contains shared prompt fragments used by review and triage.

## Add A Built-In Language

1. Add `src/metis/plugins/manifests/<language>.yaml`.
2. Add `src/metis/plugins/languages/<language>.yaml`.
3. Add a plugin class and `implementation` manifest field only when the language
   needs custom runtime behavior. The config-backed default passes the manifest
   name to `tree_sitter_language_pack`; when that is not the installed grammar
   key, follow `src/metis/plugins/systemverilog_plugin.py` and override
   `get_splitter()` with `build_code_splitter(...)`. This splitter serves Index
   chunking, not CodeGraph parsing.
4. For CodeGraph construction, set `capabilities.codegraph: true`, implement the
   provider, and register its factory in `MetisEngine` under the manifest name.
   Add same-named deterministic semantics to the composition root only for
   Reachability support.
5. Existing package-data globs cover the standard manifest, language, and profile
   locations. Update `pyproject.toml` only for assets outside those globs.
6. Extend path, required-prompt, and splitter cases in
   `tests/test_language_plugin_registry.py` and `tests/test_plugins.py`; add
   lazy-import coverage only for a custom implementation. For CodeGraph, also
   test exact file coverage, profiled source views, failure diagnostics, and
   fallback; test deterministic persisted semantics only when Reachability is
   supported.
7. Update the supported-language table in `README.md` and any language-specific
   claims affected by CodeGraph or triage support.

Built-in languages without custom runtime behavior omit `implementation` and use
the manifest name with `ConfigBackedLanguagePlugin`. Custom implementations can
subclass it and override the behavior they need.

## Add An External Language Plugin

Expose a cheap manifest through the `metis.language_plugins` entry point:

```toml
[project.entry-points."metis.language_plugins"]
examplelang = "metis_examplelang_plugin:manifest"
```

The entry point may return a `dict`, a `LanguagePluginManifest`, or a zero-argument
callable that returns either. It should not import the plugin class just to return
metadata.

Example:

```python
def manifest():
    return {
        "name": "examplelang",
        "aliases": ["examplelang"],
        "extensions": [".example"],
        "filename_patterns": [],
        "config_resource": "metis_examplelang_plugin:examplelang.yaml",
        "capabilities": {"codegraph": True},
        "priority": 0,
    }
```

The manifest entry-point module is imported during registry discovery, so keep
it lightweight; only the implementation class remains lazy. Package the
referenced YAML/profile resources and verify them from the built wheel.

When the manifest enables CodeGraph construction, a matching provider entry
point must be installed in the same or another distribution. Its name must match
the language manifest:

```toml
[project.entry-points."metis.codegraph_providers"]
examplelang = "metis_examplelang_plugin:create_codegraph_provider"
```

```python
from metis.execution_nodes import CodeGraphProvider
from metis.execution_nodes import CodeGraphProviderContext


def create_codegraph_provider(
    context: CodeGraphProviderContext,
) -> CodeGraphProvider:
    return ExampleLanguageCodeGraphProvider(context)
```

`CodeGraphProviderContext` provides
`get_language_name_for_path(path)` and
`has_language_file_role(path, role)`, plus optional `source_for_path(path)`.
When source bytes are returned, including `b""`, parse them instead of reading
the filesystem so compilation-profile views are preserved. The provider must
return an internally resolved `CodeGraphResult` for exactly the requested files.

Reachability requires deterministic CodeGraph semantics. External languages
that support it expose semantics under the same language name:

```toml
[project.entry-points."metis.codegraph_semantics"]
examplelang = "metis_examplelang_plugin.semantics:ExampleLanguageSemantics"
```

The semantics provider receives immutable symbol and call facts and returns
source/sink annotations. Metis persists those annotations in the canonical
CodeGraph under the scanned project's `.metis/` directory. Reachability is a
consumer of that contract and does not require a particular parser such as
tree-sitter.

The manifest only declares the capability. Provider and semantics implementation
details belong to the plugin package and are discovered through entry points,
not configured in YAML.
Provider or semantics behavior changes must bump the distribution version
because that identity participates in persisted CodeGraph fingerprints.

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
