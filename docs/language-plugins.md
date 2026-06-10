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
implementation: metis.plugins.verilog_plugin:VerilogPlugin
config_resource: languages/verilog.yaml
capabilities:
  reachability_review: false
priority: 0
```

Fields:

| Field | Required | Meaning |
| --- | --- | --- |
| `name` | yes | Stable language id. |
| `aliases` | no | Alternate lookup names. |
| `extensions` | yes | Exact final file extensions, such as `.py` or `.v`. |
| `filename_patterns` | no | Basename patterns for generated files, such as `.v.*`. |
| `implementation` | yes | `module:ClassOrFactory` import path for the plugin. |
| `config_resource` | yes | Per-language YAML resource. |
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

Keep both lists separate. Exact extensions are simple language ownership. Filename
patterns are only for generated or transformed files whose final extension is not
the language.

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
3. Add a plugin class under `src/metis/plugins/`.
4. Add the YAML resources to `pyproject.toml` package data if needed.
5. Add tests that cover manifest matching, lazy import, and prompt loading.

The plugin class can usually subclass `ConfigBackedLanguagePlugin`:

```python
from metis.plugins.base import ConfigBackedLanguagePlugin


class JavaPlugin(ConfigBackedLanguagePlugin):
    NAME = "java"
```

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
        "capabilities": {},
        "priority": 0,
    }
```

## Replace A Language

Provide the replacement implementation explicitly:

```yaml
language_plugins:
  verilog:
    implementation: vendor_metis_verilog:VerilogPlugin
    config_resource: vendor_metis_verilog:verilog.yaml
```

Replacement is explicit. A third-party entry point does not override a built-in
only because it was discovered first.
