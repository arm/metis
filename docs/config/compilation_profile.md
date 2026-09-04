# Build-profiled C/C++ analysis

By default, the Initialize `codegraph` node runs Tree-sitter on the checked-out
source. Add the optional `compilation_profile` node to limit C/C++ analysis to
the files and conditional branches used by a compilation database.

`compile_commands.json` records how each source file is built: its compiler,
working directory, include paths, and build flags. Metis reads this existing
file; it does not create a new database.

`compilation_profile` runs the compiler recorded by each C/C++
`compile_commands.json` entry in preprocessing mode. It records included files
and active source lines, then installs a source view with inactive lines blanked.
The `codegraph` node still uses the normal C/C++ Tree-sitter provider. Metis does
not build the project, fully expand macros for parsing, or consume a compiler
AST.

## Configuration

Run `compilation_profile` before `codegraph` in Initialize. This example
replaces the packaged execution graph and omits Triage.

```yaml
metis_engine:
  execution:
    inputs:
      review_request: {mode: code}
    stages:
      initialize:
        outputs:
          threat_model: threat_model.threat_model
          codegraph: codegraph.codegraph
        nodes:
          threat_model: {capabilities: [memory]}
          compilation_profile:
            max_concurrency: 16
          codegraph:
            depends_on: [compilation_profile]
      review:
        inputs:
          codegraph: initialize.codegraph
        nodes:
          simple_llm_review: {capabilities: [memory]}
          reachability: {capabilities: [memory]}
          finding_dedup: {}
          result: {formats: [sarif]}
    node_configuration:
      initialize:
        compilation_profile:
          compile_commands_path: build/compile_commands.json
          timeout_seconds: 60
```

The explicit dependency guarantees that the source profile is installed before
Tree-sitter reads any source. `node_configuration` holds node settings; it is
not another stage.

Set `max_concurrency` on the `compilation_profile` node to choose how many
compiler processes may run at once. It cannot exceed `metis_engine.max_workers`.
Omit it to use that global limit. There is no additional limit in the profiler.

For ordinary Tree-sitter analysis, remove `compilation_profile`, its
configuration, and the `codegraph.depends_on` entry. Keep `codegraph` for
Reachability; a Simple Review-only graph does not require it.

## Data flow

```text
compile_commands.json (optional)
        |
recorded compiler preprocessor
        |
active-line source view
        |
Tree-sitter codegraph
        |
persisted CodeGraphReference
        |
Review and Reachability
```

Without a compilation database, the flow starts at `Tree-sitter codegraph`.

## Compiler and source contract

- Metis executes the compiler command recorded in each database entry. It does
  not replace GCC with Clang or another compiler.
- Treat the compilation database and every recorded compiler or wrapper as
  trusted build input: enabling this node executes those programs.
- The current preprocessing invocation requires a GCC-compatible driver, such
  as GCC, Clang, or an Arm GNU cross-compiler. Compilers with different command
  interfaces are not supported by this node.
- A relative `compile_commands_path` resolves from the codebase root. Each
  entry's `directory` remains its working directory.
- Metis prefers the `arguments` array when an entry provides both `arguments`
  and a quoted `command` string. Compiler options and their values stay together;
  build-output and dependency-output options are removed for preprocessing.
- Forwarded `-Wp,...` arguments are supported only for the dependency-only
  forms `-Wp,-MD,file` and `-Wp,-MMD,file`. Use separate compiler flags for other
  groups. Unsupported groups are rejected without executing the command.
- GCC's `-fpch-preprocess` mode is rejected because it can omit precompiled
  header source from the preprocessing output. Remove this flag so included
  headers are processed from source.
- Compiler, source, included-header, generated-header, and sysroot paths must
  exist in the runtime environment. Object files and linked outputs are not
  required.
- Only C/C++ entries are executed; only files under the codebase are stored in
  the profile. Other-language entries are ignored.
- Inactive source bytes are replaced with spaces while line endings and byte
  positions remain unchanged. Tree-sitter and finding anchors therefore keep
  using original-source coordinates.
- Source files and included headers must use LF or CRLF line endings. Bare
  carriage returns are rejected because compilers and Tree-sitter count them
  differently, which would otherwise select the wrong source lines.
- A file with different active lines in different translation units is omitted
  from CodeGraph rather than choosing one build variant. Simple Review still
  reviews its original source.
- Invalid databases, unsupported arguments, preprocessing failures, source
  `#line` directives, and source changes detected while building the graph stop
  initialization. Later source changes are rejected when the file is read for
  review.

Finish builds and header generation before starting Initialize, and keep the
source files unchanged while it runs. Preprocessing and reading the source files
are separate operations; the profile is not an atomic filesystem snapshot.

The effective source profile is part of the persisted graph fingerprint.
Changing its raw or active source view rebuilds the graph.
Edits to files excluded from the profile do not invalidate the graph. Changes
to the selected file set still invalidate it so stored file coverage stays current.
Source views are run-local: a later run rebuilds the profile before reusing its
persisted graph revision.
