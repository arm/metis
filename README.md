# Metis: AI-Powered Security Code Review

[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white)](https://pre-commit.com/)
[![Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Python](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://python.org)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/arm/metis/badge)](https://securityscorecards.dev/viewer/?uri=github.com/arm/metis)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/10876/badge)](https://www.bestpractices.dev/projects/10876)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache2.0-yellow.svg)](LICENSE)

![Logo](.github/logo-light.png#gh-light-mode-only)
![Logo](.github/logo-dark.png#gh-dark-mode-only)

Metis is an open-source, agentic AI security framework for deep security code review, created by [Arm's Product Security Team](https://www.arm.com/products/product-security). It helps engineers detect subtle vulnerabilities, improve secure coding practices, and reduce review fatigue. This is especially valuable in large, complex, or legacy codebases where traditional tooling often falls short.

**Metis** is named after the Greek goddess of wisdom, deep thought and counsel.

## Features

- **Deep Reasoning**
  Unlike linters or traditional static analysis tools, Metis doesn’t rely on hardcoded rules. It uses LLMs capable of semantic understanding and reasoning.

- **Deterministic Local Evidence**
  Reviews and triage emphasize source-local analysis, language plugins, and deterministic evidence collection over broad retrieval.

- **Plugin-Friendly and Extensible**
  Designed with extensibility in mind: support for additional languages, models, and new prompts is straightforward.

- **Issue validation**
  Validates findings from its own analysis and third-party SAST tools, gathering evidence to reduce false positives.

- **Provider Flexibility**
  Support for major LLM services and local models (OpenAI, Azure OpenAI, Anthropic, Gemini, AWS Bedrock, Bedrock Mantle, vLLM, Ollama, llama.cpp, LiteLLM etc.). See [Set up LLM Provider](#2-set-up-llm-provider).

![Demo](.github/demo.gif)


### Supported Languages

Metis includes support for the following languages:

| Language | Review | Triage | Notes |
| --- | --- | --- | --- |
| C | Simple LLM and CodeGraph Reachability | Navigation-assisted LLM with CodeGraph context | Tree-sitter-backed CodeGraph |
| C++ | Simple LLM and CodeGraph Reachability | Navigation-assisted LLM with CodeGraph context | Tree-sitter-backed CodeGraph |
| Java | Language-plugin simple LLM review | Navigation-assisted LLM | Tree-sitter code splitting |
| C# | Language-plugin simple LLM review | Navigation-assisted LLM | Tree-sitter code splitting |
| Python | Language-plugin simple LLM review | Navigation-assisted LLM | Tree-sitter code splitting |
| Ruby | Language-plugin simple LLM review | Navigation-assisted LLM | Tree-sitter code splitting |
| Rust | Language-plugin simple LLM review | Navigation-assisted LLM | Tree-sitter code splitting |
| Solidity | Language-plugin simple LLM review | Navigation-assisted LLM | Tree-sitter code splitting |
| TypeScript | Language-plugin simple LLM review | Navigation-assisted LLM | Tree-sitter code splitting |
| Terraform | Language-plugin simple LLM review | Navigation-assisted LLM | Tree-sitter code splitting |
| Go | Language-plugin simple LLM review | Navigation-assisted LLM | Tree-sitter code splitting |
| TableGen | Language-plugin simple LLM review | Navigation-assisted LLM | Tree-sitter code splitting |
| Verilog | Language-plugin simple LLM review | Navigation-assisted LLM | Tree-sitter code splitting |
| SystemVerilog | Language-plugin simple LLM review | Navigation-assisted LLM | Verilog Tree-sitter code splitting |
| JavaScript | Language-plugin simple LLM review | Navigation-assisted LLM | Tree-sitter code splitting |
| Kotlin | Language-plugin simple LLM review | Navigation-assisted LLM | Tree-sitter code splitting |
| Perl | Language-plugin simple LLM review | Navigation-assisted LLM | Tree-sitter code splitting |
| PHP | Language-plugin simple LLM review | Navigation-assisted LLM | Tree-sitter code splitting |
| AArch64 Assembly | Language-plugin simple LLM review | Navigation-assisted LLM | Tree-sitter code splitting |
| Jupyter Notebook | Language-plugin simple LLM review | Navigation-assisted LLM | Python Tree-sitter code splitting |

For the current review graph and SARIF triage flow, see
[docs/execution-graph.md](docs/execution-graph.md) and
[docs/triage-flow.md](docs/triage-flow.md).
Optional compilation-database filtering for C/C++ review is documented in
[docs/config/compilation_profile.md](docs/config/compilation_profile.md).

Metis uses a plugin-based language system, making it easy to extend support to additional languages.

It supports ChromaDB, PostgreSQL with pgvector, and Qdrant vector-store backends.

## Getting Started

By default, Metis uses **ChromaDB** for local, no-setup usage. PostgreSQL with pgvector and Qdrant are available as optional backends.

### 1. **Installation**

After cloning the repository, you can either create a virtual environment or install dependencies system-wide.

To use a virtual environment (recommended):

```bash
uv venv
uv pip install .
```

or install system wide using --system:

```bash
uv pip install . --system
```

To install with **PostgreSQL (pgvector)** backend support:

```bash
uv pip install '.[postgres]'
```

To install with Qdrant backend support:

```bash
uv pip install '.[qdrant]'
```

### 1.1 **Docker**

```bash
git clone https://github.com/arm/metis.git

cd metis

docker build -t metis .
```

### 2. **Set up LLM Provider**

**OpenAI** (default)

Export your OpenAI API key before using Metis:

```bash
export OPENAI_API_KEY="your-key-here"
```

**Other providers**

Set `llm_provider.name` in `metis.yaml` and install the matching extra:

| Provider                 | `name`           | Install                              | Guide                                       |
|--------------------------|------------------|--------------------------------------|---------------------------------------------|
| OpenAI / Azure OpenAI    | `openai` / `azure_openai` | included                    | —                                           |
| Anthropic                | `anthropic`      | `uv pip install '.[anthropic]'`      | [docs](docs/providers/anthropic.md)         |
| Google Gemini / Vertex   | `gemini`         | `uv pip install '.[gemini]'`         | [docs](docs/providers/gemini.md)            |
| AWS Bedrock              | `bedrock`        | `uv pip install '.[bedrock]'`        | [docs](docs/providers/bedrock.md)           |
| Bedrock Mantle (Claude)  | `bedrock_mantle` | `uv pip install '.[bedrock-mantle]'` | [docs](docs/providers/bedrock_mantle.md)    |
| vLLM                     | `vllm`           | included                             | [docs](docs/providers/vllm.md)              |
| Ollama                   | `ollama`         | included                             | [docs](docs/providers/ollama.md)            |
| llama.cpp                | `llamacpp`       | included                             | [docs](docs/providers/llamacpp.md)          |

Or install everything with `uv pip install '.[all-providers]'`.

Embeddings are only required when using the `index` tool. To use a different
provider for embeddings than for chat (e.g. Anthropic chat + OpenAI
embeddings), add a separate `embedding_provider` block — see
[docs/providers/embedding-provider.md](docs/providers/embedding-provider.md).

### 3. Run Analysis

Run the configured graph against a codebase:

```
uv run metis --codebase-path <path_to_src> --verbose
```

Start the interactive prompt instead:

```
uv run metis --interactive --codebase-path <path_to_src>
```

Then run commands such as:

```
init
review_code
```

### 3.1 Docker

Go to your codebase path and run:
```bash
docker run --rm -it -v `pwd`:/metis metis
```

To pass environment variables use `-e`:
```bash
docker run --rm -it -v `pwd`:/metis -e "OPENAI_API_KEY=${OPENAI_API_KEY}" metis
```

You can pass arguments to metis:
```bash
docker run --rm -it -v `pwd`:/metis metis --codebase-path /metis --verbose --output-file /metis/results/review.json
```

## Configuration

**Metis Configuration (`metis.yaml`)**

Metis ships with `src/metis/metis.yaml`. A project may provide `metis.yaml` in
the working directory or select another file with `--config PATH`. Metis uses
the selected file as its configuration source; it does not merge that document
with the packaged YAML. When a selected file omits `metis_engine.execution`,
Metis uses the packaged execution graph. When it defines that section, the
section is the complete graph.

Configuration covers:

- **LLM provider:** chat model and provider connection settings
- **Embedding provider:** models and connection settings used by Index
- **Engine behavior:** max workers, max token length, similarity top-k
- **Review checkpoints:** project-local resume storage, enabled by default
- **Database connection:** In the case of PostgreSQL: host, port, credentials, and schema name
- **Index storage:** backend-specific storage parameters for commands that still use the index.
- **Capability settings:** index-search and navigation limits
- **Reachability:** maximum reported path length and optional domain profiles
  and hints.

Project configuration is optional when the packaged defaults are suitable.

**Language Configuration**

Language manifests, prompt templates, and splitter settings are packaged under
`src/metis/plugins/`. External language packages expose a lightweight manifest
through the `metis.language_plugins` entry-point group. See the
[language plugin guide](docs/language-plugins.md) for the file layout, manifest
contract, and extension steps.

## Running Metis

Metis also provides an interactive CLI with several built-in commands:

### Global CLI Flags

- `--custom-prompt PATH` – optional `.md` or `.txt` file containing additional
  security-review guidance. If omitted, Metis uses `.metis.md` from the project
  root when that file exists.
- `--backend chroma|postgres|qdrant` – choose a vector-store backend (default `chroma`).
- `--project-schema` namespaces PostgreSQL schemas and Qdrant collections.
- `--chroma-dir` and `--qdrant-url` configure backend storage.
- `--triage` – in the interactive prompt, triage findings after `review_code`,
  `review_dir`, `review_file`, or `review_patch` and annotate SARIF output.
- `--include-triaged` – include findings already triaged by Metis when running triage.
- `--verbose` – show the stages and nodes executed by the selected graph.
- `--interactive` – start the command prompt instead of running the configured graph.
- `--log-level` – configure Python logging independently of graph progress.
- `--quiet`, `--output-file`, `--output-files` – control console and export output.
- `--log-workflow-debug` – write a full local workflow trace containing prompts,
  model responses, tool calls, decisions, usage, and execution lifecycle data.
- `--log-workflow-debug-path PATH` – choose the trace directory or a new exact
  `.ndjson` path; this also enables workflow tracing.

See the [execution graph guide](docs/execution-graph.md) for stage, node, and
output configuration, the [workflow run-log format](docs/workflow-log-format.md)
for local trace capture, and
[adding a capability](docs/capabilities/adding-capability.md) for shared runtime
services and model-tool adapters.

### `init`
Initializes Metis repository context. When repository memory is enabled, this
loads threat-model memory first: configured
`metis_engine.threat_model.source_patterns` are stored as authoritative project
data. The packaged configuration includes common `SECURITY.*` and threat-model
filename patterns.
Metis distills those files into repository memory with the configured LLM. The
packaged execution graph does not build the vector index. Add the `index` node
to `initialize`, or run the `index` command, when retrieval is needed. Optional
git-history memory can add advisory security-review lessons; it never defines
binding project scope.

Use `--config PATH` to select a configuration with a different threat-model
source set.

### `index`
Builds the vector index used by `ask`, `update`, and nodes that use the Index
capability.

### `review_code`
Runs the configured Review stage over the codebase. The packaged graph uses the
simple LLM and CodeGraph Reachability nodes, then combines and deduplicates
their findings. Reachability reviews supported C and C++ functions; the simple
LLM review covers every file in the selected scope.

### `review_dir`
Runs the configured Review stage and limits findings to the selected directory.

### `review_file <path>`
Runs the configured Review stage and limits findings to the selected file.

### `review_patch <patch.diff>`
Runs the configured Review stage for a diff. Patch analysis requires a graph
that selects `simple_llm_review`; the packaged Reachability node reports patch
requests as inconclusive.

### `update <patch.diff>`
Incrementally updates the index using a diff. Avoids full reindexing.

### `ask <question>`
Ask questions against the indexed codebase.

### `triage <findings.sarif>`
Triages findings in a SARIF file and annotates each result with Metis triage metadata.
You can use this command on SARIF generated by Metis or by other security/static-analysis tools.
See [docs/triage-flow.md](docs/triage-flow.md) for a short overview of how triage works.

## Examples

#### Example 1: Chroma (default)

```bash
metis --interactive --codebase-path <path_to_src>
```

#### Example 2: Postgres

If you prefer not to use the default ChromaDB backend, you can switch to PostgreSQL either using a local installation or the provided Docker setup.

To get started quickly, run:

```bash
docker compose up -d
```

This will launch a PostgreSQL instance with the pgvector extension enabled, using the credentials specified in your `docker-compose.yml`.

Then, run Metis with the PostgreSQL backend:

```bash
metis \
  --project-schema myproject_main \
  --codebase-path <path_to_src> \
  --backend postgres
```

For embedding models above pgvector's normal-vector HNSW limit, such as
3072-dimensional embeddings, Metis automatically enables pgvector `halfvec`
storage for the PostgreSQL backend so HNSW indexes can still be created. You
can override this in `metis.yaml`:

```yaml
metis_engine:
  embed_dim: 3072
  pgvector_use_halfvec: auto  # auto, true, or false
```

#### Example 3: Qdrant

Qdrant must be running as a server. See the [Qdrant quickstart](https://qdrant.tech/documentation/quickstart/) for setup details, or start a local server with Docker:

```bash
docker run -p 6333:6333 qdrant/qdrant
```

Metis connects to localhost by default:

```bash
metis --backend qdrant --project-schema myproject
```

For another Qdrant Server or Qdrant Cloud endpoint, pass `--qdrant-url` or set `QDRANT_URL`. Set `QDRANT_API_KEY` when authentication is required. Metis creates `<project-schema>_code` and `<project-schema>_docs` collections.

#### Example 4: Usage and output

```bash
metis --interactive --codebase-path <path_to_src>
> review_file src/memory/remap.c
```

Vulnerable source code:
```c
// Remap memory addresses from one region to another
for (uint32_t* ptr = start; ptr < end; ptr++) {
    uint32_t value = *ptr;
    if (value >= OLD_REGION_BASE && value < OLD_REGION_BASE + REGION_SIZE) {
        value = value - OLD_REGION_BASE + NEW_REGION_BASE;
    }
}
```

Example output:

```bash
File: src/memory/remap.c
Identified issue 1: Address Remapping Loop Does Not Update Memory
Snippet:
for (uint32_t* ptr = start; ptr < end; ptr++) {
    uint32_t value = *ptr;
    if...
Why: In the remap_address_table function, the code is intended to adjust address references from an old memory region to a new one. However, the updated value stored in the local variable 'value' is never written back into memory at the pointer location (*ptr). This means the address entries remain unchanged, which can lead to unintended behavior if the system relies on those values being relocated correctly.
Mitigation: Update the loop so that after computing the new address, the value is written back. For example:
for (uint32_t* ptr = start; ptr < end; ptr++) {
    uint32_t value = *ptr;
    if (value >= OLD_REGION_BASE && value < OLD_REGION_BASE + REGION_SIZE) {
        value = ((value - OLD_REGION_BASE) + NEW_REGION_BASE);
        *ptr = value;
    }
}
This ensures that each entry is properly updated to point to the relocated memory region.
Confidence: 1.0
```

#### Example 5: Run the configured review and triage graph

```bash
metis --codebase-path <path_to_src> --verbose --output-file results/full_review.json
```

#### Example 6: Review a patch from the interactive prompt

```bash
metis --interactive --codebase-path <path_to_src> --triage
> review_patch changes.diff --output-file results/review.sarif
```

#### Example 7: Triage an existing SARIF file

```bash
metis --interactive --include-triaged
> triage results/review.sarif --output-file results/retriaged.sarif
```


## License

Metis is distributed under Apache v2.0 License.
