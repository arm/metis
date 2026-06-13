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

| Language   | Triage Analysis                          | Notes            |
|------------|------------------------------------------|------------------|
| C          | Tree-sitter + Flow Analysis + tools      | Built-in plugin  |
| C++        | Tree-sitter + Flow Analysis + tools      | Built-in plugin  |
| Python     | Tree-sitter + Structural Analysis + tools| Built-in plugin  |
| Rust       | Tree-sitter + Structural Analysis + tools| Built-in plugin  |
| TypeScript | Tree-sitter + Structural Analysis + tools| Built-in plugin  |
| Terraform  | Tools                                    | Built-in plugin  |
| Go         | Tree-sitter + Structural Analysis + tools| Built-in plugin  |
| Solidity   | Tree-sitter + Structural Analysis + tools| Built-in plugin  |
| TableGen   | Tools                                    | Built-in plugin  |
| Verilog    | Tree-sitter + Structural Analysis + tools| Built-in plugin  |

For triage analysis details (`Flow Analysis` vs `Structural Analysis`), see [docs/triage-flow.md](docs/triage-flow.md).

Metis uses a plugin-based language system, making it easy to extend support to additional languages.

It also supports multiple vector store backends, including PostgreSQL with pgvector and ChromaDB.

## Getting Started

By default, Metis uses **ChromaDB** for local, no-setup usage. You can also use **PostgreSQL (with pgvector)** for scalable indexing and multi-project support.

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

Run metis by also providing the path to the source you want to analyse:

```
uv run metis --codebase-path <path_to_src>
```

Run the security analysis across the codebase:
```
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
docker run --rm -it -v `pwd`:/metis metis --non-interactive --command 'review_code' --output-file results/review_code_results.json
```

## Configuration

**Metis Configuration (`metis.yaml`)**

Metis configuration can be over-ridden using a YAML configuration file (`metis.yaml`) in the working directory when running metis. The default configuration is in src/metis/metis.yaml. This file defines all runtime parameters including:

- **LLM provider:** OpenAI model names, embedding models, token limits
- **Engine behavior:** max workers, max token length, similarity top-k
- **Database connection:** In the case of PostgreSQL: host, port, credentials, and schema name
- **Index storage:** backend-specific storage parameters for commands that still use the index.
- **Tool defaults:** tool manifests define per-tool runtime defaults such as
  `index.search` result limits.
- **Reachability:** tree-sitter reachability tuning, including review-file mode and path-confirmation limits.

This file is **required** to run Metis and should be customized per deployment.

**Prompt Configuration (`plugins.yaml`)**

Metis uses a `plugins.yaml` file to define language-specific behavior, including LLM prompt templates and document splitting logic.
Each language plugin (e.g., C) references this file to load:

### Prompt Templates
You can customize a number of prompts like the following prompts:

- `security_review`: Guides the LLM to perform a security audit of code or diffs.
- `validation_review`: Asks the LLM to assess the correctness or quality of a generated review.
- `security_review_checks`: A list of all the security issues the LLM will try to search for.

These prompts provide natural language context for the LLM and can be tailored to your use case (e.g., stricter audits, privacy reviews, compliance).

### Code Splitting Parameters
You can also configure the chunking parameters for source code and documentation:

- `chunk_lines`: Number of lines per chunk
- `chunk_lines_overlap`: Overlap between chunks
- `max_chars`: Max characters per chunk

### Plugins
Metis discovers language plugins using Setuptools entry points. Packages can expose plugins by declaring the group `metis.plugins` in their packaging metadata. Each entry should resolve to a class implementing `metis.plugins.base.BaseLanguagePlugin` and optionally accept `plugin_config` in the constructor.

Example `pyproject.toml` for a third-party plugin:

```
[project.entry-points."metis.plugins"]
my_lang = "my_pkg.my_module:MyLanguagePlugin"
```

## Running Metis

Metis provides an interactive CLI with several built-in commands. After launching, you can run the following:

### Global CLI Flags

- `--custom-prompt PATH` – optional `.md` or `.txt` file that contains additional guidance. When provided, Metis loads it once and weaves the text into every security-review prompt. If the flag is omitted, Metis looks for `.metis.md` in your project root and uses it when present. Use this to inject organization-specific policy or security requirements without editing `plugins.yaml`.
- `--backend chroma|postgres` – choose vector-store backend (default `chroma`).
- `--project-schema` / `--chroma-dir` – backend-specific knobs.
- `--triage` – after `review_code`, `review_file`, or `review_patch`, triage findings and annotate SARIF output.
- `--include-triaged` – include findings already triaged by Metis when running triage.
- `--tools index,navigation|all|none` – configure engine tools. `navigation` is the default read-only source navigation umbrella for grep/sed-style evidence tools. `index` enables vector-index–backed retrieval (required for `ask`, `index`, `update`; optional context for review/triage) plus the model-callable `index_search` tool for review prompts, and remains opt-in. Use `--tools none` to disable the default tool set.
- `--ignore-index` – compatibility no-op retained for existing scripts.
- `--verbose`, `--quiet`, `--output-file`, `--output-files` – control logging and export formats.

See [docs/tool-plugins.md](docs/tool-plugins.md) for the tool plugin contract and
planned tree-sitter, model-tool, MCP, and private-tool extension path.

### `index`
Builds the legacy vector index used by `ask` and `update`.

### `review_code`
Performs a full security review of the codebase. For C/C++ files, Metis uses deterministic tree-sitter reachability plus targeted semantic audit passes; in mixed-language codebases, those C/C++ results are merged with normal plugin reviews for other languages.

### `review_file <path>`
Performs a targeted security review of a single file. C/C++ files use targeted reachability context by default, while non-C/C++ files use the language plugin review path. Configure the C/C++ reachability mode in `metis.yaml`.

### `review_patch <patch.diff>`
Reviews a diff/patch file and highlights potential security issues introduced by the change.

### `update <patch.diff>`
Incrementally updates the index using a diff. Avoids full reindexing.

### `ask <question>`
Ask questions against the indexed codebase.

### `triage <findings.sarif>`
Triages findings in a SARIF file and annotates each result with Metis triage metadata.
You can use this command on SARIF generated by Metis or by other security/static-analysis tools.
See [docs/triage-flow.md](docs/triage-flow.md) for a short overview of how triage works.

## Running in Non-Interactive Mode

Metis also supports a non-interactive mode, useful for automation, CI/CD pipelines, or scripted usage.

To use Metis in non-interactive mode, use the --non-interactive flag along with --command:

```bash
metis --non-interactive --command "<command> [args...]" [--output-file <file.json>]
```

## Examples

#### Example 1: Chroma (default)

```bash
metis --codebase-path <path_to_src>
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

#### Example 3: Usage and output


```bash
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

#### Example 4: Run a full security review (non-interactive)

```bash
metis --non-interactive --command "review_code" --output-file results/full_review.json
```

#### Example 5: Review and auto-triage findings into SARIF

```bash
metis --non-interactive \
  --triage \
  --command "review_patch changes.diff" \
  --output-file results/review.json \
  --output-file results/review.sarif
```

#### Example 6: Triage an existing SARIF file in place

```bash
metis --non-interactive --command "triage results/review.sarif"
```

#### Example 7: Triage an existing SARIF file into a new output file

```bash
metis --non-interactive \
  --include-triaged \
  --output-file results/retriaged.sarif \
  --command "triage results/review.sarif"
```


## License

Metis is distributed under Apache v2.0 License.
