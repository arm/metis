# Repository Memory

Repository memory is the small persistence layer Metis uses for facts that are
worth carrying across commands. It keeps structured records outside the model
context window so later workflows can reload them when they are still fresh.

Repository memory uses SQLite.

## What It Is For

- Keeping reusable repository facts in a local store
- Tracking where a fact came from and whether it is still fresh
- Looking up records by namespace and key
- Searching explicit recall text in a bounded way
- Keeping local development and CI free of new service dependencies

## What It Is Not For

- It is not a vulnerability database
- It is not a broad search layer for bug classes or CWE names
- It does not replace current source evidence
- SQLite memory is not a shared team service

## Record Shape

Records use `MemoryRecord` in `src/metis/memory/schemas.py`.

Each record has identity fields, freshness fields, payload fields, and retrieval
text.

- `namespace` and `key` identify a record
- `artifact_type` names the stored artifact
- `schema_version` and `tool_version` help callers understand compatibility
- `repo_fingerprint` ties a record to repository state
- `input_fingerprint` ties a record to the source input that produced it
- `summary_text` and `search_text` are the only text used for local recall
- `body_json` and `body_markdown` hold the actual payload
- `metadata` holds source specific attributes

- `memory_type` groups records as semantic, episodic, or procedural
- `authority` captures the trust level of the source
- `source_kind` records where the memory came from

## Memory Types

Metis uses repository memory as long term memory. It is for reusable repository
facts and lessons. It is not for per run graph state, message history, streaming
progress, or checkpoint replay.

Metis maps common memory categories onto `memory_type`.

| `memory_type` | What Metis stores | Examples | Retrieval posture |
| --- | --- | --- | --- |
| `semantic` | Stable repository facts and profiles | threat model summaries, trust boundaries, entry points, deployment assumptions, source inventory, build facts | Load early to ground analysis, then verify against current source and freshness fingerprints |
| `episodic` | Prior review experience | user confirmed false positives, benchmark outcomes, corrective commit lessons, past examples used as guidance | Load narrowly when a new task resembles the old one |
| `procedural` | Project specific rules for how Metis should work | approved review policy, repository specific triage rules, prompt and tool routing guidance | Use only when the source is authoritative and current |

Authority matters. A record from project security guidance can constrain
triage. A record inferred from history is useful context, but it should not beat
current code or authoritative project input.

## Storage

`SQLiteMemoryStore` implements the LangGraph store interface used by Metis. It
stores the record payload as JSON. The table keeps only the record identity and
store timestamps outside that JSON payload.

The `MemoryRecord` model owns the JSON shape. SQLite does not project freshness
fields into separate columns.

Store timestamps live in SQLite metadata columns. They are not duplicated inside
the JSON payload.

SQLite FTS keeps a separate text index over the explicit recall fields. That
lets local search use `artifact_type`, `summary_text`, and `search_text` without
turning every structured field into a SQL column.

SQLite opens the database in WAL mode and uses a busy timeout. That is enough
for normal local read and write overlap. It is still a local store.

## Retrieval

The store supports exact lookup and bounded search by namespace prefix, text
query, and exact filters.

Text search uses SQLite FTS5 over `summary_text` and `search_text`. Structured
payload fields are stored for lookup and audit. They are not implicitly indexed
for recall.

Raw store level `search()` has no side effects.

## Configuration

Repository memory is configured in `metis.yaml` under `memory`.

The packaged config keeps memory disabled until an engine workflow wires it in.
It sets `enabled` to `false`, `backend` to `sqlite`, and `location` to
`.metis/memory/metis_memory.sqlite3`.

The `memory.backend` and `memory.location` values come from `metis.yaml`.
SQLite locations are resolved from the repository selected by
`--codebase-path`, and must remain inside that repository.

## Engine Access

Metis opens repository memory from `metis.yaml` and keeps access inside the
engine. Workflows decide what to retrieve, then pass curated context to the
model. The model does not receive a general memory search tool.

This keeps retrieval policy in Metis code, keeps writes orchestration-owned, and
keeps stored facts tied to explicit provenance and freshness metadata.

## Source Authority

Threat-model collection is authority-aware. Configured threat-model sources and
well-known project security documents such as `SECURITY.md` and
`THREAT_MODEL.md` are stored as authoritative project data.

Metis does not infer threat context from arbitrary repository prose, source-code
shape, or git history in this path. If automation needs a large set of files,
pass those files or globs explicitly so the source set is deterministic.

Authority is not a confidence score. It tells Metis how strongly a record may
affect analysis:

- `authoritative`: explicit project policy from configured or well-known
  threat-model/security files.

Example records:

```json
{
  "memory_type": "semantic",
  "authority": "authoritative",
  "source_kind": "repo_file",
  "metadata": {"binding": true, "source": {"kind": "repo_file", "path": "SECURITY.md"}},
  "summary_text": "Callers must validate micro-kernel buffers."
}
```

## Source Metadata

Threat-model sources must resolve to files inside the repository whose extension
is listed under `docs.supported_extensions` in the plugin configuration. PDF
remains supported by repository indexing but is excluded from threat-model
initialization, which reads text sources directly. Configured sources with
unsupported extensions are ignored.

Use top-level `source_kind` for indexed coarse provenance and
`metadata.source` for richer source details. Source envelopes use this shape:

```json
{
  "kind": "repo_file",
  "uri": "file:threat-models/firmware-threat-model.md",
  "path": "threat-models/firmware-threat-model.md",
  "display_name": "Firmware Threat Model",
  "content_type": "text/plain",
  "text_origin": "repo_file",
  "input_fingerprint": "<sha256 hex digest>",
  "source_method": "configured_pattern"
}
```

Configured threat-model files are authoritative and binding in this
initialization path.

## Init Flow

When repository memory is enabled, `init` gathers threat-model memory before
other repository setup. The intended order is:

1. Load authoritative threat-model sources from
   `metis_engine.threat_model.source_patterns`.
2. Store source records with authoritative provenance.
3. Ask the configured LLM to distill concise threat-model claims and compile
   explicit policy and caller contracts from the source files.
4. Build the vector index only when the user enables `--tools index`.

Indexing is a subset of `init`; it is not required for repository memory.

## Claim Distillation and Deduplication

Metis splits each threat-model document into bounded evidence batches and asks
the configured LLM for structured claims. LangChain validates a structured
response when the provider supports it and falls back to parsing JSON text
otherwise.

Deduplication happens in two stages:

1. Metis removes claims with the same statement after case and whitespace
   normalization. This step is deterministic.
2. The LLM merges semantically overlapping claims across authoritative sources.
   Each merged claim must identify the input claim indexes that support it.
   Metis uses those indexes to preserve source references and fingerprints.

If semantic reduction fails validation, omits source indexes, or returns no
usable claims, Metis keeps all deterministically deduplicated input claims.
Source distillation failures abort initialization, so an incomplete snapshot
does not replace existing repository memory.

## Configuration

Repository memory backend and location are configured under top-level `memory`.
Threat-model collection is configured under `metis_engine.threat_model`.

```yaml
memory:
  enabled: true
  backend: sqlite
  location: .metis/memory/metis_memory.sqlite3

metis_engine:
  threat_model:
    source_patterns:
      - "SECURITY.*"
      - "THREAT_MODEL.*"
      - "THREATMODEL.*"
      - "threat_model.*"
      - ".github/SECURITY.*"
      - "docs/SECURITY.*"
      - "docs/THREAT_MODEL.*"
      - "docs/threat_model.*"
      - "docs/**/*threat*model*.*"
    history:
      enabled: false
      max_commits: 500
```

Use `--config PATH` to select a configuration with a different threat-model
source set. Enabling `history` distills recent commit messages and changed paths
into short advisory lessons. History-derived records cannot create binding scope
or automatically invalidate findings. Metis stores every unique lesson with
valid commit provenance rather than applying a fixed record-count cap.

## Review And Triage

Review uses threat-model memory to calibrate project scope before asking for
findings. Authoritative project policy can prevent out-of-scope issues from
being reported as project vulnerabilities.

Triage uses the same authoritative contract when it evaluates a SARIF finding.
An explicit binding out-of-scope policy can mark a finding invalid and store the
applied policy in the SARIF result. Caller contracts and integration-risk
clauses guide semantic review and triage instead of automatically invalidating
a finding.

## Testing

Focused backend coverage is in `tests/test_memory_backend.py`.

The tests cover namespace and key round trips, text search, filters, delete
behavior, freshness checks, invalidation, and stable `created_at` metadata on
overwrite.

## Current Limits

- SQLite is the only implemented repository memory backend
- SQLite FTS5 is required for text search
- Vector retrieval is not part of the memory store
