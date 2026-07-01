# Repository Memory

Repository memory is the small persistence layer Metis uses for facts that are
worth carrying across commands. It keeps structured records outside the model
context window so later workflows can reload them when they are still fresh.

The first backend is SQLite.

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

Use a separate backend with access control before memory is shared across users
or machines.

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

The lifecycle fields describe how a caller should treat a record.

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
or lifecycle fields into separate columns in this first storage layer.

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

The backend comes from `metis.yaml`. The location is passed to that backend as
plain backend data. Other backends can be added through the memory store
registry without changing callers.

## Tests

Focused backend coverage is in `tests/test_memory_backend.py`.

The tests cover namespace and key round trips, text search, filters, delete
behavior, freshness checks, invalidation, and stable `created_at` metadata on
overwrite.

## Current Limits

- SQLite is the only implemented repository memory backend
- SQLite FTS5 is required for text search
- Vector retrieval is not part of the memory store
- Shared service deployment needs a separate backend and access control model
