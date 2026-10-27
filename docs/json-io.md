# Streaming JSON I/O

`metis.json_io` handles streaming reads, queued journals, sorting, and atomic writes.
Deduplication stays in its node; SARIF conversion stays in `metis.sarif`.

`StreamingOutput` in `metis.engine.stages.output` owns the per-run descriptors and
passes them to nodes through `NodeContext.output`, using these shared I/O primitives.

`JsonJournal` accepts records from multiple threads. Its writer drains the current
backlog without holding the producer lock during disk I/O. Batches adjust to load;
there is no YAML setting. Queued records have an internal 8 MiB budget, with one
oversized record allowed in an empty queue. Active batches and producer-owned
records also consume memory. Closing joins the writer and propagates I/O errors.

`JsonArray` and `write_json_stream_atomic()` write iterable arrays without collecting
them. `JsonSnapshot` validates and copies inputs for incremental reads and rewrites,
preserving unknown fields. Existing strict JSON validation remains enforced,
including duplicate-key, Unicode, numeric, and recursive-output checks.
`sorted_json_records()` uses bounded chunks and at most 32 open inputs.

Journals replace periodic full-report checkpoints. Complete JSON/SARIF documents
are published at finalization. Atomic replacement preserves the previous report on
failure; concurrent writers use separate temporary files, with the last writer winning.
Temporary disk usage grows with the report and working copies.

The CLI passes output destinations and receives file references. Dictionary-returning
engine APIs and HTML/CSV export still materialize reports. External nodes retain
their declared contracts. See [triage flow](triage-flow.md) for file-based triage.
