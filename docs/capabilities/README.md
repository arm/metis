# Engine Capabilities

An engine capability is a service that an execution node may use. The selected
execution YAML grants capabilities to each node through its `capabilities`
allowlist. A capability may expose deterministic operations, model-callable
tools, or both.

- [`index`](index.md) provides vector-index construction and retrieval.
- [`memory`](../repository-memory.md) stores repository facts shared across
  commands and selected nodes.
- [`navigation`](navigation.md) provides bounded source navigation.

A Tool is a model-callable adapter that a node deliberately creates for an
operation on a granted capability. A capability grant alone does not expose a
Tool. Built-in model-facing contracts remain packaged under
`src/metis/engine/tools/contracts/` because they define prompt-time behavior,
not execution-graph access.

Built-in capability manifests live under
`src/metis/engine/capabilities/manifests/`. Only a node's execution-YAML
`capabilities` allowlist grants that node access to a capability.

See [Adding a Metis Capability](adding-capability.md) for the extension guide.
