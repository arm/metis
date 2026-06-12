# MCP Tool Contract

The `mcp` tool is planned scaffolding for configured Model Context Protocol
servers.

Metis should map MCP concepts as follows:

- MCP tools -> `model_tool` or `orchestration` capabilities.
- MCP resources -> `context_provider` capabilities.
- MCP prompts -> `prompt_contract` capabilities.

Contract requirements for each MCP server:

- server name and transport;
- allowed Metis domains;
- allowed roots or resource scopes;
- whether tool calls are read-only or side-effectful;
- model-visible description overrides;
- output schema or normalization rules;
- prompt-injection and data-exfiltration risks.

Do not expose all MCP server tools to the model by default. Filter by command,
domain, repository policy, and user configuration.
