# Source navigation

Navigation is enabled by default for simple LLM reviews and optional triage.
It provides read-only `grep`, `find_name`, `cat`, and `sed` tools under the
codebase root. Review findings stay in the assigned file or patch; the model
can inspect related definitions, callers, guards, and counterexamples elsewhere
in the repository.

Shared navigation instructions appear once in the prompt. With model tools
enabled, `metis_engine.max_token_length` bounds the rendered message content and
tool-call history. The check includes source line numbers and tool evidence,
but not provider-specific framing or schema overhead. Overflow stops the next
model call without repeating the conversation. This is separate from the output
limit in `query.max_tokens`.

Use `--tools none` to disable tools. Use `--tools index,navigation` to also
allow index retrieval. Existing `metis_engine.model_tools.max_rounds` limits
tool-call rounds; navigation retains its eight-second subprocess timeout and
16,000-character output limit. Recursive searches do not follow file symlinks,
and direct paths that resolve outside the codebase are rejected.

The [packaged model-tool contract](../../src/metis/engine/tools/contracts/navigation.md)
contains the shared source-evidence rules used by review and triage. It ships
inside the wheel so installed CLI runs receive the same guidance as source runs.
Triage investigates the reported finding; review can discover new findings
within its assigned scope. Missing context is not evidence of safety.
