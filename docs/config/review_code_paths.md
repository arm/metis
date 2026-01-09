# Selective Code Review: Include/Exclude Paths

Metis now supports fine-grained control over which files are targeted during a code review. By utilizing `review_code_include_paths` and `review_code_exclude_paths` in your configuration, you can focus the engine on critical business logic while skipping boilerplate, definitions, and tests.

## Overview

These settings allow you to filter files **specifically for the review process** without removing them from the project's broader context. This ensures that Metis stays fast and the results remain relevant.

- **`review_code_include_paths`**: Limits the review to specific directories or files.
- **`review_code_exclude_paths`**: Explicitly skips specific files or patterns during the review phase.

The **`review_code_include_paths`** and **`review_code_exclude_paths`** configurations utilize standard **gitignore-style** pattern matching.

---

## Why use this instead of `.metisignore`?

It is important to distinguish between these configuration options and the global `.metisignore` file:

| Feature | Scope | Impact on Context |
| :--- | :--- | :--- |
| **`.metisignore`** | **Global** | Files are completely invisible. They are not indexed and cannot be used by the model at all (e.g., `.venv`, `dist`, `node_modules`). |
| **Review Paths** | **Command-Specific** | Files are skipped by the `review_code` logic, but **remain available** as "Relevant Context" (via embeddings or tools) to help the AI understand the code it *is* reviewing. |

**The Logic:** You generally don't want Metis to waste time looking for bugs in a `.d.ts` or `interface.ts` file. However, if Metis is reviewing a service that imports those types, it still needs to be able to "see" those files to understand the data structures.

---

## Configuration

Add these options to your `metis.yaml` file under the `metis_engine` block.

### Example Configuration

```yaml
metis_engine:
  # Only run reviews within the backend folder
  # Where the Core Logic resides
  review_code_include_paths:
    - 'backend/'

  # Skip files that don't require logic analysis
  review_code_exclude_paths:
    - 'dto/'
    - '*.d.ts'
    - '*.spec.ts'
    - '*.fixture.ts'
    - '*.dto.ts'
    - '*.interface.ts'
    - '*.type.ts'
    - '*.schema.ts'
    - 'backend/test/'
    - 'e2e/'
```

View other examples for focused review at the `examples/focused_review_code` folder.

## Key Benefits

- **Focused Reviews**: Configure Metis to only review Core Logic, suchs as specific apps inside your big monorepo.
- **Significant Speed Increase**: Metis avoids reviewing definition files and tests.
- **Noise Reduction**: Prevents "false positive" issues or irrelevant suggestions on generated code, type interfaces, or DTOs where logic-based review is unnecessary.
- **Preserved Context**: Unlike a global ignore, the AI still has access to these files to provide better context for the logic it is actually reviewing.
