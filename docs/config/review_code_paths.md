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
| **`.metisignore`** | **Global** | Files are excluded from Metis visibility, including review traversal and index construction (for example, `.venv`, `dist`, `node_modules`). |
| **Review Paths** | **Command-Specific** | Files are skipped only by `review_code`; they remain available to targeted commands and local evidence tools. |

**The Logic:** You generally don't want Metis to spend review time on generated types, declarations, or interface-only files. Review paths let you narrow what `review_code` audits without making those files globally invisible.

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
