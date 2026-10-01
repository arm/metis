# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0


class RetrieverInitError(Exception):
    """Exception raised when retriever initialization fails."""

    def __init__(self):
        super().__init__("Failed to initialize retrievers.")


class ParsingError(Exception):
    """Exception raised when parsing fails."""

    def __init__(self, message: str):
        super().__init__(f"Parsing error: {message}")


class VectorStoreInitError(Exception):
    """Exception raised when the vector store fails to initialize."""

    def __init__(self):
        super().__init__(
            "Vector store initialization error: Unable to initialize the vector store."
        )


class VectorSchemaError(Exception):
    """Exception raised when checking for vector schema (postgres) fails."""

    def __init__(self):
        super().__init__("Error checking for project schema.")


class IndexUpdateError(Exception):
    """Raised when one or more files could not be applied to the index."""

    def __init__(self, failures: list[str]):
        super().__init__(
            f"Index update failed for {len(failures)} file(s):\n" + "\n".join(failures)
        )


class IndexStateError(Exception):
    """Exception raised when the recorded index state cannot be read or written."""

    def __init__(self, message: str):
        super().__init__(f"Index state error: {message}")


class IndexSyncError(Exception):
    """Raised when the index cannot be synced to the current commit."""
