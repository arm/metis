# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0


class PluginNotFoundError(Exception):
    """Exception raised when a requested plugin is not found."""

    def __init__(self, plugin_name: str):
        super().__init__(f"Requested plugin '{plugin_name}' not found.")


class DatabaseNotFoundError(Exception):
    """Exception raised when the database is not found."""

    def __init__(self, db_name: str):
        super().__init__(f"Requested database '{db_name}' not found.")


class QueryEngineInitError(Exception):
    """Exception raised when the query engines fail to initialize."""

    def __init__(self):
        super().__init__("Failed to initialize query engines.")


class ToolDisabledError(Exception):
    """Exception raised when a disabled engine tool is used."""

    def __init__(self, tool_name: str):
        super().__init__(
            f"Tool '{tool_name}' is disabled. Enable it with --tools {tool_name}."
        )


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
