# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.plugins.base import ConfigBackedLanguagePlugin


class SystemVerilogPlugin(ConfigBackedLanguagePlugin):
    """Language plugin providing SystemVerilog-specific splitter and prompts."""

    NAME = "systemverilog"
