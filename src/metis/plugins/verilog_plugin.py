# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.plugins.base import ConfigBackedLanguagePlugin


class VerilogPlugin(ConfigBackedLanguagePlugin):
    """Language plugin providing Verilog-specific splitter and prompts."""

    NAME = "verilog"
    DEFAULT_EXTENSIONS = [".v", ".vh"]
