# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.plugins.c_plugin import CPlugin
from metis.plugins.cpp_plugin import CppPlugin


def is_c_family_plugin(plugin) -> bool:
    return isinstance(plugin, (CPlugin, CppPlugin))
