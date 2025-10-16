# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import pkgutil
import importlib

__all__ = []

for _, module_name, _ in pkgutil.iter_modules(__path__):
    if module_name.endswith("_plugin"):
        module = importlib.import_module(f"{__name__}.{module_name}")
        globals()[module_name] = module
        __all__.append(module_name)
