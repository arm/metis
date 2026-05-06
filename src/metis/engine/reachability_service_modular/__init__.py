# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Tree-sitter backed reachability graph construction.

This package keeps the deterministic graph builder separate from the existing
LLM extraction path so it can be tested through ``reachability_treesitter``.
"""

from .service import TreeSitterReachabilityService

__all__ = ["TreeSitterReachabilityService"]
