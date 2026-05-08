# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Compatibility exports for reachability primitives.

The LLM-built reachability graph implementation was retired in favor of the
tree-sitter implementation under ``reachability_service_modular``.  A small
module remains here so older imports of graph/path/finding helpers keep working.
"""

from .reachability_common import *  # noqa: F401,F403
from .reachability_common import (  # noqa: F401
    _VULN_TO_CWE,
    _dedupe_paths,
    _normalise_vuln_type,
    _post_filter_findings,
    _read_function_body,
    _read_line_context,
    _safe_int,
    _same_file_ref,
    _severity_title,
    _write_jsonl,
)
from .reachability_service_modular.service import (  # noqa: F401
    DEFAULT_OUTPUT_DIR,
    DEFAULT_TREESITTER_OUTPUT_DIR,
    TreeSitterReachabilityService as ReachabilityService,
)
