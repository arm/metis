# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Threat-model initialization capability."""

from .service import THREAT_MODEL_NAMESPACE
from .service import initialize_threat_model_memory

__all__ = ["THREAT_MODEL_NAMESPACE", "initialize_threat_model_memory"]
