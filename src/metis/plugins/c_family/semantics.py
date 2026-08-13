# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.codegraph_semantics import CodeGraphAnnotations
from metis.codegraph_semantics import CodeGraphNodeFacts

from .rules import external_sink_type


class CFamilyCodeGraphSemantics:
    def analyze_node(self, facts: CodeGraphNodeFacts) -> CodeGraphAnnotations:
        unresolved_calls = (
            tuple(
                (call.symbol, call.line)
                for call in facts.call_sites
                if call.kind == "direct" and call.resolution == "unresolved"
            )
            if facts.call_sites
            else tuple((call, 0) for call in facts.unresolved_calls)
        )
        for call, line in dict.fromkeys(unresolved_calls):
            sink_type = external_sink_type(call)
            if sink_type:
                return CodeGraphAnnotations(
                    is_sink=True,
                    sink_type=sink_type,
                    sink_reason=(
                        f"calls external security API: {call} at line {line}"
                        if line
                        else f"calls external security API: {call}"
                    ),
                )
        return CodeGraphAnnotations()
