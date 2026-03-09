# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Any

from .base import AnalyzerRequest
from .c_family_analyzer_common import _FlowHop, _FunctionInfo, _node_text


class CFamilyFlowMixin:
    def _build_structured_flow_chain(
        self,
        *,
        request: AnalyzerRequest,
        root,
        source: bytes,
        node_index: list[Any],
        parent_map: dict[int, Any | None],
        functions: dict[str, list[_FunctionInfo]],
        max_hops: int,
        max_depth: int,
    ) -> tuple[list[_FlowHop], list[str], list[str], list[str]]:
        unresolved: list[str] = []
        fallback_targets: list[str] = []
        hops: list[_FlowHop] = []
        packet_sections: list[str] = []

        anchor = self._find_anchor_node(node_index, request.line)
        if anchor is None:
            return [], ["FLOW_ANCHOR_NOT_FOUND"], [], []

        anchor_fn = self._select_anchor_function(
            request_line=request.line,
            anchor_node=anchor,
            parent_map=parent_map,
            functions=functions,
        )

        if anchor_fn is None:
            packet_sections.append("path.anchor: <none>")
            unresolved.append("FLOW_ENCLOSING_FUNCTION_UNRESOLVED")
            anchor_calls = self._collect_calls_in_scope(root, source)[:6]
            hops.append(
                _FlowHop(
                    role="source",
                    line=request.line,
                    detail="reported context outside resolvable function scope",
                )
            )
            if anchor_calls:
                first = anchor_calls[0]
                role = "unknown"
                hops.append(
                    _FlowHop(
                        role=role,
                        line=first.line,
                        detail=f"top-level call '{first.symbol}'",
                        symbol=first.symbol,
                    )
                )
                unresolved.append(f"FLOW_SINK_CLASS_UNRESOLVED:{first.symbol}")
                if self._is_actionable_symbol(first.symbol):
                    fallback_targets.append(first.symbol)
            else:
                unresolved.append("FLOW_SINK_NOT_FOUND")
            return hops[:max_hops], unresolved, fallback_targets, packet_sections

        packet_sections.append(
            f"path.anchor: {anchor_fn.name} [{anchor_fn.line_start}-{anchor_fn.line_end}]"
        )

        hops.append(
            _FlowHop(
                role="source",
                line=request.line,
                detail=f"reported context in function '{anchor_fn.name}'",
                symbol=anchor_fn.name,
            )
        )

        near_checks = sorted(
            anchor_fn.checks,
            key=lambda item: (abs(item.line - request.line), item.line),
        )[:3]
        hops.extend(near_checks)

        callers = self._collect_callers(
            anchor_name=anchor_fn.name,
            functions=functions,
            max_depth=max_depth,
        )
        if callers:
            packet_sections.append("path.callers: " + " -> ".join(callers[:4]))
            for idx, caller in enumerate(callers[:2]):
                hops.append(
                    _FlowHop(
                        role="source",
                        line=anchor_fn.line_start,
                        detail=f"upstream caller '{caller}' reaches '{anchor_fn.name}' (depth {idx + 1})",
                        symbol=caller,
                    )
                )

        endpoint_found = False
        visited: set[tuple[str, int]] = set()
        queue: list[tuple[_FunctionInfo, int]] = [(anchor_fn, 0)]
        callee_path_parts: list[str] = [anchor_fn.name]
        while queue and len(hops) < max_hops:
            fn, depth = queue.pop(0)
            state_key = (fn.name, fn.line_start)
            if state_key in visited:
                continue
            visited.add(state_key)

            for call in fn.calls[:12]:
                if len(hops) >= max_hops:
                    break
                role = "unknown"
                hops.append(
                    _FlowHop(
                        role=role,
                        line=call.line,
                        detail=f"{fn.name} calls '{call.symbol}'",
                        symbol=call.symbol,
                    )
                )
                endpoint_found = True
                callee_path_parts.append(call.symbol)

                if not self._is_actionable_symbol(call.symbol):
                    continue
                variants = functions.get(call.symbol, [])
                if variants and depth < max_depth:
                    next_fn = variants[0]
                    queue.append((next_fn, depth + 1))
                    callee_path_parts.append(call.symbol)
                else:
                    unresolved.append(f"FLOW_EXTERNAL_CALLEE_UNRESOLVED:{call.symbol}")
                    fallback_targets.append(call.symbol)

        if len(callee_path_parts) > 1:
            packet_sections.append(
                "path.callees: " + " -> ".join(callee_path_parts[:8])
            )
        if not endpoint_found:
            unresolved.append("FLOW_SINK_NOT_FOUND")
        if len(hops) >= max_hops and queue:
            unresolved.append("FLOW_CHAIN_TRUNCATED_BY_BOUND")

        for fn_name in callee_path_parts[1:4]:
            fn_variants = functions.get(fn_name, [])
            if not fn_variants:
                continue
            fn = fn_variants[0]
            sig = self._read_signature(fn.node, source)
            packet_sections.append(
                f"path.hop: {fn.name} [{fn.line_start}-{fn.line_end}] sig='{sig}'"
            )

        return hops[:max_hops], unresolved, fallback_targets, packet_sections[:8]

    def _collect_callers(
        self,
        *,
        anchor_name: str,
        functions: dict[str, list[_FunctionInfo]],
        max_depth: int,
    ) -> list[str]:
        reverse: dict[str, set[str]] = {}
        for caller, variants in functions.items():
            for info in variants:
                for ref in info.calls:
                    if not self._is_actionable_symbol(ref.symbol):
                        continue
                    reverse.setdefault(ref.symbol, set()).add(caller)

        out: list[str] = []
        seen = set()
        frontier = [(anchor_name, 0)]
        while frontier:
            symbol, depth = frontier.pop(0)
            if depth >= max_depth:
                continue
            for caller in sorted(reverse.get(symbol, set()), key=lambda s: s.lower()):
                if caller in seen:
                    continue
                seen.add(caller)
                out.append(caller)
                frontier.append((caller, depth + 1))
                if len(out) >= 8:
                    return out
        return out

    def _read_signature(self, function_node, source: bytes) -> str:
        text = _node_text(function_node, source).strip()
        if not text:
            return ""
        first = text.split("{", 1)[0].strip()
        first = " ".join(first.split())
        return first[:160]
