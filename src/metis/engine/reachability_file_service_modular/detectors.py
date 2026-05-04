# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from .common import *

class PartialCandidateDetector:
    def __init__(self, codebase_path: str, cache: PartialAnalysisCache | None = None):
        self._cb = os.path.abspath(codebase_path)
        self._cache = cache or PartialAnalysisCache(codebase_path)

    def detect(
        self,
        index: SymbolIndex,
        target_file: str,
        target_nodes: list[FunctionNode],
        context: PartialReviewContext,
    ) -> PartialDetectorResult:
        self._cache.bind_index(index)
        result = PartialDetectorResult()
        target_names = {node.name for node in target_nodes}
        target_syms = _symbols_for_file(index, target_file)
        target_prefixes = {_module_stem(name) for name in target_names if name}
        context_syms = self._context_symbols(index, context, target_syms)

        self._detect_state_publication(index, result, target_syms, target_prefixes)
        self._detect_publish_rollback(index, result, target_syms)
        self._detect_allocation_arithmetic(index, result, target_syms)
        self._detect_arithmetic_chain_mismatch(index, result, target_syms)
        self._detect_size_propagation(index, result, target_syms, context)
        self._detect_alias_size_chain(index, result, target_syms, context)
        self._detect_alias_extent_mismatch(index, result, target_syms, context)
        self._detect_copy_contracts(index, result, target_syms)
        self._detect_cleanup_symmetry(index, result, target_syms)
        self._detect_interprocedural_cleanup_ledger(index, result, target_syms, context)
        self._detect_suspend_cleanup_ledger(index, result, target_syms, context)
        self._detect_suspend_size_sink(index, result, target_syms, context)
        self._detect_accounting_drift(index, result, target_syms)
        self._detect_resource_binding_order(index, result, target_syms)
        self._detect_resource_validation_order(index, result, target_syms)
        self._detect_async_event_order(index, result, target_syms)
        self._detect_fault_clear_order(index, result, target_syms, context)
        self._detect_stale_tracker_state(index, result, target_syms)
        self._detect_region_replace_erase(index, result, target_syms, context)
        self._detect_metadata_type_confusion(index, result, target_syms)
        self._detect_pm_runtime_sequence(index, result, target_syms)
        self._detect_pm_callback_order(index, result, target_syms)
        self._detect_secondary_element_omission(index, result, target_syms)
        self._detect_zero_count_underflow(index, result, target_syms)
        self._detect_owner_liveness_allocation(index, result, target_syms)
        self._detect_user_buffer_permission(index, result, target_syms)
        self._detect_zone_shrink_validation(index, result, target_syms)
        self._detect_success_path_cleanup(index, result, target_syms)
        self._detect_jit_lock_protocol(index, result, target_syms, context)
        self._detect_teardown_order(index, result, target_syms, context)
        self._detect_queue_publish_init(index, result, target_syms)
        self._detect_fd_reuse_race(index, result, target_syms)
        self._detect_debugfs_permission(index, result, target_syms)
        wrappers = self._detect_format_wrappers(index, result, target_syms, target_prefixes)
        self._detect_info_leaks(index, result, target_syms)
        self._detect_fops(index, result, target_file, target_names)
        self._detect_lock_order(index, result, context_syms, target_file)
        self._detect_cross_file_lock_cycles(index, result, context, target_file)
        self._detect_named_lock_inversion(index, result, context, target_file)
        self._detect_stale_after_unlock(index, result, target_syms)
        self._detect_disable_stale(index, result, target_syms)
        self._detect_callback_lifetime(index, result, target_syms, target_prefixes)
        self._detect_state_transition_protocol(index, result, target_syms, context, target_file)
        self._detect_protected_mmu_protocol(index, result, target_syms, context)
        self._detect_active_singleton_stale(index, result, target_syms, context)
        self._detect_mmu_recovery_rollback(index, result, target_syms, context)
        self._detect_policy_gate_before_sink(index, result, target_syms, context)
        self._detect_imported_same_va_fault_policy(index, result, target_syms, context)
        self._detect_imported_mapping_policy(index, result, target_syms, context)
        self._detect_sentinel_misuse(index, result, target_syms)
        self._detect_target_calls_wrappers(index, result, target_syms, wrappers)
        result.nodes = self._dedupe_nodes(result.nodes)
        result.globals = list({g.unique_name: g for g in result.globals}.values())
        return result

    def _lines(self, sym: SymbolDef) -> list[tuple[int, str]]:
        return self._cache.symbol_lines(sym)

    def _body_text(self, sym: SymbolDef) -> str:
        return self._cache.symbol_body(sym, numbered=False)

    def _node(self, index: SymbolIndex, sym: SymbolDef) -> FunctionNode:
        return _symbol_to_node(index, self._cb, sym, self._cache)

    def _add_node(self, index: SymbolIndex, result: PartialDetectorResult, sym: SymbolDef | None):
        if sym:
            result.nodes.append(self._node(index, sym))

    def _dedupe_nodes(self, nodes: list[FunctionNode]) -> list[FunctionNode]:
        seen, out = set(), []
        for node in nodes:
            if node.unique_name in seen:
                continue
            seen.add(node.unique_name)
            out.append(node)
        return out

    def _symbol_for_function(self, index: SymbolIndex, file_path: str, name: str) -> SymbolDef | None:
        return _lookup_symbol(index, file_path, name)

    def _context_symbols(self, index, context, target_syms):
        syms = {f"{sym.file_path}::{sym.name}": sym for sym in target_syms}
        for node in (
            context.target_nodes + context.inbound_callers + context.outbound_callees
            + context.shared_state_nodes + context.lifecycle_pair_nodes
            + context.callback_nodes + context.companion_nodes
        ):
            sym = self._symbol_for_function(index, node.file_path, node.name)
            if sym:
                syms[f"{sym.file_path}::{sym.name}"] = sym
        return list(syms.values())

    def _field_name_from_state_write(self, line: str) -> str:
        match = re.search(
            r"(gpu_ready|runtime_active|ready|enabled|active|initialized|loaded|online|powered|state)",
            line,
            re.IGNORECASE,
        )
        return match.group(1) if match else ""

    def _detect_state_publication(self, index, result, target_syms, target_prefixes):
        for sym in target_syms:
            lines = self._lines(sym)
            for idx, (line_no, line) in enumerate(lines):
                if not _STATE_FIELD_RE.search(line):
                    continue
                later = lines[idx + 1:idx + 45]
                error = next(((ln, txt) for ln, txt in later if _ERROR_PATH_RE.search(txt)), None)
                if not error:
                    continue
                field = self._field_name_from_state_write(line)
                rollback = any(_STATE_RESET_RE.search(txt) and field.lower() in txt.lower() for _, txt in later)
                if rollback:
                    continue
                result.state_publication_notes.append(
                    f"{sym.file_path}::{sym.name} line {line_no} publishes `{_line_excerpt(line)}` "
                    f"before later error path line {error[0]} `{_line_excerpt(error[1])}` without rollback."
                )
                self._add_node(index, result, sym)
                for use in index.field_uses.get(field, [])[:30]:
                    other = self._symbol_for_function(index, use.file_path, use.function_name)
                    if other and other.file_path != sym.file_path:
                        self._add_node(index, result, other)
                for candidate in self._paired_lifecycle_symbols(index, sym.name, target_prefixes, {"disable", "shutdown", "term", "destroy", "unload"}):
                    self._add_node(index, result, candidate)

    def _detect_publish_rollback(self, index, result, target_syms):
        rollback_names = {"rb_erase", "list_del", "hash_del", "unregister", "remove", "erase"}
        for sym in target_syms:
            lines = self._lines(sym)
            for idx, (line_no, line) in enumerate(lines):
                if not _PUBLISH_CALL_RE.search(line):
                    continue
                later = lines[idx + 1:idx + 60]
                error = next(((ln, txt) for ln, txt in later if _ERROR_PATH_RE.search(txt) or "capacity" in txt.lower() or "fail" in txt.lower()), None)
                if not error:
                    continue
                rollback = any(_ROLLBACK_CALL_RE.search(txt) for _, txt in later[:max(1, error[0] - line_no)])
                if rollback:
                    continue
                result.publish_rollback_notes.append(
                    f"{sym.file_path}::{sym.name} line {line_no} publishes `{_line_excerpt(line)}`, "
                    f"then line {error[0]} can fail via `{_line_excerpt(error[1])}` with no rollback before return."
                )
                self._add_node(index, result, sym)
                for name in rollback_names:
                    for helper in index.definitions.get(name, [])[:5]:
                        self._add_node(index, result, helper)

    def _detect_allocation_arithmetic(self, index, result, target_syms):
        for sym in target_syms:
            lines = self._lines(sym)
            for idx, (line_no, line) in enumerate(lines):
                if not _ALLOC_ARITH_RE.search(line):
                    continue
                window = "\n".join(txt for _, txt in lines[max(0, idx - 6):idx + 4])
                if _OVERFLOW_GUARD_RE.search(window):
                    continue
                result.allocation_arithmetic_notes.append(
                    f"{sym.file_path}::{sym.name} line {line_no} uses allocation arithmetic `{_line_excerpt(line)}` "
                    "without an obvious checked multiplication or SIZE_MAX guard nearby."
                )
                self._add_node(index, result, sym)

    def _detect_copy_contracts(self, index, result, target_syms):
        for sym in target_syms:
            guards = _symbol_guards(index, sym)
            count_tokens = self._count_tokens_for_symbol(sym, _symbol_assignments(index, sym))
            for use in _symbol_copy_uses(index, sym):
                size_tokens = _fact_tokens(use.size_expr)
                if not size_tokens & (_COUNT_SIZE_WORDS | _RESOURCE_WORDS) and not self._copy_size_is_fixed(use.size_expr):
                    continue
                if self._copy_result_ignored(use) and (self._copy_size_is_fixed(use.size_expr) or size_tokens & _COUNT_SIZE_WORDS):
                    result.copy_contract_notes.append(
                        f"{sym.file_path}::{sym.name} line {use.line_number} calls {use.api} "
                        f"with size/count `{_short_expr(use.size_expr)}` but ignores short-copy/short-transfer result: "
                        f"`{_line_excerpt(use.line_text)}`."
                    )
                    self._add_node(index, result, sym)
                    if len(result.copy_contract_notes) >= 20:
                        return
                    continue
                if self._copy_has_nearby_guard(guards, use, count_tokens):
                    continue
                if use.api in {"read", "write"} and not (size_tokens & _COUNT_SIZE_WORDS):
                    continue
                missing = self._copy_missing_guard_text(use, count_tokens)
                result.copy_contract_notes.append(
                    f"{sym.file_path}::{sym.name} line {use.line_number} calls {use.api} "
                    f"with size/count `{_short_expr(use.size_expr)}` but {missing}: `{_line_excerpt(use.line_text)}`."
                )
                self._add_node(index, result, sym)
                if len(result.copy_contract_notes) >= 20:
                    return

    def _count_tokens_for_symbol(self, sym: SymbolDef, assignments: list[AssignmentFact]) -> set[str]:
        text = sym.signature
        for assign in assignments[:80]:
            text += f" {assign.target} {assign.value}"
        tokens = _fact_tokens(text)
        return tokens & _COUNT_SIZE_WORDS

    def _copy_has_nearby_guard(self, guards: list[GuardFact], use: CopyUse, count_tokens: set[str]) -> bool:
        size_tokens = _fact_tokens(use.size_expr)
        wanted = (size_tokens | count_tokens) & (_COUNT_SIZE_WORDS | _RESOURCE_WORDS)
        if not wanted and self._copy_size_is_fixed(use.size_expr):
            wanted = count_tokens
        for guard in guards:
            if guard.line_number > use.line_number:
                continue
            if use.line_number - guard.line_number > 18:
                continue
            guard_text = f"{guard.lhs} {guard.rhs}"
            if guard.token in wanted:
                if self._copy_size_is_fixed(use.size_expr):
                    if re.search(r"\bsizeof\s*\(|\bmin\s*\(|\bclamp\b", guard.line_text, re.IGNORECASE):
                        return True
                    if use.size_expr and _short_expr(use.size_expr) in guard_text:
                        return True
                    continue
                return True
            if use.size_expr and _short_expr(use.size_expr) in guard_text:
                return True
        return False

    def _copy_size_is_fixed(self, expr: str) -> bool:
        expr_l = str(expr or "").lower()
        return bool(re.search(r"\bsizeof\s*\(|^\s*\d+\s*$|^[A-Z0-9_]+$", expr_l, re.IGNORECASE))

    def _copy_missing_guard_text(self, use: CopyUse, count_tokens: set[str]) -> str:
        if self._copy_size_is_fixed(use.size_expr) and count_tokens:
            return f"no nearby count/len guard ({', '.join(sorted(count_tokens)[:3])}) validates the fixed-size transfer"
        if _fact_tokens(use.size_expr) & _COUNT_SIZE_WORDS:
            return "no nearby upper-bound/short-transfer guard constrains the requested count"
        return "no nearby contract guard is visible"

    def _copy_result_ignored(self, use: CopyUse) -> bool:
        if use.api not in {"copy_to_user", "copy_from_user", "copy_in_user", "read", "write", "kernel_read", "kernel_write"}:
            return False
        prefix = use.line_text.split(use.api, 1)[0]
        if re.search(r"\b(?:if|return|ret|err|rc|res|copied|remaining)\b", prefix):
            return False
        if "=" in prefix and "==" not in prefix and "!=" not in prefix:
            return False
        return True

    def _detect_cleanup_symmetry(self, index, result, target_syms):
        for sym in target_syms:
            facts = _symbol_cleanup_facts(index, sym)
            acquires = [fact for fact in facts if fact.kind == "acquire"]
            releases = [fact for fact in facts if fact.kind == "release"]
            exits = [fact for fact in facts if fact.kind == "exit"]
            if not acquires or not exits:
                continue
            for acquire in acquires[:20]:
                expected = self._expected_release_actions(acquire.action)
                if not expected:
                    continue
                later_releases = [
                    rel for rel in releases
                    if rel.line_number > acquire.line_number and rel.action in expected
                ]
                for exit_fact in exits:
                    if exit_fact.line_number <= acquire.line_number:
                        continue
                    if exit_fact.line_number - acquire.line_number > 90:
                        continue
                    if any(acquire.line_number < rel.line_number < exit_fact.line_number for rel in later_releases):
                        continue
                    if "goto" in exit_fact.line_text.lower() and later_releases:
                        continue
                    result.cleanup_symmetry_notes.append(
                        f"{sym.file_path}::{sym.name} line {acquire.line_number} performs {acquire.action} "
                        f"`{_line_excerpt(acquire.line_text)}`, but exit line {exit_fact.line_number} "
                        f"`{_line_excerpt(exit_fact.line_text)}` has no visible {sorted(expected)[0]} before leaving."
                    )
                    self._add_node(index, result, sym)
                    if len(result.cleanup_symmetry_notes) >= 20:
                        return
                    break

    def _expected_release_actions(self, action: str) -> set[str]:
        pairs = {
            "alloc": {"free"},
            "get": {"put"},
            "map": {"unmap"},
            "register": {"unregister"},
            "insert": {"erase"},
            "inc": {"dec"},
            "enable": {"disable"},
        }
        return pairs.get(action, set())

    def _detect_accounting_drift(self, index, result, target_syms):
        for sym in target_syms:
            facts = _symbol_cleanup_facts(index, sym)
            incs = [fact for fact in facts if fact.action == "inc"]
            decs = [fact for fact in facts if fact.action == "dec"]
            exits = [fact for fact in facts if fact.kind == "exit"]
            if not incs or not exits:
                continue
            for inc in incs[:20]:
                resource_tokens = _fact_tokens(inc.resource)
                matching_decs = [
                    dec for dec in decs
                    if resource_tokens & _fact_tokens(dec.resource)
                    and dec.line_number > inc.line_number
                ]
                for exit_fact in exits:
                    if exit_fact.line_number <= inc.line_number:
                        continue
                    if any(inc.line_number < dec.line_number < exit_fact.line_number for dec in matching_decs):
                        continue
                    result.accounting_drift_notes.append(
                        f"{sym.file_path}::{sym.name} line {inc.line_number} updates counter/resource "
                        f"`{_short_expr(inc.resource)}`, but exit line {exit_fact.line_number} "
                        f"`{_line_excerpt(exit_fact.line_text)}` can leave before a matching decrement."
                    )
                    self._add_node(index, result, sym)
                    if len(result.accounting_drift_notes) >= 16:
                        return
                    break

    def _detect_arithmetic_chain_mismatch(self, index, result, target_syms):
        for sym in target_syms:
            assigns = [assign for assign in _symbol_assignments(index, sym) if assign.is_arithmetic]
            formulas = _symbol_formula_facts(index, sym)
            if len(assigns) < 1 and len(formulas) < 1:
                continue
            copy_uses = _symbol_copy_uses(index, sym)
            sinks = _symbol_sink_facts(index, sym)
            guards = _symbol_guards(index, sym)
            consumers = [
                (use.line_number, use.size_expr, use.line_text, use.api)
                for use in copy_uses
                if _fact_tokens(use.size_expr) & (_COUNT_SIZE_WORDS | _RESOURCE_WORDS)
            ]
            consumers.extend(
                (sink.line_number, sink.line_text, sink.line_text, sink.api)
                for sink in sinks
            )
            for assign in assigns[:20]:
                assign_tokens = set(assign.tokens) | (_fact_tokens(assign.value) & (_COUNT_SIZE_WORDS | _RESOURCE_WORDS))
                if not assign_tokens:
                    continue
                for line_no, expr, line_text, api in consumers[:30]:
                    if line_no <= assign.line_number:
                        continue
                    consumer_tokens = _fact_tokens(expr)
                    overlap = assign_tokens & consumer_tokens
                    if not overlap:
                        continue
                    if self._same_arithmetic_expr(assign.value, expr):
                        continue
                    if self._has_consistency_guard(guards, assign, line_no):
                        continue
                    result.arithmetic_chain_notes.append(
                        f"{sym.file_path}::{sym.name} derives `{assign.target} = {_short_expr(assign.value)}` "
                        f"at line {assign.line_number}, then {api} at line {line_no} consumes "
                        f"`{_short_expr(expr)}` with shared token(s) {', '.join(sorted(overlap)[:3])} "
                        "but no nearby consistency/overflow guard ties the formulas together."
                    )
                    self._add_node(index, result, sym)
                    if len(result.arithmetic_chain_notes) >= 16:
                        return
                    break
            for producer in formulas[:20]:
                producer_tokens = set(producer.tokens)
                if not producer_tokens or not {"mul", "shift", "round"} & set(producer.operators):
                    continue
                for consumer in formulas[:30]:
                    if consumer.line_number <= producer.line_number:
                        continue
                    overlap = producer_tokens & set(consumer.tokens)
                    if not overlap:
                        continue
                    if producer.normalized == consumer.normalized:
                        continue
                    if set(producer.operators) == set(consumer.operators) and "sizeof" in producer.operators:
                        continue
                    if self._has_formula_consistency_guard(guards, producer, consumer.line_number):
                        continue
                    result.arithmetic_chain_notes.append(
                        f"{sym.file_path}::{sym.name} line {producer.line_number} derives `{producer.target} = {_short_expr(producer.expr)}` "
                        f"with operators {','.join(producer.operators)}, but line {consumer.line_number} derives "
                        f"`{consumer.target} = {_short_expr(consumer.expr)}` with operators {','.join(consumer.operators)} over "
                        f"shared token(s) {', '.join(sorted(overlap)[:3])} and no consistency/overflow guard."
                    )
                    self._add_node(index, result, sym)
                    if len(result.arithmetic_chain_notes) >= 16:
                        return
                    break

    def _same_arithmetic_expr(self, a: str, b: str) -> bool:
        ta = _fact_tokens(a)
        tb = _fact_tokens(b)
        return bool(ta and tb and ta == tb and _ARITH_EXPR_RE.search(a) and _ARITH_EXPR_RE.search(b))

    def _has_consistency_guard(self, guards: list[GuardFact], assign: AssignmentFact, consumer_line: int) -> bool:
        assign_tokens = set(assign.tokens) | _fact_tokens(assign.target) | _fact_tokens(assign.value)
        for guard in guards:
            if guard.line_number < assign.line_number or guard.line_number > consumer_line:
                continue
            if guard.token in assign_tokens:
                return True
        return False

    def _has_formula_consistency_guard(self, guards: list[GuardFact], formula: FormulaFact, consumer_line: int) -> bool:
        tokens = set(formula.tokens) | _fact_tokens(formula.target) | _fact_tokens(formula.expr)
        for guard in guards:
            if guard.line_number < formula.line_number or guard.line_number > consumer_line:
                continue
            if guard.token in tokens and guard.op in {"<", "<=", ">", ">=", "=="}:
                return True
        return False

    def _detect_resource_binding_order(self, index, result, target_syms):
        for sym in target_syms:
            assigns = _symbol_assignments(index, sym)
            resource_assigns = [
                assign for assign in assigns
                if set(assign.tokens) & _RESOURCE_WORDS
            ]
            state_assigns = [
                assign for assign in assigns
                if set(assign.tokens) & _TRANSITION_TOKENS
                or _STATE_FIELD_RE.search(assign.line_text)
            ]
            if not resource_assigns and not state_assigns:
                continue
            self._detect_enable_before_bind(index, result, sym, resource_assigns, state_assigns)
            self._detect_disable_leaves_resource(index, result, sym, resource_assigns, state_assigns)
            if len(result.resource_binding_notes) >= 20:
                return

    def _detect_enable_before_bind(self, index, result, sym, resource_assigns, state_assigns):
        if not _name_has_any(sym.name, {"enable", "start", "enter", "resume", "init", "setup"}):
            return
        first_resource = min((assign.line_number for assign in resource_assigns), default=0)
        for state in state_assigns:
            if not re.search(r"\b(?:1|true|TRUE|ON|ACTIVE|READY|ENABLED|POWERED)\b", state.value, re.IGNORECASE):
                continue
            if first_resource and state.line_number < first_resource:
                resource = next((assign for assign in resource_assigns if assign.line_number == first_resource), None)
                result.resource_binding_notes.append(
                    f"{sym.file_path}::{sym.name} line {state.line_number} publishes state "
                    f"`{_line_excerpt(state.line_text)}` before resource binding line {first_resource} "
                    f"`{_line_excerpt(resource.line_text if resource else '')}`."
                )
                self._add_node(index, result, sym)
                return

    def _detect_disable_leaves_resource(self, index, result, sym, resource_assigns, state_assigns):
        if not _name_has_any(sym.name, {"disable", "stop", "clear", "term", "shutdown", "release", "reset"}):
            return
        clears_state = any(_STATE_RESET_RE.search(assign.line_text) for assign in state_assigns)
        if not clears_state or not resource_assigns:
            return
        clears_resource = any(_NULL_CLEAR_RE.search(assign.value) for assign in resource_assigns)
        if clears_resource:
            return
        resources = ", ".join(sorted({token for assign in resource_assigns for token in assign.tokens if token in _RESOURCE_WORDS})[:4])
        result.resource_binding_notes.append(
            f"{sym.file_path}::{sym.name} clears/tears down state but leaves paired resource token(s) "
            f"{resources or 'resource'} without a visible NULL/invalid reset."
        )
        self._add_node(index, result, sym)

    def _detect_resource_validation_order(self, index, result, target_syms):
        liveness_tokens = {"enable", "enabled", "alive", "terminated", "terminating", "stopped", "active"}
        for sym in target_syms:
            name_l = sym.name.lower()
            if not (
                _name_has_any(sym.name, {"assign", "doorbell", "queue", "bind", "map"})
                or "program_cs" in name_l
                or ("program" in name_l and "queue" in name_l)
            ):
                continue
            events = _symbol_event_facts(index, sym)
            binds = [
                event for event in events
                if event.kind == "resource_bind"
                and event.token in {"doorbell", "queue", "gpu_va"}
                and re.search(r"\b(?:doorbell|real|hw|hardware|gpu_va|program|assign|queue)\b", event.line_text, re.IGNORECASE)
            ]
            validations = [
                event for event in events
                if event.kind == "validation" and event.token in liveness_tokens
                and re.search(r"\b(?:enabled?|alive|terminated|terminating|stopped|active)\b", event.line_text, re.IGNORECASE)
            ]
            if binds:
                for bind in binds[:10]:
                    later_validation = next((event for event in validations if event.line_number > bind.line_number), None)
                    prior_final_validation = any(0 <= bind.line_number - event.line_number <= 6 for event in validations)
                    if not later_validation and prior_final_validation:
                        continue
                    validation_text = (
                        f"before final liveness validation line {later_validation.line_number} "
                        f"`{_line_excerpt(later_validation.line_text)}`"
                        if later_validation else "without a nearby queue enabled/alive/not-terminated validation"
                    )
                    result.resource_validation_notes.append(
                        f"{sym.file_path}::{sym.name} line {bind.line_number} binds real resource `{_line_excerpt(bind.line_text)}` "
                        f"{validation_text}."
                    )
                    self._add_node(index, result, sym)
                    if len(result.resource_validation_notes) >= 12:
                        return
            self._detect_doorbell_liveness_order(index, result, sym, liveness_tokens)
            if len(result.resource_validation_notes) >= 12:
                return

    def _detect_doorbell_liveness_order(self, index, result, sym: SymbolDef, liveness_tokens: set[str]):
        name_l = sym.name.lower()
        lines = self._lines(sym)
        body_text = "\n".join(line for _, line in lines)
        if not (
            "doorbell" in body_text.lower()
            and (
                "program_cs" in name_l
                or "assign_user_doorbell" in name_l
                or _name_has_any(sym.name, {"assign", "doorbell", "queue", "program", "bind"})
            )
        ):
            return
        bind_line = next((
            (line_no, line) for line_no, line in lines
            if _DOORBELL_BIND_RE.search(line)
            and not re.search(r"\b(?:if|return|WARN_ON|BUG_ON)\b", line)
            and re.search(r"\b(?:=|assign|program|map|bind|write|doorbell)\b", line, re.IGNORECASE)
        ), None)
        if not bind_line:
            return
        validations = [
            (line_no, line) for line_no, line in lines
            if (
                (_QUEUE_LIVENESS_RE.search(line) or (_fact_tokens(line) & liveness_tokens))
                and re.search(r"\b(?:if|WARN_ON|BUG_ON|return|goto)\b", line)
                and re.search(r"\b(?:queue|doorbell|enabled?|alive|terminat(?:ed|ing)|stopped|active)\b", line, re.IGNORECASE)
            )
        ]
        prior_final = any(0 <= bind_line[0] - line_no <= 8 for line_no, _ in validations)
        later = next(((line_no, line) for line_no, line in validations if line_no > bind_line[0]), None)
        if prior_final and not later:
            return
        validation_text = (
            f"before later liveness predicate line {later[0]} `{_line_excerpt(later[1])}`"
            if later else "without a nearby final queue enabled/alive/not-terminated predicate"
        )
        result.resource_validation_notes.append(
            f"{sym.file_path}::{sym.name} line {bind_line[0]} assigns/programs a real hardware doorbell "
            f"`{_line_excerpt(bind_line[1])}` {validation_text}; a terminated queue can retain stale real-doorbell binding."
        )
        self._add_node(index, result, sym)
        for call in _symbol_calls(index, sym):
            if "doorbell" not in call.lower() and "program_cs" not in call.lower():
                continue
            for helper in index.definitions.get(call, [])[:4]:
                self._add_node(index, result, helper)

    def _detect_async_event_order(self, index, result, target_syms):
        event_family = {"fault", "irq", "interrupt", "event"}
        for sym in target_syms:
            name_tokens = _fact_tokens(sym.name)
            if not (name_tokens & event_family):
                continue
            events = _symbol_event_facts(index, sym)
            clears = [event for event in events if event.kind == "async_clear" and event.token in event_family]
            schedules = [event for event in events if event.kind == "async_schedule" and event.token in event_family]
            if not clears or not schedules:
                continue
            locks = _symbol_locks(index, sym)
            for schedule in schedules[:8]:
                nearby_clears = [
                    clear for clear in clears
                    if abs(clear.line_number - schedule.line_number) <= 16
                    and (clear.token == schedule.token or {clear.token, schedule.token} & {"fault", "irq", "interrupt"})
                ]
                for clear in nearby_clears:
                    start, end = sorted((clear.line_number, schedule.line_number))
                    window = "\n".join(
                        line for line_no, line in self._lines(sym)
                        if start <= line_no <= end + 10
                    )
                    if re.search(r"\b(?:handled|complete|done|processed|synchronize_irq|flush_work|cancel_work_sync)\b", window, re.IGNORECASE):
                        continue
                    if locks and re.search(r"\b(?:mutex_lock|spin_lock)", window):
                        continue
                    if re.search(r"\b(?:pm_runtime|power|clock|clk|regulator)\b", window, re.IGNORECASE):
                        continue
                    result.async_order_notes.append(
                        f"{sym.file_path}::{sym.name} schedules async handling at line {schedule.line_number} "
                        f"`{_line_excerpt(schedule.line_text)}` but clears/acks {clear.token} state at line {clear.line_number} "
                        f"`{_line_excerpt(clear.line_text)}` without visible serialization or handled confirmation."
                    )
                    self._add_node(index, result, sym)
                    if len(result.async_order_notes) >= 12:
                        return

    def _detect_fault_clear_order(self, index, result, target_syms, context):
        context_syms = self._context_symbols(index, context, target_syms)
        workers = [
            sym for sym in context_syms
            if _fact_tokens(sym.name) & {"fault", "work", "worker", "handler", "irq", "interrupt"}
            and "fault" in _fact_tokens(self._body_text(sym)[:8000])
        ][:32]
        for sym in target_syms:
            sym_text = f"{sym.name} {self._body_text(sym)[:16000]}"
            if not (_fact_tokens(sym_text) & {"fault", "irq", "interrupt"}):
                continue
            lines = self._lines(sym)
            clear_line = next(((line_no, line) for line_no, line in lines if _FAULT_CLEAR_RE.search(line)), None)
            if not clear_line:
                continue
            schedule_line = next((
                (line_no, line) for line_no, line in lines
                if line_no >= clear_line[0] - 12
                and line_no <= clear_line[0] + 24
                and _ASYNC_SCHEDULE_RE.search(line)
                and re.search(r"\b(?:fault|irq|interrupt|work|worker)\b", line, re.IGNORECASE)
            ), None)
            worker = next((candidate for candidate in workers if candidate.file_path != sym.file_path), None)
            if not schedule_line and not worker:
                continue
            window = "\n".join(
                line for line_no, line in lines
                if clear_line[0] <= line_no <= min(clear_line[0] + 24, sym.body_end or clear_line[0] + 24)
            )
            if re.search(r"\b(?:fault_handled|handled|processed|complete|flush_work|cancel_work_sync|synchronize_irq)\b", window, re.IGNORECASE):
                continue
            note_tail = (
                f"scheduled async consumer line {schedule_line[0]} `{_line_excerpt(schedule_line[1])}`"
                if schedule_line else f"selected async consumer {worker.file_path}::{worker.name}"
            )
            result.fault_clear_order_notes.append(
                f"{sym.file_path}::{sym.name} line {clear_line[0]} clears/acks fault state "
                f"`{_line_excerpt(clear_line[1])}` before {note_tail} has visible handled confirmation or serialization; "
                "repeated faults can be re-armed before deferred handling drains."
            )
            self._add_node(index, result, sym)
            if worker:
                self._add_node(index, result, worker)
            if len(result.fault_clear_order_notes) >= 8:
                return

    def _detect_stale_tracker_state(self, index, result, target_syms):
        for sym in target_syms:
            events = _symbol_event_facts(index, sym)
            removes = [event for event in events if event.kind == "tracker_remove"]
            invalidates = [event for event in events if event.kind == "tracker_invalidate"]
            if not removes:
                continue
            lines = self._lines(sym)
            for remove in removes[:8]:
                later_invalidate = any(
                    0 < inv.line_number - remove.line_number <= 12 for inv in invalidates
                )
                later_remove = next((event for event in removes if event.line_number > remove.line_number), None)
                if later_invalidate:
                    continue
                stale_state_line = next((
                    (line_no, line) for line_no, line in lines
                    if line_no > remove.line_number
                    and line_no - remove.line_number <= 18
                    and re.search(r"\b(?:start_pfn|inserted|tracker|node|rbtree|rb_node)\b", line, re.IGNORECASE)
                ), None)
                if not stale_state_line and not later_remove:
                    continue
                result.stale_tracker_notes.append(
                    f"{sym.file_path}::{sym.name} line {remove.line_number} removes tracker/tree state "
                    f"`{_line_excerpt(remove.line_text)}` but does not invalidate the inserted/start_pfn marker before "
                    f"{'second remove line ' + str(later_remove.line_number) if later_remove else 'later tracker-state use line ' + str(stale_state_line[0])}."
                )
                self._add_node(index, result, sym)
                if len(result.stale_tracker_notes) >= 12:
                    return

    def _detect_region_replace_erase(self, index, result, target_syms, context):
        context_syms = self._context_symbols(index, context, target_syms)
        free_companion = next((
            sym for sym in context_syms
            if sym.file_path not in {target.file_path for target in target_syms}
            and re.search(r"\b(?:region_refcnt_free|free|release)\b", f"{sym.name} {self._body_text(sym)[:8000]}", re.IGNORECASE)
            and "region" in _fact_tokens(f"{sym.name} {self._body_text(sym)[:4000]}")
        ), None)
        for sym in target_syms:
            body = self._body_text(sym)[:18000]
            if not (_REGION_REPLACE_RE.search(body) and _name_has_any(sym.name, {"region", "remove", "replace", "merge", "insert"})):
                continue
            if not re.search(r"\b(?:ENOMEM|alloc|new|replace|exact|merge|split)\b", body, re.IGNORECASE):
                continue
            lines = self._lines(sym)
            failure = next((
                (line_no, line) for line_no, line in lines
                if re.search(r"\b(?:ENOMEM|ERR_PTR|return\s+-ENOMEM|goto\s+(?:err|fail|out))\b", line, re.IGNORECASE)
            ), None)
            free_line = next((
                (line_no, line) for line_no, line in lines
                if re.search(r"\b(?:region_refcnt_free|kbase_free_alloced_region|free|kfree)\w*\s*\(", line, re.IGNORECASE)
            ), None)
            if not failure or not free_line:
                continue
            path_window = "\n".join(
                line for line_no, line in lines
                if min(failure[0], free_line[0]) <= line_no <= max(failure[0], free_line[0])
            )
            exact_replacement_path = re.search(
                r"\b(?:ENOMEM|replace|replacement|exact|descriptor|alloc|merge)\b",
                path_window,
                re.IGNORECASE,
            )
            path_erase = re.search(
                r"\b(?:rb_erase|list_del|start_pfn\s*=\s*0|rblink.*NULL|RB_CLEAR)\b",
                path_window,
                re.IGNORECASE,
            )
            if path_erase or not exact_replacement_path:
                continue
            result.region_replace_erase_notes.append(
                f"{sym.file_path}::{sym.name} line {failure[0]} enters replacement/failure path "
                f"`{_line_excerpt(failure[1])}`, then line {free_line[0]} frees/removes the region "
                f"`{_line_excerpt(free_line[1])}` without visible rbtree/rblink/start_pfn invalidation on that exact path"
                f"{' before companion free context ' + free_companion.file_path + '::' + free_companion.name if free_companion else ''}."
            )
            self._add_node(index, result, sym)
            if free_companion:
                self._add_node(index, result, free_companion)
            if len(result.region_replace_erase_notes) >= 8:
                return

    def _detect_metadata_type_confusion(self, index, result, target_syms):
        for sym in target_syms:
            direct = self._detect_direct_page_private_metadata_cast(index, result, sym)
            if direct:
                if len(result.metadata_type_confusion_notes) >= 10:
                    return
                continue
            casts = _symbol_cast_facts(index, sym)
            if not casts:
                continue
            lines = self._lines(sym)
            for cast in casts[:8]:
                cast_text = f"{cast.target_type} {cast.source} {cast.line_text} {sym.name}".lower()
                if not ("page_private" in cast_text or "folio_get_private" in cast_text):
                    continue
                if not re.search(r"\b(?:kbase_page_metadata|page_metadata|metadata)\b", cast_text):
                    continue
                deref = next((
                    (line_no, line) for line_no, line in lines
                    if 0 < line_no - cast.line_number <= 10
                    and re.search(r"\b" + re.escape(cast.target) + r"\s*(?:->|\.)", line)
                ), None)
                if not deref:
                    continue
                context_text = "\n".join(
                    line for line_no, line in lines
                    if max(sym.line_number, cast.line_number - 8) <= line_no <= cast.line_number + 14
                ).lower()
                if not re.search(r"\b(?:huge|2mb|2m|migration|recover|recovery|cleanup|metadata|page_private)\b", context_text):
                    continue
                result.metadata_type_confusion_notes.append(
                    f"{sym.file_path}::{sym.name} line {cast.line_number} reinterprets opaque metadata "
                    f"`{_short_expr(cast.source)}` as {cast.target_type}, then dereferences `{cast.target}` at line "
                    f"{deref[0]} `{_line_excerpt(deref[1])}`."
                )
                self._add_node(index, result, sym)
                if len(result.metadata_type_confusion_notes) >= 10:
                    return

    def _detect_direct_page_private_metadata_cast(self, index, result, sym: SymbolDef) -> bool:
        lines = self._lines(sym)
        for line_no, line in lines:
            if not (
                re.search(r"\bpage_private\s*\(", line)
                and re.search(r"\bkbase_page_metadata\b|page_metadata", line)
                and re.search(r"\(\s*(?:struct\s+)?[A-Za-z_]*page_metadata[A-Za-z0-9_\s]*\*", line)
            ):
                continue
            match = re.search(r"(?:struct\s+\w+\s*\*\s*)?(?P<target>[A-Za-z_][A-Za-z0-9_]*)\s*=", line)
            target = match.group("target") if match else ""
            deref = next((
                (later_no, later) for later_no, later in lines
                if 0 < later_no - line_no <= 14
                and target
                and re.search(r"\b" + re.escape(target) + r"\s*(?:->|\.)", later)
            ), None)
            if not deref:
                continue
            context_text = "\n".join(
                later for later_no, later in lines
                if max(sym.line_number, line_no - 10) <= later_no <= line_no + 18
            )
            if not re.search(r"\b(?:huge|2mb|2m|migration|recover|recovery|dma_addr_t|page_private|compound)\b", context_text, re.IGNORECASE):
                continue
            result.metadata_type_confusion_notes.append(
                f"{sym.file_path}::{sym.name} line {line_no} casts opaque page_private metadata "
                f"`{_line_excerpt(line)}` to page metadata and dereferences `{target}` at line "
                f"{deref[0]} `{_line_excerpt(deref[1])}` without proving the private value has that type."
            )
            self._add_node(index, result, sym)
            return True
        return False

    def _detect_pm_runtime_sequence(self, index, result, target_syms):
        for sym in target_syms:
            events = _symbol_event_facts(index, sym)
            sensitive = [event for event in events if event.kind == "pm_sensitive_action"]
            runtime_gets = [event for event in events if event.kind == "pm_runtime_get"]
            if not sensitive:
                continue
            first_get = min((event.line_number for event in runtime_gets), default=0)
            name_l = sym.name.lower()
            pm_name = _name_has_any(sym.name, {"pm", "power", "runtime", "clock", "clk", "resume", "gpu"})
            power_control = [
                event for event in sensitive
                if re.search(r"\b(?:enable_gpu_power_control|disable_gpu_power_control)\s*\(", event.line_text)
            ]
            if "runtime_on" in name_l or ("runtime" in name_l and "resume" in name_l):
                duplicate_enable = [event for event in power_control if "enable_gpu_power_control" in event.line_text]
                if len(duplicate_enable) >= 1 and not _symbol_locks(index, sym):
                    event = duplicate_enable[0]
                    result.pm_sequence_notes.append(
                        f"{sym.file_path}::{sym.name} line {event.line_number} changes GPU power-control state "
                        f"`{_line_excerpt(event.line_text)}` in runtime-on callback without visible runtime PM serialization/ownership."
                    )
                    self._add_node(index, result, sym)
                    if len(result.pm_sequence_notes) >= 12:
                        return
                    continue
            if "runtime_off" in name_l or ("runtime" in name_l and "suspend" in name_l):
                disable = [event for event in power_control if "disable_gpu_power_control" in event.line_text]
                enable = [event for event in power_control if "enable_gpu_power_control" in event.line_text]
                if enable or (len(disable) > 1 and not _symbol_locks(index, sym)):
                    event = (enable or disable)[0]
                    result.pm_sequence_notes.append(
                        f"{sym.file_path}::{sym.name} line {event.line_number} performs power-control transition "
                        f"`{_line_excerpt(event.line_text)}` in runtime-off path without a balanced serialized runtime ownership pair."
                    )
                    self._add_node(index, result, sym)
                    if len(result.pm_sequence_notes) >= 12:
                        return
                    continue
            for action in sensitive[:8]:
                if first_get and first_get < action.line_number:
                    continue
                if not pm_name:
                    continue
                result.pm_sequence_notes.append(
                    f"{sym.file_path}::{sym.name} line {action.line_number} performs runtime-PM-sensitive action "
                    f"`{_line_excerpt(action.line_text)}` before a visible successful pm_runtime_get/resume ownership point."
                )
                self._add_node(index, result, sym)
                if len(result.pm_sequence_notes) >= 12:
                    return

    def _detect_pm_callback_order(self, index, result, target_syms):
        power_owner = [
            sym for sym in target_syms
            if re.search(r"pm_callback_power_(?:on|off)", sym.name, re.IGNORECASE)
            and re.search(r"\b(?:enable_gpu_power_control|disable_gpu_power_control)\s*\(", self._body_text(sym), re.IGNORECASE)
        ]
        for sym in target_syms:
            name_l = sym.name.lower()
            if not (
                "pm_callback" in name_l
                or ("runtime" in name_l and ("on" in name_l or "off" in name_l or "resume" in name_l or "suspend" in name_l))
                or ("power" in name_l and ("on" in name_l or "off" in name_l))
            ):
                continue
            lines = self._lines(sym)
            runtime_get = next(((line_no, line) for line_no, line in lines if _PM_RUNTIME_API_RE.search(line)), None)
            runtime_put = next((
                (line_no, line) for line_no, line in lines
                if re.search(r"\b(?:pm_runtime_put|pm_runtime_put_sync|pm_runtime_put_autosuspend)\w*\s*\(", line)
            ), None)
            power_lines = [
                (line_no, line) for line_no, line in lines
                if re.search(r"\b(?:enable_gpu_power_control|disable_gpu_power_control)\s*\(", line)
            ]
            if not power_lines:
                continue
            first_power = power_lines[0]
            if "runtime" in name_l and power_owner:
                owner_names = ", ".join(f"{owner.file_path}::{owner.name}" for owner in power_owner[:2])
                result.pm_callback_order_notes.append(
                    f"{sym.file_path}::{sym.name} line {first_power[0]} performs runtime-callback GPU power-control "
                    f"`{_line_excerpt(first_power[1])}` while power callback path(s) {owner_names} also own "
                    "GPU power-control transitions; this creates an extra unsynchronized runtime power-control path."
                )
                self._add_node(index, result, sym)
                for owner in power_owner[:2]:
                    self._add_node(index, result, owner)
                if len(result.pm_callback_order_notes) >= 8:
                    return
                continue
            if "enable_gpu_power_control" in first_power[1] and (not runtime_get or first_power[0] < runtime_get[0]):
                result.pm_callback_order_notes.append(
                    f"{sym.file_path}::{sym.name} line {first_power[0]} enables GPU power control "
                    f"`{_line_excerpt(first_power[1])}` before a visible successful runtime-PM ownership point"
                    f"{' line ' + str(runtime_get[0]) + ' `' + _line_excerpt(runtime_get[1]) + '`' if runtime_get else ''}."
                )
                self._add_node(index, result, sym)
                if len(result.pm_callback_order_notes) >= 8:
                    return
                continue
            if "runtime" in name_l and ("off" in name_l or "suspend" in name_l):
                disable_count = sum(1 for _, line in power_lines if "disable_gpu_power_control" in line)
                enable_count = sum(1 for _, line in power_lines if "enable_gpu_power_control" in line)
                if enable_count or (disable_count > 1 and not _symbol_locks(index, sym)):
                    result.pm_callback_order_notes.append(
                        f"{sym.file_path}::{sym.name} has runtime-off power-control sequence "
                        f"`{_line_excerpt(first_power[1])}` without a balanced serialized runtime ownership pair"
                        f"{' around line ' + str(runtime_put[0]) if runtime_put else ''}."
                    )
                    self._add_node(index, result, sym)
                    if len(result.pm_callback_order_notes) >= 8:
                        return

    def _detect_secondary_element_omission(self, index, result, target_syms):
        for sym in target_syms:
            if not _name_has_any(sym.name, {"slot", "atom", "job", "sched", "queue"}):
                continue
            if self._detect_head_next_priority_omission(index, result, sym):
                if len(result.secondary_omission_notes) >= 8:
                    return
                continue
            events = _symbol_event_facts(index, sym)
            firsts = [event for event in events if event.kind == "slot_first"]
            seconds = [event for event in events if event.kind == "slot_second"]
            skips = [event for event in events if event.kind == "slot_skip"]
            if not firsts or not skips:
                continue
            for first in firsts[:6]:
                skip = next((event for event in skips if 0 < event.line_number - first.line_number <= 24), None)
                if not skip:
                    continue
                has_second_before_skip = any(first.line_number < event.line_number < skip.line_number for event in seconds)
                has_second_after = any(0 < event.line_number - skip.line_number <= 24 for event in seconds)
                if has_second_before_skip or not has_second_after:
                    continue
                result.secondary_omission_notes.append(
                    f"{sym.file_path}::{sym.name} processes first slot/atom at line {first.line_number}, then priority branch "
                    f"line {skip.line_number} `{_line_excerpt(skip.line_text)}` can leave before second slot/atom handling."
                )
                self._add_node(index, result, sym)
                if len(result.secondary_omission_notes) >= 8:
                    return

    def _detect_head_next_priority_omission(self, index, result, sym: SymbolDef) -> bool:
        body = self._body_text(sym)[:16000]
        if not re.search(r"\b(?:JS_HEAD|HEAD_NEXT|head_next|slot|soft_hard_stop|reset|stop)\b", f"{sym.name} {body}", re.IGNORECASE):
            return False
        if not re.search(r"\b(?:prio|priority)\b", body, re.IGNORECASE):
            return False
        lines = self._lines(sym)
        head_line = next(((line_no, line) for line_no, line in lines if re.search(r"\b(?:JS_HEAD|head)\b", line, re.IGNORECASE)), None)
        next_line = next(((line_no, line) for line_no, line in lines if re.search(r"\b(?:JS_HEAD_NEXT|HEAD_NEXT|next)\b", line, re.IGNORECASE)), None)
        skip_line = next((
            (line_no, line) for line_no, line in lines
            if re.search(r"\b(?:prio|priority)\b", line, re.IGNORECASE)
            and re.search(r"\b(?:return|continue|break|goto)\b|!=|<|>", line)
        ), None)
        if not head_line or not skip_line:
            return False
        if next_line and next_line[0] < skip_line[0]:
            return False
        result.secondary_omission_notes.append(
            f"{sym.file_path}::{sym.name} processes job-slot head at line {head_line[0]} "
            f"`{_line_excerpt(head_line[1])}`, then priority branch line {skip_line[0]} "
            f"`{_line_excerpt(skip_line[1])}` can leave before JS_HEAD_NEXT/next-atom handling"
            f"{' at line ' + str(next_line[0]) if next_line else ''}."
        )
        self._add_node(index, result, sym)
        return True

    def _detect_zero_count_underflow(self, index, result, target_syms):
        for sym in target_syms:
            body_tokens = _fact_tokens(f"{sym.name} {sym.signature} {self._body_text(sym)[:12000]}")
            if not (body_tokens & {"count", "nr", "num"} and body_tokens & {"jit", "id", "dup", "alloc", "scan"}):
                continue
            lines = self._lines(sym)
            for idx, (line_no, line) in enumerate(lines):
                if not _ZERO_COUNT_UNDERFLOW_RE.search(line):
                    continue
                line_tokens = _fact_tokens(line)
                if not (line_tokens & {"count", "nr", "num", "id", "dup", "duplicate"}):
                    continue
                prior = "\n".join(txt for _, txt in lines[max(0, idx - 12):idx])
                if re.search(r"\b(?:count|nr|num)\s*(?:==|<=)\s*0\b|\b!\s*(?:count|nr|num)\b", prior):
                    continue
                result.zero_count_underflow_notes.append(
                    f"{sym.file_path}::{sym.name} line {line_no} uses reverse/count-derived index "
                    f"`{_line_excerpt(line)}` without a nearby zero-count guard, so count==0 can underflow the scan."
                )
                self._add_node(index, result, sym)
                if len(result.zero_count_underflow_notes) >= 8:
                    return

    def _detect_owner_liveness_allocation(self, index, result, target_syms):
        for sym in target_syms:
            text = f"{sym.name} {sym.signature} {self._body_text(sym)[:18000]}"
            if not re.search(r"\b(?:mem_pool|pool|grow|alloc_pages)\b", text, re.IGNORECASE):
                continue
            if not (_POOL_ALLOC_RE.search(text) and re.search(r"\b(?:for|while|do\s*\{)\b", text)):
                continue
            if not re.search(r"\b(?:kctx|current|task|process|user|oom|dying|worker|workqueue|owner)\b", text, re.IGNORECASE):
                continue
            if _OWNER_LIVENESS_RE.search(text):
                continue
            lines = self._lines(sym)
            alloc_line = next(((line_no, line) for line_no, line in lines if _POOL_ALLOC_RE.search(line)), None)
            loop_line = next((
                (line_no, line) for line_no, line in lines
                if re.search(r"\b(?:for|while|do)\b", line)
                and re.search(r"\b(?:page|pool|alloc|grow)\b", line, re.IGNORECASE)
            ), None)
            if not alloc_line:
                continue
            result.owner_liveness_notes.append(
                f"{sym.file_path}::{sym.name} line {alloc_line[0]} performs page/pool allocation "
                f"`{_line_excerpt(alloc_line[1])}` in a growth/allocation loop without a visible owner-task "
                f"exiting/OOM/fatal-signal bailout"
                f"{' near loop line ' + str(loop_line[0]) + ' `' + _line_excerpt(loop_line[1]) + '`' if loop_line else ''}."
            )
            self._add_node(index, result, sym)
            if len(result.owner_liveness_notes) >= 8:
                return

    def _detect_user_buffer_permission(self, index, result, target_syms):
        for sym in target_syms:
            text = f"{sym.name} {sym.signature} {self._body_text(sym)[:18000]}"
            if not (_USER_BUFFER_RE.search(text) and _GUP_RE.search(text) and _GPU_WRITE_FLAG_RE.search(text)):
                continue
            if not _name_has_any(sym.name, {"user", "buffer", "import", "from_user", "mem"}):
                continue
            lines = self._lines(sym)
            gup_line = next(((line_no, line) for line_no, line in lines if _GUP_RE.search(line)), None)
            flag_line = next(((line_no, line) for line_no, line in lines if _GPU_WRITE_FLAG_RE.search(line)), None)
            if not gup_line:
                continue
            prior = "\n".join(line for line_no, line in lines if line_no <= gup_line[0])
            has_cpu_write_gate = re.search(
                r"\b(?:KBASE_REG_CPU_WR|CPU_WR|FOLL_WRITE|writeable|writable|VM_WRITE)\b",
                prior,
                re.IGNORECASE,
            )
            has_gpu_only_gate = re.search(r"\b(?:KBASE_REG_GPU_WR|GPU_WR|gpu_wr|GPU.*WRITE)\b", prior, re.IGNORECASE)
            if has_cpu_write_gate and not has_gpu_only_gate:
                continue
            result.user_buffer_permission_notes.append(
                f"{sym.file_path}::{sym.name} line {gup_line[0]} pins/imports USER_BUFFER pages "
                f"`{_line_excerpt(gup_line[1])}` while permission logic uses GPU-write semantics"
                f"{' at line ' + str(flag_line[0]) + ' `' + _line_excerpt(flag_line[1]) + '`' if flag_line else ''}; "
                "the target path lacks a clear CPU-write/FOLL_WRITE provenance gate before user pages become writable."
            )
            self._add_node(index, result, sym)
            if len(result.user_buffer_permission_notes) >= 8:
                return

    def _detect_zone_shrink_validation(self, index, result, target_syms):
        for sym in target_syms:
            text = f"{sym.name} {sym.signature} {self._body_text(sym)[:18000]}"
            if not _ZONE_SHRINK_RE.search(text):
                continue
            if not re.search(r"\b(?:init_jit|init_exec|region_tracker_init|jit|exec|zone)\b", text, re.IGNORECASE):
                continue
            if not re.search(r"\b(?:shrink|split|resize|trim|replace)\b", text, re.IGNORECASE):
                continue
            if re.search(r"\b(?:entire(?:ly)?\s+free|fully\s+free|zone.*free.*check|overlap.*check|is_region_free)\b", text, re.IGNORECASE):
                continue
            lines = self._lines(sym)
            shrink_line = next((
                (line_no, line) for line_no, line in lines
                if re.search(r"\b(?:shrink|split|resize|trim|replace|zone)\b", line, re.IGNORECASE)
            ), None)
            if not shrink_line:
                continue
            imported_context = re.search(r"\b(?:imported|dma_buf|user_buffer|same_va|overlap|mapping)\b", text, re.IGNORECASE)
            result.zone_shrink_notes.append(
                f"{sym.file_path}::{sym.name} line {shrink_line[0]} shrinks/splits an existing VA zone "
                f"`{_line_excerpt(shrink_line[1])}` without a visible validation that the source zone is still entirely free"
                f"{' while imported/user-buffer overlap tokens are in scope' if imported_context else ''}."
            )
            self._add_node(index, result, sym)
            if len(result.zone_shrink_notes) >= 8:
                return

    def _detect_success_path_cleanup(self, index, result, target_syms):
        for sym in target_syms:
            text = f"{sym.name} {sym.signature} {self._body_text(sym)[:18000]}"
            if not (re.search(r"\breq_arr\b", text) and _SUCCESS_FD_RE.search(text)):
                continue
            lines = self._lines(sym)
            alloc_line = next((
                (line_no, line) for line_no, line in lines
                if re.search(r"\breq_arr\b", line)
                and re.search(r"\b(?:alloc|calloc|kmalloc|kcalloc|kvmalloc|vzalloc)\b", line)
            ), None)
            fd_line = next(((line_no, line) for line_no, line in lines if re.search(r"\banon_inode_getfd\s*\(", line)), None)
            if not alloc_line or not fd_line:
                continue
            return_line = next((
                (line_no, line) for line_no, line in lines
                if line_no > fd_line[0]
                and line_no - fd_line[0] <= 24
                and re.search(r"\breturn\s+(?:fd|ret|[A-Za-z_][A-Za-z0-9_]*)\b", line)
            ), None)
            if not return_line:
                continue
            between = "\n".join(line for line_no, line in lines if fd_line[0] <= line_no <= return_line[0])
            if re.search(r"\b(?:kfree|kvfree|vfree|free)\s*\(\s*req_arr\b|goto\s+free_buf", between):
                continue
            result.success_path_cleanup_notes.append(
                f"{sym.file_path}::{sym.name} allocates temporary `req_arr` at line {alloc_line[0]} "
                f"`{_line_excerpt(alloc_line[1])}`, then success path line {return_line[0]} "
                f"`{_line_excerpt(return_line[1])}` returns after anon_inode_getfd line {fd_line[0]} without freeing it."
            )
            self._add_node(index, result, sym)
            if len(result.success_path_cleanup_notes) >= 8:
                return

    def _detect_jit_lock_protocol(self, index, result, target_syms, context):
        context_syms = self._context_symbols(index, context, target_syms)
        target_uniques = {_symbol_unique_name(target) for target in target_syms}
        jit_companions = [
            sym for sym in context_syms
            if _symbol_unique_name(sym) not in target_uniques
            and _JIT_STATE_RE.search(f"{sym.name} {self._body_text(sym)[:8000]}")
        ][:40]
        for sym in target_syms:
            text = f"{sym.name} {sym.signature} {self._body_text(sym)[:18000]}"
            if not _JIT_STATE_RE.search(text):
                continue
            if not re.search(r"\b(?:allocate|alloc|free|process|finish|allow)\b", text, re.IGNORECASE):
                continue
            if not re.search(r"\b(?:list_add|list_del|limit|usage|count|evict|pool|alloc)\b", text, re.IGNORECASE):
                continue
            locks = _symbol_locks(index, sym)
            has_jit_lock = any(
                re.search(r"\b(?:jit|kctx|ctx|csf).*(?:lock|mutex)|(?:lock|mutex).*(?:jit|kctx|ctx|csf)\b", lock)
                for lock in locks
            )
            if has_jit_lock:
                continue
            companion = next((
                candidate for candidate in jit_companions
                if bool(re.search(r"\bfree\b", candidate.name, re.IGNORECASE)) != bool(re.search(r"\bfree\b", sym.name, re.IGNORECASE))
            ), jit_companions[0] if jit_companions else None)
            state_line = next((
                (line_no, line) for line_no, line in self._lines(sym)
                if re.search(r"\b(?:jit|list_add|list_del|limit|usage|alloc|free|evict)\b", line, re.IGNORECASE)
            ), None)
            if not state_line:
                continue
            result.jit_lock_protocol_notes.append(
                f"{sym.file_path}::{sym.name} line {state_line[0]} updates shared JIT state "
                f"`{_line_excerpt(state_line[1])}` without a visible context-wide JIT lock"
                f"{' while companion path ' + companion.file_path + '::' + companion.name + ' also mutates JIT state' if companion else ''}."
            )
            self._add_node(index, result, sym)
            if companion:
                self._add_node(index, result, companion)
            if len(result.jit_lock_protocol_notes) >= 8:
                return

    def _detect_teardown_order(self, index, result, target_syms, context):
        context_syms = self._context_symbols(index, context, target_syms)
        schedule_companion = next((
            sym for sym in context_syms
            if re.search(
                r"\b(?:schedule_out|sched.*out|disable.*as|as.*disable|address.*space)\b",
                f"{sym.name} {self._body_text(sym)[:8000]}",
                re.IGNORECASE,
            )
        ), None)
        for sym in target_syms:
            text = f"{sym.name} {sym.signature} {self._body_text(sym)[:18000]}"
            if not _TEARDOWN_ORDER_RE.search(text):
                continue
            if not re.search(r"\b(?:term|teardown|destroy|free|release|region_tracker|mmu)\b", text, re.IGNORECASE):
                continue
            lines = self._lines(sym)
            free_line = next((
                (line_no, line) for line_no, line in lines
                if re.search(r"\b(?:region_tracker_term|kbase_mmu_term|free.*region|kbase_free_alloced_region|rb_erase|mmu.*term)\b", line, re.IGNORECASE)
            ), None)
            if not free_line:
                continue
            schedule_line = next((
                (line_no, line) for line_no, line in lines
                if re.search(r"\b(?:schedule_out|sched.*out|disable.*as|as.*disable|mmu_disable|address.*space)\b", line, re.IGNORECASE)
            ), None)
            if schedule_line and schedule_line[0] < free_line[0]:
                continue
            result.teardown_order_notes.append(
                f"{sym.file_path}::{sym.name} line {free_line[0]} tears down VA/MMU resources "
                f"`{_line_excerpt(free_line[1])}` before a visible schedule-out/address-space-disable point"
                f"{' (later line ' + str(schedule_line[0]) + ' `' + _line_excerpt(schedule_line[1]) + '`)' if schedule_line else ''}"
                f"{' shown in companion ' + schedule_companion.file_path + '::' + schedule_companion.name if schedule_companion and not schedule_line else ''}."
            )
            self._add_node(index, result, sym)
            if schedule_companion:
                self._add_node(index, result, schedule_companion)
            if len(result.teardown_order_notes) >= 8:
                return

    def _detect_queue_publish_init(self, index, result, target_syms):
        for sym in target_syms:
            text = f"{sym.name} {sym.signature} {self._body_text(sym)[:18000]}"
            if not (_QUEUE_PUBLISH_RE.search(text) and _name_has_any(sym.name, {"queue", "new", "create", "alloc"})):
                continue
            lines = self._lines(sym)
            publish_line = next((
                (line_no, line) for line_no, line in lines
                if _QUEUE_PUBLISH_RE.search(line)
                and re.search(r"\b(?:=|set_bit|bitmap_set|atomic_set)\b", line)
            ), None)
            if not publish_line:
                continue
            fail_line = next((
                (line_no, line) for line_no, line in lines
                if line_no > publish_line[0]
                and line_no - publish_line[0] <= 90
                and _ERROR_PATH_RE.search(line)
            ), None)
            if not fail_line:
                continue
            unwind = "\n".join(line for line_no, line in lines if publish_line[0] < line_no < fail_line[0])
            if re.search(r"\b(?:clear_bit|bitmap_clear|array.*=\s*NULL|in_use.*=\s*0|queue.*=\s*NULL)\b", unwind, re.IGNORECASE):
                continue
            result.queue_publish_init_notes.append(
                f"{sym.file_path}::{sym.name} line {publish_line[0]} publishes queue pointer/in-use state "
                f"`{_line_excerpt(publish_line[1])}` before full initialization; failure path line {fail_line[0]} "
                f"`{_line_excerpt(fail_line[1])}` lacks visible pointer/bit rollback."
            )
            self._add_node(index, result, sym)
            if len(result.queue_publish_init_notes) >= 8:
                return

    def _detect_fd_reuse_race(self, index, result, target_syms):
        for sym in target_syms:
            text = f"{sym.name} {sym.signature} {self._body_text(sym)[:18000]}"
            if not re.search(r"\b(?:sync_fence|fence|fd)\b", text, re.IGNORECASE):
                continue
            if not (_SUCCESS_FD_RE.search(text) and re.search(r"\b(?:fd_install|copy_to_user|return\s+fd|put_user)\b", text, re.IGNORECASE)):
                continue
            lines = self._lines(sym)
            publish_line = next((
                (line_no, line) for line_no, line in lines
                if re.search(r"\b(?:fd_install|copy_to_user|put_user|return\s+fd)\b", line, re.IGNORECASE)
            ), None)
            lookup_line = next((
                (line_no, line) for line_no, line in lines
                if publish_line
                and line_no > publish_line[0]
                and re.search(r"\b(?:sync_fence_fdget|fdget|fget)\s*\(", line)
            ), None)
            if not publish_line or not lookup_line:
                continue
            result.fd_reuse_notes.append(
                f"{sym.file_path}::{sym.name} publishes fd at line {publish_line[0]} "
                f"`{_line_excerpt(publish_line[1])}`, then re-looks up an fd at line {lookup_line[0]} "
                f"`{_line_excerpt(lookup_line[1])}`; descriptor reuse can bind later trigger/cleanup to the wrong fence."
            )
            self._add_node(index, result, sym)
            if len(result.fd_reuse_notes) >= 8:
                return

    def _detect_debugfs_permission(self, index, result, target_syms):
        for sym in target_syms:
            text = f"{sym.name} {sym.signature} {self._body_text(sym)[:18000]}"
            if not _DEBUGFS_AUTH_RE.search(text):
                continue
            if not re.search(r"\b(?:debugfs|timeline|tlstream|profil)\b", text, re.IGNORECASE):
                continue
            lines = self._lines(sym)
            create_line = next((
                (line_no, line) for line_no, line in lines
                if re.search(r"\bdebugfs_create_file\s*\(", line)
                and re.search(r"\b(?:0444|S_IRUGO|S_IROTH|S_IRUSR\s*\|\s*S_IRGRP\s*\|\s*S_IROTH)\b", line)
            ), None)
            acquire_line = next((
                (line_no, line) for line_no, line in lines
                if re.search(r"\b(?:\w*timeline_io_acquire|tlstream\w*|profil\w*)\s*\(", line, re.IGNORECASE)
            ), None)
            if not create_line and not acquire_line:
                continue
            prior = "\n".join(line for line_no, line in lines if not acquire_line or line_no <= acquire_line[0])
            if re.search(r"\b(?:capable|ptrace_may_access|uid_eq|permission|0600|S_IWUSR)\b", prior, re.IGNORECASE):
                continue
            line_no, line = acquire_line or create_line
            result.debugfs_permission_notes.append(
                f"{sym.file_path}::{sym.name} line {line_no} exposes/acquires debugfs profiling stream "
                f"`{_line_excerpt(line)}` without a visible capability/owner permission check on the target path."
            )
            self._add_node(index, result, sym)
            if len(result.debugfs_permission_notes) >= 8:
                return

    def _detect_interprocedural_cleanup_ledger(self, index, result, target_syms, context):
        context_syms = self._context_symbols(index, context, target_syms)
        related = [
            sym for sym in context_syms
            if _name_has_any(sym.name, {"suspend", "drain", "delete", "cleanup", "release", "queue", "group", "kcpu"})
        ][:80]
        acquire_tokens: set[str] = set()
        acquire_sites: dict[str, SymbolDef] = {}
        for sym in related:
            for fact in _symbol_cleanup_facts(index, sym):
                fact_tokens = _fact_tokens(f"{fact.resource} {fact.line_text} {sym.name}")
                if fact.kind == "acquire" and (
                    fact_tokens & {"pages", "page", "mapping", "refcount", "groups", "suspend", "cqs_wait", "group_suspend"}
                    or re.search(r"\b(?:kbase_mem_phy_alloc_kernel_unmapped|get_page|pin_user_pages|alloc_pages)\b", fact.line_text)
                ):
                    for token in fact_tokens & (_RESOURCE_WORDS | {"pages", "mapping", "refcount", "groups", "suspend", "cqs_wait", "group_suspend"}):
                        acquire_tokens.add(token)
                        acquire_sites.setdefault(token, sym)
        if not acquire_tokens:
            return
        for sym in target_syms:
            if not _name_has_any(sym.name, {"suspend", "drain", "delete", "cleanup", "release", "queue", "group", "kcpu"}):
                continue
            body = self._body_text(sym)[:16000]
            branch_tokens = _fact_tokens(body) & {"drain_queue", "drain", "suspend", "group_suspend", "cqs_wait", "groups", "pages", "mapping"}
            if not branch_tokens and not re.search(r"\b(?:GROUP_SUSPEND|CQS_WAIT|drain_queue|delete_queue|kcpu_queue_process)\b", body):
                continue
            facts = _symbol_cleanup_facts(index, sym)
            releases = [fact for fact in facts if fact.kind == "release"]
            exits = [fact for fact in facts if fact.kind == "exit"]
            if not exits or not branch_tokens:
                continue
            for token in sorted(acquire_tokens & (branch_tokens | {"pages", "mapping", "groups"}))[:6]:
                matching_release = any(
                    token in _fact_tokens(rel.resource + " " + rel.line_text)
                    or re.search(r"\b(?:put_page|kbase_mem_phy_alloc_put|free_pages|unmap)\b", rel.line_text)
                    for rel in releases
                )
                if matching_release:
                    continue
                exit_fact = exits[0]
                result.cleanup_ledger_notes.append(
                    f"{sym.file_path}::{sym.name} participates in branch-specific {token}/suspend/drain cleanup but exit line "
                    f"{exit_fact.line_number} `{_line_excerpt(exit_fact.line_text)}` has no visible release/rollback "
                    f"for related {token} resources acquired in selected companion path "
                    f"{acquire_sites.get(token).file_path + '::' + acquire_sites.get(token).name if acquire_sites.get(token) else '(unknown)'}."
                )
                self._add_node(index, result, sym)
                if acquire_sites.get(token):
                    self._add_node(index, result, acquire_sites[token])
                if len(result.cleanup_ledger_notes) >= 10:
                    return

    def _detect_suspend_cleanup_ledger(self, index, result, target_syms, context):
        context_syms = self._context_symbols(index, context, target_syms)
        target_files = {sym.file_path for sym in target_syms}
        sources = []
        sinks = []
        for sym in context_syms:
            body = self._body_text(sym)[:16000]
            text = f"{sym.name} {sym.signature} {body}"
            tokens = _fact_tokens(text)
            if (
                {"suspend", "queue", "group"} & tokens
                and _SUSPEND_SOURCE_RE.search(text)
                and re.search(r"\b(?:get_user_pages|pin_user_pages|normal_suspend_buf|sus_buf|nr_pages|PFN_UP)\b", text)
            ):
                sources.append(sym)
            if (
                {"suspend", "queue", "group", "drain"} & tokens
                and re.search(r"\b(?:drain_queue|GROUP_SUSPEND|CQS_WAIT|delete|cleanup|release|kcpu|wait)\b", text, re.IGNORECASE)
            ):
                sinks.append(sym)
        if not sources or not sinks:
            return
        sinks = sorted(sinks[:40], key=lambda sym: (
            0 if _name_has_any(sym.name, {"delete", "drain", "process", "kcpu", "cleanup"}) else 1,
            sym.file_path,
            sym.line_number,
        ))
        for sink in sinks[:24]:
            sink_body = self._body_text(sink)[:16000]
            branch_line = next((
                (line_no, line) for line_no, line in self._lines(sink)
                if re.search(r"\b(?:drain_queue|GROUP_SUSPEND|CQS_WAIT|delete_queue|kcpu_queue_process|delete|cleanup|release|wait)\b", line)
            ), None)
            if not branch_line:
                continue
            sink_lines = self._lines(sink)
            branch_window = "\n".join(
                line for line_no, line in sink_lines
                if branch_line[0] <= line_no <= branch_line[0] + 70
            )
            if _SUSPEND_RELEASE_RE.search(branch_window):
                continue
            branch_tokens = _fact_tokens(f"{sink.name} {branch_line[1]} {sink_body[:4000]}")
            if not (
                branch_tokens & {"drain_queue", "drain", "group_suspend", "cqs_wait", "suspend", "queue", "wait"}
                or re.search(r"\b(?:GROUP_SUSPEND|CQS_WAIT|drain_queue|delete_queue|kcpu_queue_process)\b", branch_window)
            ):
                continue
            for source in sources[:24]:
                if _symbol_unique_name(source) == _symbol_unique_name(sink):
                    continue
                source_tokens = _fact_tokens(f"{source.name} {self._body_text(source)[:6000]}")
                sink_tokens = _fact_tokens(f"{sink.name} {sink_body}")
                if not (source_tokens & sink_tokens & {"suspend", "queue", "group", "pages", "buf"}):
                    continue
                if source.file_path not in target_files and sink.file_path not in target_files:
                    continue
                result.suspend_cleanup_ledger_notes.append(
                    f"{sink.file_path}::{sink.name} line {branch_line[0]} owns branch-specific suspend cleanup "
                    f"`{_line_excerpt(branch_line[1])}` for resources prepared in "
                    f"{source.file_path}::{source.name}, but the selected drain/CQS/GROUP_SUSPEND delete path has no visible "
                    "put_page/unpin_user_pages/kbase_mem_phy_alloc_put/kbase_mem_phy_alloc_kernel_unmapped release."
                )
                self._add_node(index, result, sink)
                self._add_node(index, result, source)
                if len(result.suspend_cleanup_ledger_notes) >= 10:
                    return
                break

    def _detect_suspend_size_sink(self, index, result, target_syms, context):
        context_syms = self._context_symbols(index, context, target_syms)
        target_files = {sym.file_path for sym in target_syms}
        consumers = []
        for sym in context_syms:
            for line_no, line in self._lines(sym):
                if not re.search(
                    r"\b(?:PFN_UP|PFN_DOWN|DIV_ROUND_UP|normal_suspend_buf|sus_buf|nr_pages|phy\s*\[|copy|"
                    r"group_copy_suspend_buf|suspend_buf)\b",
                    line,
                    re.IGNORECASE,
                ):
                    continue
                tokens = _fact_tokens(f"{sym.name} {line}")
                if tokens & {"suspend", "buf", "pages", "size", "queue", "group"}:
                    consumers.append((sym, line_no, line))
        if not consumers:
            return
        consumers = sorted(consumers, key=lambda item: (
            0 if re.search(r"\b(?:group_copy_suspend_buf|normal_suspend_buf|PFN_UP|phy\s*\[)\b", f"{item[0].name} {item[2]}", re.IGNORECASE) else 1,
            item[0].file_path,
            item[1],
        ))
        for producer in context_syms:
            if producer.file_path not in target_files and not _name_has_any(producer.name, {"suspend", "queue", "group"}):
                continue
            assigns = _symbol_assignments(index, producer)
            guards = _symbol_guards(index, producer)
            for assign in assigns[:80]:
                assign_text = f"{assign.target} {assign.value} {assign.line_text}"
                assign_tokens = _fact_tokens(assign_text)
                if not (
                    assign_tokens & {"suspend", "sus", "buf", "size", "nr", "pages"}
                    and re.search(r"\b(?:sus_buf|suspend_buf|normal_suspend_buf|nr_pages|size|end_addr)\b", assign_text)
                ):
                    continue
                if self._has_size_upper_bound_guard(guards, assign.line_number, assign_tokens):
                    continue
                for consumer, consumer_line, consumer_text in consumers[:40]:
                    consumer_tokens = _fact_tokens(f"{consumer.name} {consumer_text}")
                    if not (assign_tokens & consumer_tokens & {"suspend", "buf", "size", "pages", "nr", "group"}):
                        continue
                    if producer.file_path not in target_files and consumer.file_path not in target_files:
                        continue
                    exact_page_array_sink = bool(
                        re.search(r"(PFN_UP|normal_suspend_buf|phy\s*\[)", consumer_text, re.IGNORECASE)
                    )
                    result.suspend_size_sink_notes.append(
                        f"{producer.file_path}::{producer.name} line {assign.line_number} propagates suspend size/page "
                        f"state `{_line_excerpt(assign.line_text)}` without a visible upper bound; "
                        f"{consumer.file_path}::{consumer.name} later consumes the derived suspend extent at line "
                        f"{consumer_line} `{_line_excerpt(consumer_text)}`"
                        f"{' using PFN_UP/normal_suspend_buf.phy-style page-array indexing' if exact_page_array_sink else ''}."
                    )
                    self._add_node(index, result, producer)
                    self._add_node(index, result, consumer)
                    if len(result.suspend_size_sink_notes) >= 10:
                        return
                    break

    def _detect_size_propagation(self, index, result, target_syms, context):
        context_syms = self._context_symbols(index, context, target_syms)
        consumers = []
        for sym in context_syms:
            if sym in target_syms:
                continue
            for use in _symbol_copy_uses(index, sym):
                tokens = _fact_tokens(use.size_expr + " " + use.line_text)
                if tokens & {"size", "pages", "nr", "count", "len"}:
                    consumers.append((sym, use.line_number, use.size_expr, use.line_text))
            for formula in _symbol_formula_facts(index, sym):
                if set(formula.tokens) & {"size", "pages", "nr", "count", "len"}:
                    consumers.append((sym, formula.line_number, formula.expr, formula.line_text))
        if not consumers:
            return
        for sym in target_syms:
            assignments = _symbol_assignments(index, sym)
            guards = _symbol_guards(index, sym)
            for assign in assignments[:60]:
                tokens = set(assign.tokens) | _fact_tokens(assign.target + " " + assign.value)
                if not (tokens & {"size", "pages", "nr", "count", "len"} and tokens & {"sus", "suspend", "buffer", "buf", "pages"}):
                    continue
                if self._has_size_upper_bound_guard(guards, assign.line_number, tokens):
                    continue
                companion = next((item for item in consumers if tokens & _fact_tokens(item[2] + " " + item[3])), None)
                if not companion:
                    continue
                comp_sym, line_no, expr, line_text = companion
                result.size_propagation_notes.append(
                    f"{sym.file_path}::{sym.name} line {assign.line_number} propagates user-controlled size/page state "
                    f"`{_line_excerpt(assign.line_text)}` without an upper-bound/consistency check; companion "
                    f"{comp_sym.file_path}::{comp_sym.name} later consumes `{_short_expr(expr)}` at line {line_no} "
                    f"`{_line_excerpt(line_text)}`."
                )
                self._add_node(index, result, sym)
                self._add_node(index, result, comp_sym)
                if len(result.size_propagation_notes) >= 10:
                    return

    def _has_size_upper_bound_guard(self, guards: list[GuardFact], line_number: int, tokens: set[str]) -> bool:
        wanted = tokens & (_COUNT_SIZE_WORDS | {"pages", "size", "len", "count", "nr"})
        for guard in guards:
            if guard.line_number > line_number:
                continue
            if line_number - guard.line_number > 24:
                continue
            if guard.token in wanted and guard.op in {"<", "<=", ">", ">="}:
                return True
        return False

    def _detect_alias_size_chain(self, index, result, target_syms, context):
        context_syms = self._context_symbols(index, context, target_syms)
        companion_consumers = []
        for sym in context_syms:
            for formula in _symbol_formula_facts(index, sym):
                formula_tokens = set(formula.tokens) | _fact_tokens(formula.expr + " " + formula.target)
                if {"alias", "pages", "region"} & formula_tokens:
                    companion_consumers.append((sym, formula))
            for use in _symbol_copy_uses(index, sym):
                use_tokens = _fact_tokens(use.size_expr + " " + use.line_text)
                if {"alias", "pages", "region"} & use_tokens:
                    companion_consumers.append((sym, use))
        for sym in target_syms:
            if "alias" not in _fact_tokens(sym.name + " " + sym.signature):
                continue
            formulas = _symbol_formula_facts(index, sym)
            guards = _symbol_guards(index, sym)
            producer = next((
                formula for formula in formulas
                if {"nents", "stride"} <= (_fact_tokens(formula.expr) | set(formula.tokens))
                and "mul" in formula.operators
            ), None)
            if not producer:
                continue
            if self._has_formula_consistency_guard(guards, producer, producer.line_number + 20):
                continue
            consumer = next((
                item for item in companion_consumers
                if item[0] is not sym
                and {"alias", "pages", "region", "gpu_va"} & _fact_tokens(getattr(item[1], "expr", getattr(item[1], "size_expr", "")) + " " + getattr(item[1], "line_text", ""))
            ), None)
            if not consumer:
                continue
            consumer_sym, consumer_fact = consumer
            consumer_expr = getattr(consumer_fact, "expr", getattr(consumer_fact, "size_expr", ""))
            result.arithmetic_chain_notes.append(
                f"{sym.file_path}::{sym.name} line {producer.line_number} computes alias extent `{producer.target} = {_short_expr(producer.expr)}` "
                "from nents*stride without an overflow/consistency guard; companion "
                f"{consumer_sym.file_path}::{consumer_sym.name} later consumes alias region/page extent "
                f"`{_short_expr(consumer_expr)}` at line {consumer_fact.line_number}."
            )
            self._add_node(index, result, sym)
            self._add_node(index, result, consumer_sym)
            if len(result.arithmetic_chain_notes) >= 16:
                return

    def _detect_alias_extent_mismatch(self, index, result, target_syms, context):
        context_syms = self._context_symbols(index, context, target_syms)
        consumers = []
        for sym in context_syms:
            for line_no, line in self._lines(sym):
                if not re.search(r"\b(?:alias|gpu_va|region|num_pages|nr_pages|va_pages|map|mmap|insert)\b", line, re.IGNORECASE):
                    continue
                tokens = _fact_tokens(f"{sym.name} {line}")
                if tokens & {"alias", "region", "pages", "gpu_va"}:
                    consumers.append((sym, line_no, line))
        if not consumers:
            return
        for sym in target_syms:
            sym_text = f"{sym.name} {sym.signature} {self._body_text(sym)[:16000]}"
            if "alias" not in _fact_tokens(sym_text):
                continue
            formulas = _symbol_formula_facts(index, sym)
            guards = _symbol_guards(index, sym)
            extent = next((
                formula for formula in formulas
                if "mul" in formula.operators
                and {"nents", "stride"} <= (_fact_tokens(formula.expr) | set(formula.tokens))
            ), None)
            extent_line = None
            if not extent:
                extent_line = next((
                    (line_no, line) for line_no, line in self._lines(sym)
                    if re.search(r"\b(?:num_pages|nr_pages|va_pages|extent|size)\b", line, re.IGNORECASE)
                    and re.search(r"\bnents\b", line, re.IGNORECASE)
                    and re.search(r"\bstride\b", line, re.IGNORECASE)
                    and "*" in line
                ), None)
            if not extent and not extent_line:
                continue
            extent_number = extent.line_number if extent else extent_line[0]
            extent_text = extent.line_text if extent else extent_line[1]
            if extent and self._has_formula_consistency_guard(guards, extent, extent.line_number + 24):
                continue
            reservation = next((
                formula for formula in formulas
                if formula.line_number > extent_number
                and {"pages", "region", "gpu_va"} & (set(formula.tokens) | _fact_tokens(formula.target))
                and (not extent or formula.normalized != extent.normalized)
            ), None)
            consumer = next((
                item for item in consumers
                if item[0].file_path == sym.file_path or _module_stem(item[0].name) == _module_stem(sym.name)
            ), None) or (consumers[0] if consumers else None)
            if not consumer:
                continue
            consumer_sym, consumer_line, consumer_text = consumer
            result.alias_extent_mismatch_notes.append(
                f"{sym.file_path}::{sym.name} line {extent_number} derives alias extent "
                f"`{_line_excerpt(extent_text)}` from nents*stride without a visible overflow/"
                f"consistency guard; "
                f"{'reservation line ' + str(reservation.line_number) + ' `' + _line_excerpt(reservation.line_text) + '` and ' if reservation else ''}"
                f"{consumer_sym.file_path}::{consumer_sym.name} consumes alias region/page extent at line "
                f"{consumer_line} `{_line_excerpt(consumer_text)}`."
            )
            self._add_node(index, result, sym)
            self._add_node(index, result, consumer_sym)
            if len(result.alias_extent_mismatch_notes) >= 8:
                return

    def _detect_info_leaks(self, index, result, target_syms):
        reporter_notes = []
        for sym in target_syms:
            if not re.search(r"\b(?:report_bus_fault|bus_fault|fault_and_kill)\b", sym.name, re.IGNORECASE):
                continue
            for line_no, line in self._lines(sym):
                if not (_LOG_CALL_RE.search(line) and _BUS_FAULT_REPORT_RE.search(f"{sym.name} {line}")):
                    continue
                if not (_SENSITIVE_FORMAT_RE.search(line) or re.search(r"\b(?:PA|phys|physical|fault->addr|fault\.addr)\b", line)):
                    continue
                reporter_notes.append((
                    sym,
                    f"{sym.file_path}::{sym.name} line {line_no} logs hardware-supplied bus-fault physical address "
                    f"`{_line_excerpt(line)}`; bus/cacheability/shareability fault reporters should not expose PA/fault->addr."
                ))
        if reporter_notes:
            for sym, note in reporter_notes[:8]:
                result.info_leak_notes.append(note)
                self._add_node(index, result, sym)
            return
        for sym in target_syms:
            for line_no, line in self._lines(sym):
                if not _LOG_CALL_RE.search(line):
                    continue
                if not _SENSITIVE_TOKEN_RE.search(line):
                    continue
                if not (_SENSITIVE_FORMAT_RE.search(line) or "phys" in line.lower() or "token" in line.lower() or "secret" in line.lower()):
                    continue
                result.info_leak_notes.append(
                    f"{sym.file_path}::{sym.name} line {line_no} logs sensitive-looking data `{_line_excerpt(line)}`."
                )
                self._add_node(index, result, sym)

    def _detect_format_wrappers(self, index, result, target_syms, target_prefixes):
        wrappers: dict[str, SymbolDef] = {}
        target_dir = str(Path(target_syms[0].file_path).parent).replace("\\", "/") if target_syms else ""
        for sym in _security_symbol_candidates(index):
            same_module = (
                sym.file_path == (target_syms[0].file_path if target_syms else "")
                or str(Path(sym.file_path).parent).replace("\\", "/") == target_dir
                or _module_stem(sym.name) in target_prefixes
            )
            if not same_module and not _name_has_any(sym.name, {"log", "debug", "trace"}):
                continue
            signature = sym.signature.lower()
            if not re.search(r"(const\s+char\s*\*\s*(?:fmt|format|msg)|char\s*\*\s*(?:fmt|format|msg))", signature):
                continue
            body = self._body_text(sym)
            if not _VARIADIC_WRAPPER_RE.search(body):
                continue
            if not re.search(r"\b(?:fmt|format|msg)\b", body):
                continue
            wrappers[sym.name] = sym
            result.format_notes.append(
                f"{sym.file_path}::{sym.name} wraps a variable format parameter and calls printf-family output."
            )
            self._add_node(index, result, sym)
        return wrappers

    def _detect_target_calls_wrappers(self, index, result, target_syms, wrappers):
        if not wrappers:
            return
        for sym in target_syms:
            for line_no, line in self._lines(sym):
                for wrapper_name, wrapper_sym in wrappers.items():
                    if not re.search(r"\b" + re.escape(wrapper_name) + r"\s*\(", line):
                        continue
                    args = _first_call_args(line, wrapper_name)
                    if not args or _is_string_literal(args[0]):
                        continue
                    result.format_notes.append(
                        f"{sym.file_path}::{sym.name} line {line_no} passes non-literal `{args[0]}` "
                        f"to variadic format wrapper {wrapper_sym.file_path}::{wrapper_sym.name}."
                    )
                    self._add_node(index, result, sym)
                    self._add_node(index, result, wrapper_sym)

    def _detect_fops(self, index, result, target_file, target_names):
        for g in index.globals:
            text = g.initializer
            lower = text.lower()
            refs = set(g.referenced_functions)
            if g.file_path != target_file and not refs & target_names:
                continue
            if "file_operations" not in lower and "fops" not in lower and ".release" not in lower:
                continue
            has_open = ".open" in lower
            has_release = ".release" in lower
            has_activity = any(token in lower for token in (".poll", ".ioctl", ".read", ".write"))
            has_flush = ".flush" in lower
            if has_open and has_release and has_activity and not has_flush:
                result.fops_notes.append(
                    f"{g.file_path}::{g.name} line {g.line_number} has open/release plus poll/ioctl/read/write but no .flush."
                )
                result.globals.append(g)
                for ref in g.referenced_functions:
                    for sym in index.definitions.get(ref, [])[:4]:
                        self._add_node(index, result, sym)

    def _detect_lock_order(self, index, result, syms, target_file):
        edges: dict[tuple[str, str], list[tuple[SymbolDef, int]]] = defaultdict(list)
        for sym in syms:
            held: list[str] = []
            for line_no, line in self._lines(sym):
                for match in _LOCK_CALL_RE.finditer(line):
                    lock = _normalise_lock_expr(match.group("arg"))
                    if not lock:
                        continue
                    if _UNLOCK_WORD_RE.search(match.group("fn")):
                        if lock in held:
                            held.remove(lock)
                        continue
                    for prior in held:
                        if prior != lock:
                            edges[(prior, lock)].append((sym, line_no))
                    if lock not in held:
                        held.append(lock)
        seen = set()
        for (a, b), first_edges in edges.items():
            reverse_edges = edges.get((b, a))
            if not reverse_edges:
                continue
            for sym_a, line_a in first_edges:
                for sym_b, line_b in reverse_edges:
                    if sym_a.name == sym_b.name and sym_a.file_path == sym_b.file_path:
                        continue
                    if sym_a.file_path != target_file and sym_b.file_path != target_file:
                        continue
                    key = tuple(sorted((f"{sym_a.file_path}::{sym_a.name}", f"{sym_b.file_path}::{sym_b.name}", a, b)))
                    if key in seen:
                        continue
                    seen.add(key)
                    result.lock_order_notes.append(
                        f"{a}->{b}: {sym_a.file_path}::{sym_a.name} line {line_a}; "
                        f"{b}->{a}: {sym_b.file_path}::{sym_b.name} line {line_b}."
                    )
                    self._add_node(index, result, sym_a)
                    self._add_node(index, result, sym_b)
                    if len(result.lock_order_notes) >= 20:
                        return

    def _detect_cross_file_lock_cycles(self, index, result, context, target_file):
        syms = self._context_symbols(index, context, _symbols_for_file(index, target_file))
        edge_map: dict[tuple[str, str], list[LockOrderEdge]] = defaultdict(list)
        for sym in syms:
            for edge in _symbol_lock_edges(index, sym):
                if not self._lock_edge_is_specific(edge):
                    continue
                edge_map[(edge.first_lock, edge.second_lock)].append(edge)
        for edge in self._interprocedural_lock_edges(index, syms):
            if not self._lock_edge_is_specific(edge):
                continue
            edge_map[(edge.first_lock, edge.second_lock)].append(edge)
        if not edge_map:
            return
        seen = set()
        for (a, b), forward_edges in edge_map.items():
            reverse_edges = edge_map.get((b, a), [])
            for e1 in forward_edges:
                for e2 in reverse_edges:
                    if not self._cross_file_cycle_is_relevant(e1, e2, target_file):
                        continue
                    if not self._lock_cycle_has_async_or_named_path(index, [e1, e2]):
                        continue
                    key = tuple(sorted((
                        f"{e1.file_path}:{e1.function_name}:{e1.first_lock}>{e1.second_lock}",
                        f"{e2.file_path}:{e2.function_name}:{e2.first_lock}>{e2.second_lock}",
                    )))
                    if key in seen:
                        continue
                    seen.add(key)
                    result.cross_file_lock_notes.append(self._lock_cycle_note(index, [e1, e2], target_file))
                    self._add_edge_nodes(index, result, [e1, e2])
                    if len(result.cross_file_lock_notes) >= 16:
                        return
        locks = sorted({lock for edge in edge_map for lock in edge})[:24]
        for a in locks:
            for b in locks:
                if b == a:
                    continue
                for c in locks:
                    if c in {a, b}:
                        continue
                    if not (edge_map.get((a, b)) and edge_map.get((b, c)) and edge_map.get((c, a))):
                        continue
                    for e1 in edge_map[(a, b)]:
                        for e2 in edge_map[(b, c)]:
                            for e3 in edge_map[(c, a)]:
                                if not self._cross_file_cycle_is_relevant(e1, e2, target_file, extra=e3):
                                    continue
                                if not self._lock_cycle_has_async_or_named_path(index, [e1, e2, e3]):
                                    continue
                                key = tuple(sorted((
                                    f"{e1.file_path}:{e1.function_name}:{e1.first_lock}>{e1.second_lock}",
                                    f"{e2.file_path}:{e2.function_name}:{e2.first_lock}>{e2.second_lock}",
                                    f"{e3.file_path}:{e3.function_name}:{e3.first_lock}>{e3.second_lock}",
                                )))
                                if key in seen:
                                    continue
                                seen.add(key)
                                result.cross_file_lock_notes.append(self._lock_cycle_note(index, [e1, e2, e3], target_file))
                                self._add_edge_nodes(index, result, [e1, e2, e3])
                                if len(result.cross_file_lock_notes) >= 16:
                                    return

    def _detect_named_lock_inversion(self, index, result, context, target_file):
        syms = self._context_symbols(index, context, _symbols_for_file(index, target_file))
        edge_map: dict[tuple[str, str], list[LockOrderEdge]] = defaultdict(list)
        for sym in syms:
            for edge in _symbol_lock_edges(index, sym):
                if not self._lock_edge_is_specific(edge):
                    continue
                if not self._named_lock_edge(edge):
                    continue
                edge_map[(edge.first_lock, edge.second_lock)].append(edge)
        for edge in self._interprocedural_lock_edges(index, syms[:120]):
            if not self._lock_edge_is_specific(edge):
                continue
            if not self._named_lock_edge(edge):
                continue
            edge_map[(edge.first_lock, edge.second_lock)].append(edge)
        seen = set()
        for (first, second), forward in edge_map.items():
            reverse = edge_map.get((second, first), [])
            if not reverse:
                continue
            for e1 in forward[:8]:
                for e2 in reverse[:8]:
                    if not self._cross_file_cycle_is_relevant(e1, e2, target_file):
                        continue
                    if not self._lock_cycle_has_async_or_named_path(index, [e1, e2]):
                        continue
                    key = tuple(sorted((
                        f"{e1.file_path}:{e1.function_name}:{e1.first_lock}>{e1.second_lock}",
                        f"{e2.file_path}:{e2.function_name}:{e2.first_lock}>{e2.second_lock}",
                    )))
                    if key in seen:
                        continue
                    seen.add(key)
                    result.named_lock_inversion_notes.append(
                        f"Named lock inversion: target/companion paths acquire {e1.first_lock}->{e1.second_lock} "
                        f"in {e1.file_path}::{e1.function_name} line {e1.line_number} and "
                        f"{e2.first_lock}->{e2.second_lock} in {e2.file_path}::{e2.function_name} line {e2.line_number}; "
                        "callback/notifier/backend context is present in the selected lock path."
                    )
                    self._add_edge_nodes(index, result, [e1, e2])
                    if len(result.named_lock_inversion_notes) >= 8:
                        return

    def _cross_file_cycle_is_relevant(self, first: LockOrderEdge, second: LockOrderEdge, target_file: str, *, extra: LockOrderEdge | None = None) -> bool:
        edges = [first, second] + ([extra] if extra else [])
        files = {edge.file_path for edge in edges}
        if target_file not in files or len(files) < 2:
            return False
        return any(edge.file_path == target_file for edge in edges)

    def _lock_edge_is_specific(self, edge: LockOrderEdge) -> bool:
        generic = {"lock", "mutex", "spinlock", "ctx.lock", "queue.lock"}
        return (
            edge.first_lock
            and edge.second_lock
            and edge.first_lock != edge.second_lock
            and edge.first_lock not in generic
            and edge.second_lock not in generic
        )

    def _named_lock_edge(self, edge: LockOrderEdge) -> bool:
        text = f"{edge.first_lock} {edge.second_lock} {edge.function_name} {edge.line_text}".lower()
        return bool(re.search(r"\b(?:hwaccess|clk|clock|rtm|hwcnt|backend|state|fw|mmu|scheduler)\b", text))

    def _lock_cycle_has_async_or_named_path(self, index: SymbolIndex, edges: list[LockOrderEdge]) -> bool:
        text = " ".join(
            f"{edge.file_path} {edge.function_name} {edge.line_text} {edge.first_lock} {edge.second_lock}"
            for edge in edges
        ).lower()
        has_async = bool(re.search(r"\b(?:callback|notifier|notify|clock|clk|hwcnt|counter|backend|irq|interrupt|work)\b", text))
        has_named_lock = bool(re.search(r"\b(?:hwaccess|clk|clock|hwcnt|backend|state|ctx|rtm)\b", text))
        for edge in edges:
            sym = _lookup_symbol(index, edge.file_path, edge.function_name)
            meta = index.meta_by_symbol.get(_symbol_unique_name(sym)) if sym else None
            if meta and (meta.has_callback_words or meta.has_notifier_words):
                has_async = True
        return has_async and has_named_lock

    def _lock_cycle_note(self, index: SymbolIndex, edges: list[LockOrderEdge], target_file: str) -> str:
        parts = []
        async_hint = False
        for edge in edges:
            sym = _lookup_symbol(index, edge.file_path, edge.function_name)
            meta = index.meta_by_symbol.get(_symbol_unique_name(sym)) if sym else None
            async_hint = async_hint or bool(meta and (meta.has_callback_words or meta.has_notifier_words))
            role = "target" if edge.file_path == target_file else "companion"
            parts.append(
                f"{edge.first_lock}->{edge.second_lock} in {role} "
                f"{edge.file_path}::{edge.function_name} line {edge.line_number}"
            )
        suffix = " Callback/notifier/asynchronous linkage is present." if async_hint else ""
        return "Cross-file lock cycle candidate: " + "; ".join(parts) + "." + suffix

    def _add_edge_nodes(self, index: SymbolIndex, result: PartialDetectorResult, edges: list[LockOrderEdge]):
        for edge in edges:
            self._add_node(index, result, _lookup_symbol(index, edge.file_path, edge.function_name))

    def _interprocedural_lock_edges(self, index: SymbolIndex, syms: list[SymbolDef]) -> list[LockOrderEdge]:
        selected_by_name: dict[str, list[SymbolDef]] = defaultdict(list)
        selected_unique = {_symbol_unique_name(sym) for sym in syms}
        for sym in syms:
            selected_by_name[sym.name].append(sym)
        edges: list[LockOrderEdge] = []
        for sym in syms:
            held: list[str] = []
            for line_no, line in self._lines(sym):
                for match in _LOCK_CALL_RE.finditer(line):
                    lock = _normalise_lock_expr(match.group("arg"))
                    if not lock:
                        continue
                    if _UNLOCK_WORD_RE.search(match.group("fn")):
                        if lock in held:
                            held.remove(lock)
                    elif lock not in held:
                        held.append(lock)
                if not held:
                    continue
                for call in _CALL_RE.findall(line):
                    if call in _CONTROL_CALLS:
                        continue
                    for callee in selected_by_name.get(call, [])[:4]:
                        if _symbol_unique_name(callee) not in selected_unique:
                            continue
                        callee_locks = _symbol_locks(index, callee)
                        for held_lock in held:
                            for callee_lock in sorted(callee_locks)[:4]:
                                if held_lock == callee_lock:
                                    continue
                                edges.append(LockOrderEdge(
                                    first_lock=held_lock,
                                    second_lock=callee_lock,
                                    file_path=sym.file_path,
                                    function_name=sym.name,
                                    line_number=line_no,
                                    line_text=f"{_line_excerpt(line)} -> {callee.file_path}::{callee.name}",
                                ))
        return edges[:160]

    def _detect_stale_after_unlock(self, index, result, target_syms):
        for sym in target_syms:
            held = False
            cached_vars: dict[str, tuple[int, str]] = {}
            for line_no, line in self._lines(sym):
                if _LOCK_CALL_RE.search(line) and not _UNLOCK_WORD_RE.search(line):
                    held = True
                if held:
                    match = _ASSIGN_FROM_FIELD_RE.search(line)
                    if match:
                        cached_vars[match.group("var")] = (line_no, line)
                if _LOCK_CALL_RE.search(line) and _UNLOCK_WORD_RE.search(line):
                    held = False
                    continue
                if held:
                    continue
                for var, (assign_line, assign_text) in list(cached_vars.items()):
                    if line_no <= assign_line + 1:
                        continue
                    if re.search(r"\b" + re.escape(var) + r"\b", line):
                        result.stale_after_unlock_notes.append(
                            f"{sym.file_path}::{sym.name} caches `{_line_excerpt(assign_text)}` under lock at line {assign_line}, "
                            f"then uses {var} after unlock at line {line_no}: `{_line_excerpt(line)}`."
                        )
                        self._add_node(index, result, sym)
                        cached_vars.pop(var, None)

    def _detect_disable_stale(self, index, result, target_syms):
        for sym in target_syms:
            if not _DISABLE_NAME_RE.search(sym.name):
                continue
            body = self._body_text(sym)
            if not _DISABLE_STATE_RE.search(body):
                continue
            lower = body.lower()
            stale_bits = []
            if "doorbell" in lower and "invalid" not in lower:
                stale_bits.append("doorbell")
            if "pending" in lower and not re.search(r"pending\s*=\s*0", lower):
                stale_bits.append("pending")
            if ("callback" in lower or "work" in lower or "timer" in lower) and not _CANCEL_OR_REF_RE.search(lower):
                stale_bits.append("callback/work/timer")
            if not stale_bits:
                continue
            result.disable_stale_notes.append(
                f"{sym.file_path}::{sym.name} disables state but does not clear {', '.join(stale_bits)}."
            )
            self._add_node(index, result, sym)

    def _detect_callback_lifetime(self, index, result, target_syms, target_prefixes):
        for sym in target_syms:
            body = self._body_text(sym)
            if not _CALLBACK_STORE_RE.search(body):
                continue
            if _CANCEL_OR_REF_RE.search(body):
                continue
            note_line = next((item for item in self._lines(sym) if _CALLBACK_STORE_RE.search(item[1])), None)
            if not note_line:
                continue
            result.callback_lifetime_notes.append(
                f"{sym.file_path}::{sym.name} line {note_line[0]} stores object/context pointer `{_line_excerpt(note_line[1])}` "
                "without nearby refcount, unregister, cancel, or clear evidence."
            )
            self._add_node(index, result, sym)
            for candidate in self._paired_lifecycle_symbols(index, sym.name, target_prefixes, {"destroy", "release", "term", "shutdown", "disable"}):
                self._add_node(index, result, candidate)

    def _detect_state_transition_protocol(self, index, result, target_syms, context, target_file):
        context_syms = self._context_symbols(index, context, target_syms)
        companions = [sym for sym in context_syms if sym.file_path != target_file]
        companion_by_token: dict[str, list[SymbolDef]] = defaultdict(list)
        for sym in companions:
            for token in _symbol_state_tokens(index, sym):
                companion_by_token[token].append(sym)

        for sym in target_syms:
            tokens = _symbol_state_tokens(index, sym)
            if not tokens & (_WAIT_ACK_TOKENS | _TRANSITION_TOKENS | _SUBSYSTEM_TOKENS):
                continue
            self._detect_wait_ack_without_verify(index, result, sym, companions)
            self._detect_protocol_lock_mismatch(index, result, sym, companion_by_token)
            if len(result.protocol_notes) >= 24:
                return

    def _detect_wait_ack_without_verify(self, index, result, sym: SymbolDef, companions: list[SymbolDef]):
        tokens = _symbol_state_tokens(index, sym)
        if not (tokens & _WAIT_ACK_TOKENS):
            return
        if not (tokens & (_STATE_VERIFY_TOKENS | _SUBSYSTEM_TOKENS)):
            return
        lines = self._lines(sym)
        for idx, (line_no, line) in enumerate(lines):
            lower = line.lower()
            if not any(token in lower for token in _WAIT_ACK_TOKENS):
                continue
            later = "\n".join(txt for _, txt in lines[idx + 1:idx + 16])
            later_tokens = set(_protocol_tokens_from_text(later))
            if (later_tokens and (_STATE_VERIFY_TOKENS & later_tokens)) or self._has_state_verify_guard_after(index, sym, line_no):
                continue
            companion = self._best_protocol_companion(index, sym, companions)
            note = (
                f"{sym.file_path}::{sym.name} line {line_no} waits for ack/event `{_line_excerpt(line)}` "
                "without a nearby final active/protected/ready state verification."
            )
            if companion:
                note += f" Companion transition context: {companion.file_path}::{companion.name}."
                self._add_node(index, result, companion)
            result.protocol_notes.append(note)
            self._add_node(index, result, sym)
            return

    def _has_state_verify_guard_after(self, index, sym: SymbolDef, line_number: int) -> bool:
        for guard in _symbol_guards(index, sym):
            if guard.line_number <= line_number:
                continue
            if guard.line_number - line_number > 18:
                continue
            if guard.token in _STATE_VERIFY_TOKENS:
                return True
        return False

    def _detect_protocol_lock_mismatch(self, index, result, sym: SymbolDef, companion_by_token: dict[str, list[SymbolDef]]):
        tokens = _symbol_state_tokens(index, sym)
        if not (tokens & (_TRANSITION_TOKENS | _SUBSYSTEM_TOKENS)):
            return
        target_locks = _symbol_locks(index, sym)
        checked = 0
        for token in sorted(tokens & (_TRANSITION_TOKENS | _SUBSYSTEM_TOKENS)):
            for companion in companion_by_token.get(token, [])[:10]:
                if companion.file_path == sym.file_path:
                    continue
                companion_locks = _symbol_locks(index, companion)
                if not companion_locks:
                    continue
                if target_locks & companion_locks:
                    continue
                if not self._same_protocol_area(sym, companion):
                    continue
                missing = ", ".join(sorted(companion_locks)[:3])
                result.protocol_notes.append(
                    f"{sym.file_path}::{sym.name} shares `{token}` transition/protocol state with "
                    f"{companion.file_path}::{companion.name}, but target-side lock coverage "
                    f"{sorted(target_locks)[:3] or ['(none)']} does not match companion lock(s) {missing}."
                )
                self._add_node(index, result, sym)
                self._add_node(index, result, companion)
                checked += 1
                if checked >= 4:
                    return

    def _best_protocol_companion(self, index, sym: SymbolDef, companions: list[SymbolDef]) -> SymbolDef | None:
        sym_tokens = _symbol_state_tokens(index, sym)
        candidates = []
        for companion in companions:
            overlap = len(sym_tokens & _symbol_state_tokens(index, companion))
            if not overlap:
                continue
            score = overlap
            if str(Path(companion.file_path).parent) == str(Path(sym.file_path).parent):
                score += 3
            if _module_stem(companion.name) == _module_stem(sym.name):
                score += 2
            if _symbol_locks(index, companion):
                score += 2
            candidates.append((-score, companion.file_path, companion.line_number, companion.name, companion))
        return sorted(candidates, key=lambda item: item[:-1])[0][-1] if candidates else None

    def _same_protocol_area(self, a: SymbolDef, b: SymbolDef) -> bool:
        dir_a = str(Path(a.file_path).parent).replace("\\", "/")
        dir_b = str(Path(b.file_path).parent).replace("\\", "/")
        if dir_a == dir_b or dir_a.startswith(dir_b) or dir_b.startswith(dir_a):
            return True
        stem_a = _module_stem(a.name)
        stem_b = _module_stem(b.name)
        return bool(stem_a and stem_b and (stem_a.startswith(stem_b) or stem_b.startswith(stem_a)))

    def _detect_protected_mmu_protocol(self, index, result, target_syms, context):
        context_syms = self._context_symbols(index, context, target_syms)
        target_uniques = {_symbol_unique_name(target) for target in target_syms}
        companion_mmu = [
            sym for sym in context_syms
            if _symbol_unique_name(sym) not in target_uniques
            and (
                "mmu" in _symbol_state_tokens(index, sym)
                or re.search(r"\bmmu_hw_mutex|mmu.*lock|hw_mutex\b", self._body_text(sym)[:8000], re.IGNORECASE)
            )
            and (
                any(self._is_mmu_serialization_lock(lock) for lock in _symbol_locks(index, sym))
                or re.search(r"\bmmu_hw_mutex|mmu.*lock|hw_mutex\b", self._body_text(sym)[:8000], re.IGNORECASE)
            )
        ][:40]
        if not companion_mmu:
            return
        for sym in target_syms:
            name_l = sym.name.lower()
            if "exit" in name_l or "leave" in name_l:
                continue
            if not (
                "protm" in name_l
                or "protected" in name_l
                or "wait_protected_mode_enter" in name_l
                or "protected_mode_enter" in name_l
                or "scheduler_group_check_protm_enter" in name_l
            ):
                continue
            tokens = _symbol_state_tokens(index, sym)
            body = self._body_text(sym)[:16000]
            if not ({"protected", "protm"} & (tokens | _fact_tokens(body))):
                continue
            events = _symbol_event_facts(index, sym)
            waits = [event for event in events if event.kind == "protected_wait"]
            wait_line = None
            if waits:
                wait_line = (waits[0].line_number, waits[0].line_text)
            else:
                wait_line = next((
                    (line_no, line) for line_no, line in self._lines(sym)
                    if re.search(r"\b(?:wait.*protected|protected.*wait|ack|completion|event|fence)\b", line, re.IGNORECASE)
                ), None)
            if not wait_line:
                continue
            verifies = [event for event in events if event.kind == "protected_verify"]
            sym_locks = _symbol_locks(index, sym)
            companion = self._best_protocol_companion(index, sym, companion_mmu) or companion_mmu[0]
            if not self._same_protocol_area(sym, companion):
                continue
            companion_locks = set(_symbol_locks(index, companion))
            if re.search(r"\bmmu_hw_mutex\b", self._body_text(companion)[:8000], re.IGNORECASE):
                companion_locks.add("mmu_hw_mutex")
            mmu_locks = {lock for lock in companion_locks if self._is_mmu_serialization_lock(lock)}
            missing_mmu_lock = bool(mmu_locks and not (sym_locks & mmu_locks))
            missing_verify = not any(0 < verify.line_number - wait_line[0] <= 24 for verify in verifies)
            if not missing_verify:
                later = "\n".join(line for line_no, line in self._lines(sym) if wait_line[0] < line_no <= wait_line[0] + 24)
                missing_verify = not re.search(r"\b(?:protected|protm)[A-Za-z0-9_]*(?:->|\.)?(?:active|entered|enabled|state)\b", later, re.IGNORECASE)
            if not (missing_mmu_lock and missing_verify):
                continue
            result.protected_mmu_notes.append(
                f"{sym.file_path}::{sym.name} line {wait_line[0]} enters/waits for protected mode "
                f"`{_line_excerpt(wait_line[1])}` while companion MMU path {companion.file_path}::{companion.name} "
                f"uses MMU serialization lock(s) {', '.join(sorted(mmu_locks)[:3])}; target lock coverage "
                f"{sorted(sym_locks)[:3] or ['(none)']} and final protected-active verification are insufficient."
            )
            self._add_node(index, result, sym)
            self._add_node(index, result, companion)
            if len(result.protected_mmu_notes) >= 8:
                return

    def _detect_active_singleton_stale(self, index, result, target_syms, context):
        context_syms = self._context_symbols(index, context, target_syms)
        fault_companion = next((
            sym for sym in context_syms
            if sym.file_path not in {target.file_path for target in target_syms}
            and _fact_tokens(f"{sym.name} {self._body_text(sym)[:8000]}") & {"protected", "fault", "protm"}
        ), None)
        for sym in target_syms:
            body = self._body_text(sym)[:16000]
            if not _ACTIVE_SINGLETON_RE.search(body):
                continue
            if not re.search(r"\b(?:remove|free|release|timeout|stop|teardown|destroy|fault|runnable)\b", f"{sym.name} {body}", re.IGNORECASE):
                continue
            lines = self._lines(sym)
            singleton_line = next(((line_no, line) for line_no, line in lines if _ACTIVE_SINGLETON_RE.search(line)), None)
            if not singleton_line:
                continue
            clears_singleton = any(
                _ACTIVE_SINGLETON_RE.search(line)
                and re.search(r"=\s*(?:NULL|nullptr|0)\b|clear|reset", line, re.IGNORECASE)
                for _, line in lines
            )
            if clears_singleton:
                continue
            teardown_line = next((
                (line_no, line) for line_no, line in lines
                if line_no >= singleton_line[0]
                and re.search(r"\b(?:remove|free|release|timeout|stop|destroy|fault)\w*\b", line, re.IGNORECASE)
            ), singleton_line)
            result.active_singleton_stale_notes.append(
                f"{sym.file_path}::{sym.name} line {singleton_line[0]} references active protected singleton "
                f"`{_line_excerpt(singleton_line[1])}`, but teardown/removal path line {teardown_line[0]} "
                f"`{_line_excerpt(teardown_line[1])}` does not visibly clear it before later protected/fault use"
                f"{' in ' + fault_companion.file_path + '::' + fault_companion.name if fault_companion else ''}."
            )
            self._add_node(index, result, sym)
            if fault_companion:
                self._add_node(index, result, fault_companion)
            if len(result.active_singleton_stale_notes) >= 8:
                return

    def _is_mmu_serialization_lock(self, lock: str) -> bool:
        lock_l = str(lock or "").lower()
        return bool(re.search(r"\bmmu\b|mmu_.*mutex|hw_mutex|mmu\.lock|mmu_lock", lock_l))

    def _detect_mmu_recovery_rollback(self, index, result, target_syms, context):
        context_syms = self._context_symbols(index, context, target_syms)
        for sym in target_syms:
            name_tokens = _fact_tokens(sym.name)
            if not ({"mmu", "recovery", "rollback", "insert"} & name_tokens):
                continue
            body = self._body_text(sym)[:18000]
            body_tokens = _fact_tokens(body)
            if not ({"mmu", "pages"} <= body_tokens and {"recovery", "rollback", "failure"} & body_tokens):
                continue
            lines = self._lines(sym)
            formulas = _symbol_formula_facts(index, sym)
            loop_line = next(((line_no, line) for line_no, line in lines if _MMU_RECOVERY_LOOP_RE.search(line)), None)
            action_line = next(((line_no, line) for line_no, line in lines if _MMU_RECOVERY_ACTION_RE.search(line)), None)
            if not loop_line or not action_line:
                continue
            phys_formula = next((
                formula for formula in formulas
                if {"phys", "pages"} & set(formula.tokens)
                and {"add", "mul", "shift"} & set(formula.operators)
            ), None)
            bounds_text = "\n".join(line for _, line in lines[max(0, loop_line[0] - sym.line_number - 4):loop_line[0] - sym.line_number + 8])
            mismatch = (
                bool(re.search(r"\b(?:nr|count|pages|remaining|inserted|i)\b", bounds_text, re.IGNORECASE))
                and bool(re.search(r"\b(?:phys|pfn|base|start)\b", body, re.IGNORECASE))
                and not re.search(r"\b(?:min|max|clamp|WARN_ON|BUG_ON|assert|if\s*\([^)]*(?:nr|count|pages)[^)]*(?:phys|pfn|base))", bounds_text, re.IGNORECASE)
            )
            if not mismatch:
                continue
            caller = self._advanced_phys_pointer_caller(index, sym, context_syms)
            caller_suffix = ""
            if caller:
                caller_sym, caller_line, caller_text = caller
                caller_suffix = (
                    f" Caller {caller_sym.file_path}::{caller_sym.name} line {caller_line} passes an advanced "
                    f"phys/base pointer `{_line_excerpt(caller_text)}`, so rollback uses the wrong base."
                )
            result.mmu_recovery_notes.append(
                f"{sym.file_path}::{sym.name} recovery loop line {loop_line[0]} `{_line_excerpt(loop_line[1])}` "
                f"uses rollback/page bounds that are not visibly tied to phys-base adjustment"
                f"{' line ' + str(phys_formula.line_number) + ' `' + _line_excerpt(phys_formula.line_text) + '`' if phys_formula else ''}; "
                f"recovery action line {action_line[0]} `{_line_excerpt(action_line[1])}` may unmap/write/free the wrong rollback range."
                f"{caller_suffix}"
            )
            self._add_node(index, result, sym)
            if caller:
                self._add_node(index, result, caller[0])
            if len(result.mmu_recovery_notes) >= 8:
                return

    def _advanced_phys_pointer_caller(self, index: SymbolIndex, callee: SymbolDef, context_syms: list[SymbolDef]):
        for sym in context_syms[:120]:
            if _symbol_unique_name(sym) == _symbol_unique_name(callee):
                continue
            for line_no, line in self._lines(sym):
                if not re.search(r"\b" + re.escape(callee.name) + r"\s*\(", line):
                    continue
                if re.search(r"\b(?:phys|pfn|base)\s*(?:\+|\+=|\+\+)|&\s*(?:phys|pfn|base)\s*\[|(?:phys|pfn|base)\s*\+\s*(?:nr|count|pages|inserted|i)\b", line, re.IGNORECASE):
                    return sym, line_no, line
        return None

    def _detect_policy_gate_before_sink(self, index, result, target_syms, context):
        context_syms = self._context_symbols(index, context, target_syms)
        companion_guards = self._companion_policy_guards(index, context_syms, {sym.file_path for sym in target_syms})
        for sym in target_syms:
            sinks = _symbol_sink_facts(index, sym)
            if not sinks:
                continue
            guards = _symbol_guards(index, sym)
            for sink in sinks:
                required = self._required_policy_tokens_for_sink(sink, sym, companion_guards)
                if not required:
                    continue
                if self._has_policy_guard_before(guards, sink.line_number, required):
                    continue
                token = sorted(required)[0]
                companion = companion_guards.get(token)
                note = (
                    f"{sym.file_path}::{sym.name} line {sink.line_number} reaches privileged sink "
                    f"{sink.api} `{_line_excerpt(sink.line_text)}` without a prior "
                    f"{token}/provenance gate in the target path."
                )
                if companion:
                    note += (
                        f" Companion guard evidence: {companion.file_path}::{companion.name} "
                        f"checks `{token}`."
                    )
                    self._add_node(index, result, companion)
                result.policy_gate_notes.append(note)
                self._add_node(index, result, sym)
                if len(result.policy_gate_notes) >= 16:
                    return

    def _companion_policy_guards(self, index, syms: list[SymbolDef], target_files: set[str]) -> dict[str, SymbolDef]:
        guards = {}
        for sym in syms:
            if sym.file_path in target_files:
                continue
            for guard in _symbol_guards(index, sym):
                if guard.token in _POLICY_GUARD_WORDS or guard.token in {"protected", "protm", "same_va", "imported"}:
                    guards.setdefault(guard.token, sym)
        return guards

    def _required_policy_tokens_for_sink(self, sink: SinkFact, sym: SymbolDef, companion_guards: dict[str, SymbolDef]) -> set[str]:
        sink_tokens = _fact_tokens(f"{sink.api} {sink.line_text} {sym.name}")
        required = sink_tokens & (_POLICY_GUARD_WORDS | {"protected", "protm", "same_va", "imported"})
        if sink.api in {"mmap", "vm_fault", "remap_pfn_range", "vm_insert_pfn", "vmf_insert_pfn", "insert_pfn", "io_remap_pfn_range"}:
            required |= {"permission"} if "permission" in companion_guards else set()
            required |= {"same_va"} if "same_va" in companion_guards else set()
            required |= {"imported"} if "imported" in companion_guards else set()
            required |= {"protected"} if "protected" in companion_guards else set()
        if "dma_buf" in sink.api or "import" in sink.api or "export" in sink.api:
            required |= {"imported"} if "imported" in companion_guards else set()
            required |= {"owner"} if "owner" in companion_guards else set()
        return {token for token in required if token in companion_guards or token in sink_tokens}

    def _has_policy_guard_before(self, guards: list[GuardFact], line_number: int, required: set[str]) -> bool:
        for guard in guards:
            if guard.line_number > line_number:
                continue
            if line_number - guard.line_number > 35:
                continue
            if guard.token in required:
                return True
        return False

    def _detect_imported_same_va_fault_policy(self, index, result, target_syms, context):
        context_syms = self._context_symbols(index, context, target_syms)
        companion_guards = self._companion_policy_guards(index, context_syms, {sym.file_path for sym in target_syms})
        for sym in target_syms:
            if not _name_has_any(sym.name, {"mmap", "fault", "pfn", "vm"}):
                continue
            body_tokens = _domain_root_tokens(self._body_text(sym)[:16000])
            provenance_tokens = body_tokens | set(companion_guards)
            if not ({"imported", "same_va"} <= provenance_tokens and ({"umm", "dma_buf", "imported"} & provenance_tokens)):
                continue
            sinks = [
                sink for sink in _symbol_sink_facts(index, sym)
                if sink.api in {"vm_fault", "vm_insert_pfn", "vmf_insert_pfn", "insert_pfn", "remap_pfn_range", "io_remap_pfn_range", "mmap"}
                or re.search(r"\b(?:fault|pfn|mmap)\b", sink.line_text, re.IGNORECASE)
            ]
            if not sinks:
                continue
            guards = _symbol_guards(index, sym)
            for sink in sinks[:8]:
                if self._has_policy_guard_before(guards, sink.line_number, {"imported", "same_va"}):
                    continue
                result.policy_gate_notes.append(
                    f"{sym.file_path}::{sym.name} line {sink.line_number} reaches CPU fault/PFN mapping sink "
                    f"`{_line_excerpt(sink.line_text)}` without rejecting imported UMM SAME_VA provenance first."
                )
                self._add_node(index, result, sym)
                if companion_guards.get("imported"):
                    self._add_node(index, result, companion_guards["imported"])
                if companion_guards.get("same_va"):
                    self._add_node(index, result, companion_guards["same_va"])
                if len(result.policy_gate_notes) >= 16:
                    return

    def _detect_imported_mapping_policy(self, index, result, target_syms, context):
        context_syms = self._context_symbols(index, context, target_syms)
        target_files = {target.file_path for target in target_syms}
        context_provenance: set[str] = set()
        for ctx_sym in context_syms[:120]:
            ctx_text = f"{ctx_sym.name} {ctx_sym.signature} {self._body_text(ctx_sym)[:8000]}"
            context_provenance.update(_domain_root_tokens(ctx_text))
            context_provenance.update(_fact_tokens(ctx_text) & {"imported", "same_va", "same", "va", "dma", "buf", "umm", "protected", "native"})
        companion = next((
            sym for sym in context_syms
            if sym.file_path not in target_files
            and _fact_tokens(f"{sym.name} {self._body_text(sym)[:8000]}") & {"imported", "same_va", "dma", "umm", "native"}
        ), None)
        for sym in target_syms:
            body = self._body_text(sym)[:18000]
            text = f"{sym.name} {sym.signature} {body}"
            tokens = _fact_tokens(text)
            provenance = (tokens | context_provenance) & (_MAPPING_POLICY_WORDS | {"same", "va", "dma", "buf", "type"})
            if not ({"imported", "protected"} & provenance or {"dma", "buf"} <= provenance or {"same", "va"} <= provenance):
                continue
            if not (provenance & {"native", "imported", "protected", "umm", "dma", "buf", "same", "va"}):
                continue
            sink_line = next((
                (line_no, line) for line_no, line in self._lines(sym)
                if re.search(
                    r"\b(?:vmap_prot|vmap|kmap|mmap|vm_fault|vm_insert_pfn|vmf_insert_pfn|"
                    r"remap_pfn_range|copy_to_user|copy_from_user|softjob|kcpu|cpu_vm_fault|reg_mmap|context_mmap)\b",
                    line,
                    re.IGNORECASE,
                )
            ), None)
            if not sink_line:
                continue
            prior = "\n".join(line for line_no, line in self._lines(sym) if line_no <= sink_line[0])
            has_native_gate = re.search(r"\b(?:KBASE_MEM_TYPE_NATIVE|MEM_TYPE_NATIVE)\b", prior, re.IGNORECASE)
            if has_native_gate and re.search(r"\b(?:if|WARN_ON|BUG_ON|return|goto)\b", prior, re.IGNORECASE):
                continue
            result.imported_mapping_policy_notes.append(
                f"{sym.file_path}::{sym.name} line {sink_line[0]} reaches CPU mapping/access sink "
                f"`{_line_excerpt(sink_line[1])}` with imported/protected/SAME_VA-style provenance in scope, "
                "but no prior native-only provenance gate is visible on the target path."
            )
            self._add_node(index, result, sym)
            if companion:
                self._add_node(index, result, companion)
            if len(result.imported_mapping_policy_notes) >= 8:
                return

    def _detect_sentinel_misuse(self, index, result, target_syms):
        for sym in target_syms:
            sentinels = _symbol_sentinel_facts(index, sym)
            if not sentinels:
                continue
            lines = self._lines(sym)
            exact_phys_context = re.search(
                r"\b(?:syncset|sync_set|mem_pool|pool|cache|flush|clean|invalidate|phys|dma)\b",
                f"{sym.name} {self._body_text(sym)[:12000]}",
                re.IGNORECASE,
            )
            if exact_phys_context:
                for sentinel in sentinels[:8]:
                    sentinel_text = f"{sentinel.expr} {sentinel.line_text}"
                    if not re.search(r"\b(?:phys|phys_addr|dma|pfn|pa)\b", sentinel_text, re.IGNORECASE):
                        continue
                    downstream = next((
                        (line_no, line) for line_no, line in lines
                        if 0 < line_no - sentinel.line_number <= 24
                        and re.search(r"\b(?:sync|cache|flush|clean|invalidate|pool|free|add|release|skip|page)\b", line, re.IGNORECASE)
                    ), None)
                    if not downstream:
                        continue
                    result.sentinel_misuse_notes.append(
                        f"{sym.file_path}::{sym.name} line {sentinel.line_number} treats physical/DMA/PFN zero "
                        f"`{_line_excerpt(sentinel.line_text)}` as not-present, controlling cache/pool/page action "
                        f"line {downstream[0]} `{_line_excerpt(downstream[1])}` where address zero can be valid."
                    )
                    self._add_node(index, result, sym)
                    if len(result.sentinel_misuse_notes) >= 8:
                        return
                if result.sentinel_misuse_notes:
                    continue
            for sentinel in sentinels[:8]:
                downstream = next((
                    (line_no, line) for line_no, line in lines
                    if 0 < line_no - sentinel.line_number <= 18
                    and re.search(r"\b(?:sync|free|cache|pool|release|remove|skip|present|valid|page)\b", line, re.IGNORECASE)
                ), None)
                if not downstream:
                    continue
                result.sentinel_misuse_notes.append(
                    f"{sym.file_path}::{sym.name} line {sentinel.line_number} treats `{sentinel.expr} {sentinel.value}` "
                    f"as a not-present sentinel for physical/PFN state, controlling line {downstream[0]} "
                    f"`{_line_excerpt(downstream[1])}` where physical address/PFN zero may be valid."
                )
                self._add_node(index, result, sym)
                if len(result.sentinel_misuse_notes) >= 8:
                    return

    def _paired_lifecycle_symbols(self, index, name, target_prefixes, wanted_actions):
        stem = _module_stem(name)
        for sym in _lifecycle_symbol_candidates(index):
            sym_l = sym.name.lower()
            if not any(action in sym_l for action in wanted_actions):
                continue
            sym_stem = _module_stem(sym.name)
            if sym_stem == stem or sym_stem.startswith(stem) or stem.startswith(sym_stem) or sym_stem in target_prefixes:
                yield sym


_PARTIAL_REVIEW_SYS = """\
You are a conservative C/C++ security reviewer.
Review ONLY the target file for the requested pass.
Other files are evidence and context only.
Return findings only when the primary defective code is in the TARGET FILE.
Do not report bugs rooted in callers/callees unless the target file misuses their contract
or the target file owns the broken API behavior.
Use canonical ownership fields for every finding:
{{"primary_file": "src/example.c", "primary_function": "example_function",
"primary_line": 123,
"canonical_key": "src/example.c:example_function:vulnerability_family:root_cause_token"}}
Report each distinct root cause once. Be conservative.
vulnerability_type must be one of: """ + _VULN_TYPES + """.
Return ONLY valid JSON:
{{"findings": [{{"is_vulnerable": true, "vulnerability_type": "buffer_overflow",
"severity": "high", "confidence": "high", "function_name": "target_fn",
"related_function": "helper_fn", "line": 123, "description": "...",
"root_cause": "...", "evidence": "...", "primary_file": "src/target.c",
"primary_function": "target_fn", "primary_line": 123,
"canonical_key": "src/target.c:target_fn:memory_bounds:size_check"}}]}}
Return {{"findings": []}} if none found.
"""

_PARTIAL_REVIEW_USR = """\
Target file: {target_file}
Pass: {pass_name}

Review focus:
{focus}

Scope rule:
{scope_rule}

Candidate paths and relationships:
{paths_section}

Deterministic candidate notes:
{candidate_notes}

Global/callback constructs:
{globals_section}

== TARGET FILE CODE ==
{target_code}

== CONTEXT CODE ==
{context_code}
"""

_PASS_FOCI = {
    "target_intra": (
        "Bugs fully inside the target file: buffer overflow, null deref, format string, "
        "command injection, path traversal, integer overflow, double free, partial cleanup, "
        "TOCTOU, raw struct info leak. Do not report fixed literal printf formats."
    ),
    "inbound_contract": (
        "How external callers pass untrusted size/path/pointer/state into target functions. "
        "Report only if the target function fails to enforce its own contract or has broken ownership semantics."
    ),
    "outbound_misuse": (
        "Whether target code misuses helper APIs: wrong length field, ignored return, rich enum treated as bool, "
        "ownership transfer mistakes, NUL-termination contract mismatch."
    ),
    "shared_state": (
        "Shared-state semantic bugs in the target file: accounting drift, alias_count mismatch, refcount no-op, "
        "wrong flags/constants, width mismatch, stale length, information disclosure."
    ),
    "lifecycle": (
        "Lifecycle/ownership pairs: create/destroy, get/put, map/unmap, load/unload, init/term, "
        "callback teardown, stale pointers across realloc/compact, alias/source lifetime mismatch."
    ),
    "concurrency": (
        "Concrete concurrency bugs only: missing lock for shared fields, stale-after-unlock, lock-order among selected "
        "functions touching the same locks, teardown races with pending work/timers/callbacks."
    ),
    "state_publication": (
        "Ready/enabled/loaded/active/runtime flags set before validation or rollback-safe completion; error paths after "
        "publication that do not roll state back; disable/off paths that leave doorbell, ready, pending, or active state stale."
    ),
    "publish_rollback": (
        "Object publication before rollback-safe completion: rb_link_node/list_add/hash_add/register/insert before later "
        "capacity, allocation, validation, or registration failure, with missing or ineffective rollback."
    ),
    "allocation_arithmetic": (
        "Multiplication or addition in malloc/calloc/realloc/copy sizes where count comes from a parameter or field and no "
        "checked arithmetic or SIZE_MAX guard prevents undersized allocation."
    ),
    "copy_contract": (
        "Fixed-size copy/read/write contract bugs in the target file: missing count/len validation before fixed-size or "
        "user-controlled transfers, ignored short-transfer semantics, and mismatched object size versus requested count."
    ),
    "cleanup_symmetry": (
        "Exact cleanup/unwind asymmetry in the target file: an alloc/get/map/register/insert is followed by an error/exit "
        "path that skips the matching free/put/unmap/unregister/erase. Do not report generic leaks without the exact skipped unwind."
    ),
    "accounting_drift": (
        "Counter/refcount/accounting drift in the target file: increments or mapping/page/group accounting updates whose "
        "early returns or alternate branches skip the matching decrement or rollback."
    ),
    "arithmetic_chain_mismatch": (
        "Arithmetic-chain mismatch bugs: one derived allocation/region quantity is based on one formula while later copy/map/"
        "iteration consumes a stronger or different related formula without an overflow or consistency check."
    ),
    "resource_binding_order": (
        "Resource binding and state ordering bugs: enable/ready/active/doorbell state published before binding or validation, "
        "stale mapping/token/pages after disable/reset, and logical queue/context state diverging from actual mapped resources."
    ),
    "resource_validation_order": (
        "Exact predicate/use ordering bugs: real doorbell/mapping/queue resource binding before final enabled/alive/not-terminated "
        "validation. Report the exact bind statement and the missing or late liveness predicate."
    ),
    "cleanup_ledger": (
        "Interprocedural cleanup ledger bugs across selected queue/suspend/drain/delete functions: later exploit-relevant cleanup "
        "paths skip page/mapping/ref releases that companion paths acquired. Prefer later cleanup omission over shallow local unwind."
    ),
    "suspend_cleanup_ledger": (
        "Suspend-buffer cleanup bugs across prepare and later drain/delete/wait paths: report the exact later cleanup branch "
        "that omits page, mapping, or allocation-ref release for suspend resources prepared in related context."
    ),
    "suspend_size_sink": (
        "Suspend-buffer size sink bugs: unbounded suspend size/page state is stored in a resource object and later consumed "
        "by PFN/page-array/copy/iteration logic. Report both the producer and exact downstream consumer."
    ),
    "async_event_order": (
        "Async clear-before-handle bugs: fault/interrupt/event state is cleared or acked around queued work without serialization, "
        "flush, handled confirmation, or final safe-consume evidence."
    ),
    "fault_clear_order": (
        "Fault-specific clear-before-handle bugs: fault clear/ack register or command writes occur before queued/deferred "
        "fault handling has visibly completed or been serialized. Report the exact clear statement and async consumer."
    ),
    "size_propagation": (
        "User-controlled size propagation bugs: size/count/page state is stored into a resource object and later consumed by "
        "copy/iteration/page-count logic without an upper-bound or formula consistency check."
    ),
    "alias_extent_mismatch": (
        "Alias extent mismatch bugs: nents*stride or equivalent alias extent arithmetic is not tied to region reservation "
        "and later mapping consumption by an overflow or consistency check. Report exact producer and consumer."
    ),
    "stale_tracker_state": (
        "Stale tracker/double-remove bugs: tracker/rbtree/list removal without invalidating inserted/start_pfn/ownership state, "
        "allowing later second removal or stale cleanup."
    ),
    "region_replace_erase": (
        "Region replacement failure bugs: replacement/merge/allocation-failure paths free or replace a region without erasing "
        "or invalidating its rbtree/rblink/start_pfn linkage on that exact path."
    ),
    "metadata_type_confusion": (
        "Opaque metadata reinterpretation bugs: page_private/private integer-ish metadata cast to a struct pointer and immediately "
        "dereferenced or mutated without concrete type validation."
    ),
    "pm_runtime_sequence": (
        "Runtime PM sequencing bugs: power-control, clock, regulator, or register-sensitive action before pm_runtime_get/resume "
        "ownership is established, or unbalanced power-control sequencing around runtime on/off."
    ),
    "pm_callback_order": (
        "PM callback order bugs: callback-local GPU power-control enable/disable is ordered before runtime-PM ownership or "
        "is unbalanced across runtime on/off callbacks. Report the exact power-control call and missing ownership point."
    ),
    "secondary_element_omission": (
        "Paired-slot/atom omission bugs: first slot/atom is processed, then a priority/branch exit skips required second slot/atom "
        "handling. Report only concrete first/second/skip evidence."
    ),
    "zero_count_underflow": (
        "Zero-count underflow bugs: count/nr/num is used in count-1 or reverse scan logic without a nearby nonzero guard. "
        "Report the exact loop/index expression and missing zero-count validation."
    ),
    "owner_liveness_allocation": (
        "Owner-task liveness allocation bugs: page/pool growth loops allocate on behalf of a userspace owner without checking "
        "exiting/OOM/fatal-signal liveness. Report the exact allocation loop and missing owner bailout; avoid generic loop leaks."
    ),
    "user_buffer_permission": (
        "USER_BUFFER permission semantic bugs: get_user_pages/pin_user_pages import paths use GPU-write semantics where a "
        "CPU-write/FOLL_WRITE provenance gate is required. Report the exact pin/import call and mismatched permission predicate."
    ),
    "zone_shrink_validation": (
        "Region-zone shrink validation bugs: init/split/shrink paths reduce or replace a VA zone without proving the source "
        "zone is still entirely free, especially with imported/user-buffer overlap context. Report the exact shrink statement."
    ),
    "success_path_cleanup": (
        "Success-path temporary cleanup bugs: temporary buffers are allocated, an fd/resource is successfully installed, then "
        "the success return bypasses the cleanup label/free. Report only exact temp-resource and success-return evidence."
    ),
    "jit_lock_protocol": (
        "JIT lock protocol bugs: JIT allocate/free/process paths mutate shared JIT lists, limits, or pools from different queue "
        "paths without a common context-wide JIT lock. Report exact shared-state updates and companion mutator evidence."
    ),
    "teardown_order": (
        "Teardown-order bugs: VA regions or MMU tables are freed/terminated before the context is visibly scheduled out or "
        "its address space is disabled. Report the exact teardown statement and missing prior disable/schedule-out."
    ),
    "queue_publish_init": (
        "Queue publish-before-init bugs: queue pointers, array slots, or in-use bits are published before full initialization, "
        "and a later failure path lacks pointer/bit rollback. Report exact publish and failure statements."
    ),
    "fd_reuse_race": (
        "FD reuse race bugs: an fd is published to userspace and later re-looked-up for trigger/cleanup, allowing descriptor "
        "reuse to bind the operation to the wrong object. Report exact publish and relookup statements."
    ),
    "debugfs_permission": (
        "Debugfs/profiling authorization bugs: profiling/timeline debugfs streams are world-readable or acquired without a "
        "capability/owner check. Report exact debugfs/acquire statement and missing permission gate."
    ),
    "protected_mmu_protocol": (
        "Protected-mode/MMU protocol bugs: protected-mode enter/wait lacks the companion MMU serialization lock or final "
        "protected-active verification. Report the exact wait/enter statement and missing lock/verification."
    ),
    "active_singleton_stale": (
        "Active protected singleton stale-state bugs: active group/singleton pointers survive remove/free/timeout paths and "
        "can be reused by protected fault or scheduler handling. Report the exact singleton and teardown path."
    ),
    "mmu_recovery_rollback": (
        "MMU failure-recovery rollback bugs: recovery loop bounds, page counts, or phys/PFN base adjustment diverge from "
        "the unmap/write/free rollback action. Report the exact loop/action and mismatched rollback range."
    ),
    "sentinel_misuse": (
        "Wrong sentinel/constant bugs: physical address, PFN, DMA, or translated address compared with 0/NULL as not-present, "
        "then used to control sync/free/cache/pool behavior where zero may be valid."
    ),
    "policy_gate_before_sink": (
        "Policy/provenance gate-before-sink bugs in the target file: mmap/fault/PFN/usercopy/import/export sinks reached "
        "without the required imported/same_va/protected/permission/owner guard. Companion files may show the expected guard."
    ),
    "imported_mapping_policy": (
        "Imported/protected CPU-mapping policy bugs: imported, SAME_VA, DMA-BUF, or protected resources reach vmap/mmap/"
        "fault/softjob/KCPU access sinks without a visible native/provenance gate on the target path."
    ),
    "format_and_info_leak": (
        "Variadic logger wrappers, non-literal format arguments into printf-family wrappers, and debug/log output of "
        "physical addresses, DMA addresses, pointers, tokens, keys, or secrets. Fixed literal formats with %s arguments are not bugs."
    ),
    "fops_lifecycle": (
        "file_operations/ops lifecycle: .release without .flush around poll/ioctl/read/write/shared-fd lifetime; release or "
        "teardown destroys context while poll/ioctl/callback/work/timer can still access it."
    ),
    "lock_and_stale": (
        "Deterministic lock-order candidates and stale local/cached pointer or state after unlock/relock. Report missing locks "
        "only when a concrete protected field, teardown race, or corruption path is shown."
    ),
    "cross_file_lock_cycle": (
        "Cross-file deadlock cycles and callback/notifier-induced lock inversions. Report only when the target file contributes "
        "a concrete lock-order edge or unsafe callback participation; use companion files only to prove the other edge(s)."
    ),
    "named_lock_inversion": (
        "Named lock inversions: target and callback/notifier/backend companion paths acquire stable named locks in opposite "
        "orders. Report the exact lock names and the two concrete order edges."
    ),
    "state_transition_protocol": (
        "Distributed protocol/state transition bugs: wait/ack without final active/protected verification, protected-mode/MMU/"
        "scheduler/firmware transitions without the companion serialization lock, and split enter/exit or enable/disable "
        "protocols where the target file owns the unsafe participation."
    ),
    "partial_exact_fallback": (
        "Bounded recall fallback for high-signal root causes only: concrete target-file ordering/race, cleanup/unwind, "
        "branch-specific resource release, size propagation/arithmetic mismatch, metadata reinterpretation, imported/SAME_VA "
        "policy omission, sentinel misuse, or protected/MMU sequencing. Be conservative and exact."
    ),
}



__all__ = [name for name in globals() if not name.startswith('__')]
