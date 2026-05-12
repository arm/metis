# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Context selection for partial single-file reachability review."""

from __future__ import annotations

from .common import *

class PartialContextBuilder:
    """Select callers, callees, shared state, lifecycle peers, and callbacks."""

    def __init__(
        self,
        codebase_path: str,
        caps: PartialContextCaps | None = None,
        cache: PartialAnalysisCache | None = None,
    ):
        self._cb = os.path.abspath(codebase_path)
        self._caps = caps or PartialContextCaps()
        self._cache = cache or PartialAnalysisCache(codebase_path)

    def build_for_file(
        self,
        target_file: str,
        target_nodes: list[FunctionNode],
        symbol_index: SymbolIndex,
    ) -> PartialReviewContext:
        target_file = target_file.replace("\\", "/")
        self._cache.bind_index(symbol_index)
        target_symbols = _symbols_for_file(symbol_index, target_file)
        if not target_nodes:
            target_nodes = [self._node_for_symbol(symbol_index, sym) for sym in target_symbols]

        target_names = {node.name for node in target_nodes}
        target_calls = self._target_calls(target_nodes, symbol_index, target_symbols)
        target_fields = self._target_fields(target_file, symbol_index)
        target_prefixes = {_module_stem(name) for name in target_names if name}
        target_dir = str(Path(target_file).parent).replace("\\", "/")

        outbound_syms = self._cap_ranked_symbols(
            self._outbound_callees(target_calls, symbol_index, target_file, target_dir, target_prefixes),
            self._caps.max_outbound,
        )
        inbound_syms = self._cap_ranked_symbols(
            self._inbound_callers(target_names, symbol_index, target_file, target_dir, target_prefixes),
            self._caps.max_inbound,
        )
        shared_syms = self._cap_ranked_symbols(
            self._shared_state_nodes(target_fields, symbol_index, target_file, target_dir, target_prefixes),
            self._caps.max_shared,
        )
        lifecycle_syms = self._cap_ranked_symbols(
            self._lifecycle_pair_nodes(target_names, symbol_index, target_file, target_dir, target_prefixes),
            self._caps.max_lifecycle,
        )
        callback_ranked, globals_ = self._callback_context(
            target_file, target_names, symbol_index, target_dir, target_prefixes)
        callback_syms = self._cap_ranked_symbols(callback_ranked, self._caps.max_callbacks)
        inbound_syms, outbound_syms, shared_syms, lifecycle_syms, callback_syms = self._cap_total_symbols(
            inbound_syms, outbound_syms, shared_syms, lifecycle_syms, callback_syms)

        inbound = self._materialize_symbols(symbol_index, inbound_syms)
        outbound = self._materialize_symbols(symbol_index, outbound_syms)
        shared = self._materialize_symbols(symbol_index, shared_syms)
        lifecycle = self._materialize_symbols(symbol_index, lifecycle_syms)
        callbacks = self._materialize_symbols(symbol_index, callback_syms)

        paths = self._candidate_paths(target_nodes, inbound, outbound, shared, lifecycle, callbacks)
        return PartialReviewContext(
            target_file=target_file,
            target_nodes=target_nodes,
            inbound_callers=inbound,
            outbound_callees=outbound,
            shared_state_nodes=shared,
            lifecycle_pair_nodes=lifecycle,
            callback_nodes=callbacks,
            companion_nodes=[],
            globals=globals_,
            candidate_paths=paths,
        )

    def expand_companions(
        self,
        context: PartialReviewContext,
        index: SymbolIndex,
        *,
        progress_callback=None,
    ) -> int:
        selected = {_symbol_unique_name(sym): sym for sym in _symbols_for_file(index, context.target_file)}
        selected.update({_symbol_unique_name(sym): sym for sym in self._context_symbols(index, context)})
        selected_syms = list(selected.values())
        signal = self._companion_signal(index, context, selected_syms)
        if not signal["enabled"]:
            return 0
        if progress_callback:
            progress_callback({
                "event": "partial_companion_expansion_start",
                "locks": len(signal["locks"]),
                "state_tokens": len(signal["state_tokens"]),
                "event_tokens": len(signal.get("event_tokens", set())),
                "callback_or_notifier": bool(signal["callback_or_notifier"]),
            })
        ranked = self._companion_candidates(index, context, signal)
        remaining = max(0, self._caps.max_total_context_functions - len(self._all_context_nodes(context)))
        limit = min(max(0, int(self._caps.max_companions or 0)), remaining)
        companions = self._cap_ranked_symbols(ranked, limit)
        existing = {node.unique_name for node in self._all_context_nodes(context)}
        companions = [sym for sym in companions if _symbol_unique_name(sym) not in existing]
        context.companion_nodes = self._dedupe_nodes(
            list(context.companion_nodes or []) + self._materialize_symbols(index, companions)
        )
        context.candidate_paths = _dedupe_paths(
            list(context.candidate_paths or []) + self._companion_paths(index, context)
        )
        if progress_callback:
            progress_callback({
                "event": "partial_companion_expansion_done",
                "companions": len(context.companion_nodes),
                "candidate_symbols": len(ranked),
            })
        return len(context.companion_nodes)

    def _context_symbols(self, index: SymbolIndex, context: PartialReviewContext) -> list[SymbolDef]:
        symbols = {}
        for node in self._all_context_nodes(context):
            sym = _lookup_symbol(index, node.file_path, node.name)
            if sym:
                symbols[_symbol_unique_name(sym)] = sym
        return list(symbols.values())

    def _all_context_nodes(self, context: PartialReviewContext) -> list[FunctionNode]:
        nodes = {}
        for group in (
            context.target_nodes, context.inbound_callers, context.outbound_callees,
            context.shared_state_nodes, context.lifecycle_pair_nodes,
            context.callback_nodes, context.companion_nodes,
        ):
            for node in group or []:
                nodes[node.unique_name] = node
        return list(nodes.values())

    def _companion_signal(self, index: SymbolIndex, context: PartialReviewContext, symbols: list[SymbolDef]) -> dict:
        locks: set[str] = set()
        state_tokens: set[str] = set()
        event_tokens: set[str] = set()
        has_lock_edges = False
        callback_or_notifier = False
        lifecycle_concurrency = False
        exact_ordering = False
        for sym in symbols:
            unique = _symbol_unique_name(sym)
            meta = index.meta_by_symbol.get(unique)
            sym_locks = _symbol_locks(index, sym)
            sym_tokens = _symbol_state_tokens(index, sym)
            sym_events = _symbol_event_facts(index, sym)
            locks.update(sym_locks)
            state_tokens.update(sym_tokens)
            event_tokens.update(
                event.token for event in sym_events
                if event.kind in {
                    "resource_bind", "resource_clear", "async_schedule", "async_clear",
                    "pm_sensitive_action", "pm_runtime_get", "tracker_remove",
                    "tracker_invalidate", "slot_first", "slot_second", "protected_wait",
                    "fault_clear", "suspend_resource", "active_singleton",
                }
                and event.token not in {"register", "power", "pm", "slot"}
            )
            has_lock_edges = has_lock_edges or bool(_symbol_lock_edges(index, sym))
            exact_ordering = exact_ordering or bool(sym_events)
            callback_or_notifier = callback_or_notifier or bool(
                meta and (meta.has_callback_words or meta.has_notifier_words)
            )
            lifecycle_concurrency = lifecycle_concurrency or bool(
                meta and meta.has_lifecycle_words and (sym_locks or (sym_tokens & _TRANSITION_TOKENS))
            )
        strong_protocol = bool(state_tokens & (_WAIT_ACK_TOKENS | _STATE_VERIFY_TOKENS | _SUBSYSTEM_TOKENS))
        enabled = bool(has_lock_edges or callback_or_notifier or strong_protocol or lifecycle_concurrency or exact_ordering)
        return {
            "enabled": enabled,
            "locks": locks,
            "state_tokens": state_tokens,
            "event_tokens": event_tokens,
            "has_lock_edges": has_lock_edges,
            "callback_or_notifier": callback_or_notifier,
            "lifecycle_concurrency": lifecycle_concurrency,
            "exact_ordering": exact_ordering,
        }

    def _companion_candidates(self, index: SymbolIndex, context: PartialReviewContext, signal: dict) -> list:
        target_file = context.target_file
        target_dir = str(Path(target_file).parent).replace("\\", "/")
        target_names = {node.name for node in context.target_nodes}
        target_prefixes = {_module_stem(name) for name in target_names if name}
        existing = {node.unique_name for node in self._all_context_nodes(context)}
        ranked = {}

        for lock in signal["locks"]:
            for sym in index.symbols_by_lock.get(lock, [])[:160]:
                self._remember_companion_candidate(
                    ranked, index, sym, target_file, target_dir, target_prefixes,
                    signal, existing, bonus=42,
                )
        for token in signal["state_tokens"]:
            for sym in index.symbols_by_state_token.get(token, [])[:180]:
                self._remember_companion_candidate(
                    ranked, index, sym, target_file, target_dir, target_prefixes,
                    signal, existing, bonus=32,
                )
        for token in signal.get("event_tokens", set()):
            for sym in index.symbols_by_event_token.get(token, [])[:140]:
                self._remember_companion_candidate(
                    ranked, index, sym, target_file, target_dir, target_prefixes,
                    signal, existing, bonus=36,
                )
        if signal["callback_or_notifier"]:
            for sym in (_callback_symbol_candidates(index) + _notifier_symbol_candidates(index))[:220]:
                self._remember_companion_candidate(
                    ranked, index, sym, target_file, target_dir, target_prefixes,
                    signal, existing, bonus=26,
                )
        if signal["lifecycle_concurrency"]:
            for sym in _lifecycle_symbol_candidates(index)[:220]:
                self._remember_companion_candidate(
                    ranked, index, sym, target_file, target_dir, target_prefixes,
                    signal, existing, bonus=18,
                )
        return list(ranked.values())

    def _remember_companion_candidate(
        self,
        ranked_by_unique,
        index: SymbolIndex,
        sym: SymbolDef,
        target_file: str,
        target_dir: str,
        target_prefixes: set[str],
        signal: dict,
        existing: set[str],
        *,
        bonus: int,
    ):
        unique = _symbol_unique_name(sym)
        if unique in existing:
            return
        sym_dir = str(Path(sym.file_path).parent).replace("\\", "/")
        sym_stem = _module_stem(sym.name)
        lock_overlap = len(_symbol_locks(index, sym) & signal["locks"])
        token_overlap = len(_symbol_state_tokens(index, sym) & signal["state_tokens"])
        event_overlap = len({event.token for event in _symbol_event_facts(index, sym)} & signal.get("event_tokens", set()))
        if not lock_overlap and not token_overlap and not event_overlap and sym_dir != target_dir and sym_stem not in target_prefixes:
            return
        score_bonus = bonus + min(30, lock_overlap * 12) + min(24, token_overlap * 8) + min(24, event_overlap * 8)
        if sym_dir == target_dir:
            score_bonus += 28
        elif sym_dir.startswith(target_dir) or target_dir.startswith(sym_dir):
            score_bonus += 14
        if sym_stem in target_prefixes or any(
            sym_stem.startswith(prefix) or prefix.startswith(sym_stem)
            for prefix in target_prefixes if prefix
        ):
            score_bonus += 18
        meta = index.meta_by_symbol.get(unique)
        if meta and (meta.has_callback_words or meta.has_notifier_words):
            score_bonus += 10
        rank = self._rank_symbol(index, sym, target_file, target_dir, target_prefixes, bonus=score_bonus)
        self._remember_ranked_symbol(ranked_by_unique, rank, sym)

    def _companion_paths(self, index: SymbolIndex, context: PartialReviewContext) -> list[ReachabilityPath]:
        paths = []
        for target_node in context.target_nodes:
            target_sym = _lookup_symbol(index, target_node.file_path, target_node.name)
            target_locks = _symbol_locks(index, target_sym) if target_sym else set()
            target_tokens = _symbol_state_tokens(index, target_sym) if target_sym else set()
            for node in context.companion_nodes:
                sym = _lookup_symbol(index, node.file_path, node.name)
                if not sym:
                    continue
                if (
                    target_node.name in node.calls
                    or node.name in target_node.calls
                    or target_locks & _symbol_locks(index, sym)
                    or target_tokens & _symbol_state_tokens(index, sym)
                    or _module_stem(target_node.name) == _module_stem(node.name)
                ):
                    paths.append(ReachabilityPath(
                        target_node.unique_name,
                        node.unique_name,
                        [target_node.unique_name, node.unique_name],
                        node.sink_type,
                    ))
        return paths

    def _dedupe_nodes(self, nodes: list[FunctionNode]) -> list[FunctionNode]:
        seen, out = set(), []
        for node in nodes:
            if node.unique_name in seen:
                continue
            seen.add(node.unique_name)
            out.append(node)
        return out

    def _target_calls(self, target_nodes, index, target_symbols):
        calls = []
        for node in target_nodes:
            calls.extend(node.calls or [])
        for sym in target_symbols:
            calls.extend(_symbol_calls(index, sym))
        return list(dict.fromkeys(c for c in calls if c not in _CONTROL_CALLS))

    def _target_fields(self, target_file, index):
        return {use.field for use in _field_uses_for_file(index, target_file)}

    def _rank_symbol(self, index: SymbolIndex, sym: SymbolDef, target_file, target_dir, target_prefixes, bonus=0):
        score = bonus
        if sym.file_path == target_file:
            score += 100
        if str(Path(sym.file_path).parent).replace("\\", "/") == target_dir:
            score += 45
        stem = _module_stem(sym.name)
        if stem in target_prefixes or any(stem.startswith(p) or p.startswith(stem) for p in target_prefixes if p):
            score += 30
        calls = _symbol_calls(index, sym)
        meta = index.meta_by_symbol.get(_symbol_unique_name(sym))
        if (meta and meta.has_security_api) or any(
            _SECURITY_API_RE.search(f"{call}(") or call in _COMMON_LIBC_CALLS for call in calls
        ):
            score += 12
        if (meta and meta.has_lifecycle_words) or _name_has_any(sym.name, _LIFECYCLE_WORDS):
            score += 8
        if (meta and meta.has_callback_words) or _name_has_any(sym.name, _CALLBACK_WORDS):
            score += 10
        if "\\test\\" in sym.file_path.lower() or "/test/" in sym.file_path.lower():
            score -= 15
        return (-score, sym.file_path, int(sym.line_number or 0), sym.name)

    def _cap_ranked_symbols(self, ranked, limit):
        seen = set()
        result = []
        for _, sym in sorted(ranked, key=lambda item: item[0]):
            unique = _symbol_unique_name(sym)
            if unique in seen:
                continue
            seen.add(unique)
            result.append(sym)
            if len(result) >= limit:
                break
        return result

    def _cap_total_symbols(self, *groups):
        cap = self._caps.max_total_context_functions
        selected = []
        seen = set()
        output = []
        for group in groups:
            kept = []
            for sym in group:
                unique = _symbol_unique_name(sym)
                if unique in seen:
                    continue
                if len(selected) >= cap:
                    break
                seen.add(unique)
                selected.append(sym)
                kept.append(sym)
            output.append(kept)
        return output

    def _materialize_symbols(self, index: SymbolIndex, symbols: list[SymbolDef]) -> list[FunctionNode]:
        return [self._node_for_symbol(index, sym) for sym in symbols]

    def _node_for_symbol(self, index: SymbolIndex, sym: SymbolDef) -> FunctionNode:
        return _symbol_to_node(index, self._cb, sym, self._cache)

    def _remember_ranked_symbol(self, ranked_by_unique, rank, sym: SymbolDef):
        unique = _symbol_unique_name(sym)
        current = ranked_by_unique.get(unique)
        if current is None or rank < current[0]:
            ranked_by_unique[unique] = (rank, sym)

    def _outbound_callees(self, calls, index, target_file, target_dir, target_prefixes):
        ranked = {}
        for call in calls:
            if call in _COMMON_LIBC_CALLS:
                continue
            for sym in index.definitions.get(call, []):
                rank = self._rank_symbol(index, sym, target_file, target_dir, target_prefixes, bonus=20)
                self._remember_ranked_symbol(ranked, rank, sym)
        return list(ranked.values())

    def _caller_symbol_for_site(self, site: CallSite, index: SymbolIndex) -> SymbolDef | None:
        for sym in _symbols_for_file(index, site.caller_file):
            if sym.name == site.caller_name and sym.body_start <= site.line_number <= sym.body_end:
                return sym
        return _lookup_symbol(index, site.caller_file, site.caller_name)

    def _inbound_callers(self, target_names, index, target_file, target_dir, target_prefixes):
        ranked = {}
        for name in target_names:
            for site in index.callsites.get(name, []):
                sym = self._caller_symbol_for_site(site, index)
                if not sym:
                    continue
                rank = self._rank_symbol(index, sym, target_file, target_dir, target_prefixes, bonus=35)
                self._remember_ranked_symbol(ranked, rank, sym)
        return list(ranked.values())

    def _shared_state_nodes(self, fields, index, target_file, target_dir, target_prefixes):
        ranked = {}
        for field_name in fields:
            if field_name in _GENERIC_FIELDS and field_name not in _IMPORTANT_FIELDS:
                continue
            rarity_bonus = max(0, 30 - len(index.field_uses.get(field_name, [])))
            if field_name in _IMPORTANT_FIELDS:
                rarity_bonus += 20
            for use in index.field_uses.get(field_name, []):
                if use.file_path == target_file:
                    continue
                sym = self._symbol_for_function(index, use.file_path, use.function_name)
                if not sym:
                    continue
                rank = self._rank_symbol(index, sym, target_file, target_dir, target_prefixes, bonus=rarity_bonus)
                self._remember_ranked_symbol(ranked, rank, sym)
        return list(ranked.values())

    def _symbol_for_function(self, index, file_path, name):
        return _lookup_symbol(index, file_path, name)

    def _lifecycle_pair_nodes(self, target_names, index, target_file, target_dir, target_prefixes):
        wanted = set()
        for name in target_names:
            parts = _tokens(name)
            stem = _module_stem(name)
            for action in _LIFECYCLE_WORDS:
                if action in parts or name.lower().endswith("_" + action):
                    for pair in self._paired_actions(action):
                        wanted.add((stem, pair))
        ranked = {}
        if not wanted:
            return []
        for sym in _lifecycle_symbol_candidates(index):
            sym_l = sym.name.lower()
            sym_stem = _module_stem(sym.name)
            for stem, action in wanted:
                if action in sym_l and (sym_stem == stem or sym_stem.startswith(stem) or stem.startswith(sym_stem)):
                    rank = self._rank_symbol(index, sym, target_file, target_dir, target_prefixes, bonus=28)
                    self._remember_ranked_symbol(ranked, rank, sym)
                    break
        return list(ranked.values())

    def _paired_actions(self, action):
        pairs = {
            "create": ("destroy", "free", "release"),
            "destroy": ("create", "alloc", "init"),
            "alloc": ("free", "destroy"),
            "free": ("alloc", "create"),
            "init": ("term", "cleanup", "shutdown"),
            "term": ("init", "setup"),
            "setup": ("cleanup", "term"),
            "cleanup": ("setup", "init"),
            "open": ("release", "close", "flush"),
            "release": ("open", "flush", "poll", "ioctl"),
            "close": ("open", "flush"),
            "flush": ("open", "release", "close"),
            "get": ("put", "release"),
            "put": ("get", "ref"),
            "ref": ("unref", "put"),
            "unref": ("ref", "get"),
            "map": ("unmap",),
            "unmap": ("map",),
            "load": ("unload", "verify"),
            "unload": ("load",),
            "enable": ("disable", "reset"),
            "disable": ("enable", "reset"),
            "start": ("stop",),
            "stop": ("start",),
            "register": ("unregister",),
            "unregister": ("register",),
            "add": ("remove", "erase"),
            "remove": ("add", "insert"),
            "insert": ("erase", "remove"),
            "erase": ("insert", "add"),
            "grow": ("shrink",),
            "shrink": ("grow",),
            "suspend": ("resume",),
            "resume": ("suspend",),
            "schedule": ("cancel", "flush"),
            "cancel": ("schedule", "flush"),
            "arm": ("disarm", "cancel"),
            "disarm": ("arm",),
        }
        return pairs.get(action, ())

    def _callback_context(self, target_file, target_names, index, target_dir, target_prefixes):
        ranked = {}
        globals_ = []
        selected_names = set(target_names)
        for g in index.globals:
            gl = f"{g.name} {g.kind} {g.initializer}".lower()
            refs_target = bool(set(g.referenced_functions) & target_names)
            same_file = g.file_path == target_file
            if same_file or refs_target or any(word in gl for word in _CALLBACK_WORDS):
                if same_file or refs_target or str(Path(g.file_path).parent).replace("\\", "/") == target_dir:
                    globals_.append(g)
                    selected_names.update(g.referenced_functions)
        for name in selected_names:
            for sym in index.definitions.get(name, []):
                rank = self._rank_symbol(index, sym, target_file, target_dir, target_prefixes, bonus=30)
                self._remember_ranked_symbol(ranked, rank, sym)
        for sym in _callback_symbol_candidates(index) + _lifecycle_symbol_candidates(index):
            if str(Path(sym.file_path).parent).replace("\\", "/") != target_dir and sym.file_path != target_file:
                continue
            rank = self._rank_symbol(index, sym, target_file, target_dir, target_prefixes, bonus=18)
            self._remember_ranked_symbol(ranked, rank, sym)
        return list(ranked.values()), globals_[:40]

    def _candidate_paths(self, target_nodes, inbound, outbound, shared, lifecycle, callbacks):
        target_by_name = {n.name: n for n in target_nodes}
        paths = []
        for caller in inbound:
            for target in target_nodes:
                if target.name in caller.calls:
                    paths.append(ReachabilityPath(caller.unique_name, target.unique_name, [caller.unique_name, target.unique_name], target.sink_type))
        for target in target_nodes:
            for callee in outbound:
                if callee.name in target.calls:
                    paths.append(ReachabilityPath(target.unique_name, callee.unique_name, [target.unique_name, callee.unique_name], callee.sink_type))
        related = shared + lifecycle + callbacks
        for target in target_nodes:
            for node in related:
                if node.unique_name == target.unique_name:
                    continue
                if _module_stem(node.name) == _module_stem(target.name) or target.name in node.calls or node.name in target.calls:
                    paths.append(ReachabilityPath(target.unique_name, node.unique_name, [target.unique_name, node.unique_name], node.sink_type))
                    if node.name in target_by_name:
                        paths.append(ReachabilityPath(node.unique_name, target.unique_name, [node.unique_name, target.unique_name], target.sink_type))
        return _dedupe_paths(paths)



__all__ = [name for name in globals() if not name.startswith('__')]
