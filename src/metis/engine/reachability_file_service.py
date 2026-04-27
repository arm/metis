# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import logging
import os
import re
import threading

from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path

from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate

from metis.usage import submit_with_current_context
from metis.utils import parse_json_output, read_file_content

from .reachability_service import (
    Deduplicator,
    FunctionNode,
    GlobalConstruct,
    GraphBuilder,
    PathTracer,
    ReachabilityGraph,
    ReachabilityPath,
    VulnerabilityFinding,
    _VULN_TO_CWE,
    _dedupe_paths,
    _normalise_vuln_type,
    _post_filter_findings,
    _read_function_body,
    _read_line_context,
    _safe_int,
    _same_file_ref,
    _severity_title,
)
from .repository import EngineRepository
from .runtime import EngineConfig

logger = logging.getLogger("metis")


_C_CPP_EXTS = frozenset({".c", ".h", ".cc", ".cpp", ".hpp", ".hh", ".hxx", ".cxx"})
_CONTROL_CALLS = frozenset({
    "if", "for", "while", "switch", "return", "sizeof", "alignof", "_Generic",
    "case", "do", "else", "typedef", "defined",
})
_COMMON_LIBC_CALLS = frozenset({
    "malloc", "calloc", "realloc", "free", "memcpy", "memmove", "memset",
    "strcpy", "strncpy", "strcat", "snprintf", "sprintf", "printf", "fprintf",
    "vfprintf", "fopen", "open", "close", "read", "write", "stat", "lstat",
    "access", "system", "popen",
})
_SECURITY_API_RE = re.compile(
    r"\b(?:memcpy|memmove|strcpy|strcat|strncpy|sprintf|vsprintf|snprintf|"
    r"malloc|calloc|realloc|free|fopen|open|stat|lstat|access|unlink|rename|"
    r"system|popen|exec(?:l|le|lp|lpe|v|ve|vp|vpe)?|printf|fprintf|vprintf|"
    r"vfprintf|recv|read|write|send|ioctl)\s*\(",
    re.IGNORECASE,
)
_SOURCE_RE = re.compile(
    r"\b(?:ioctl|sysfs|debugfs|netlink|recv|read|fread|argv|argc|getenv|"
    r"copy_from_user|user|request|packet|socket|interrupt|irq|firmware|fw)\b",
    re.IGNORECASE,
)
_SINK_KIND_RE = re.compile(
    r"\b(?:memcpy|memmove|strcpy|strcat|sprintf|vsprintf|system|popen|exec|"
    r"fopen|open|stat|lstat|access|free|kfree|vfree|mutex_destroy|"
    r"spin_lock|mutex_lock|ioctl|mmio|dma|doorbell|register|reset)\b",
    re.IGNORECASE,
)
_FIELD_RE = re.compile(r"(?:->|\.)\s*([A-Za-z_][A-Za-z0-9_]*)")
_CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_GLOBAL_REF_RE = re.compile(
    r"\.(?:open|release|ioctl|poll|flush|callback|fn|worker|data|probe|remove|"
    r"shutdown|suspend|resume|read|write)\s*=\s*&?\s*([A-Za-z_][A-Za-z0-9_]*)"
)
_GLOBAL_START_RE = re.compile(
    r"\b(?:struct\s+\w*(?:file_operations|ops|fops)\w*|timer|work|watchdog|ops|fops)\b",
    re.IGNORECASE,
)
_FUNCTION_DEF_RE = re.compile(
    r"(?m)^[ \t]*(?P<signature>(?:[A-Za-z_][A-Za-z0-9_]*[ \t\*\&]+)+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}]*\)\s*"
    r"(?:const\s*)?(?:noexcept\s*)?)\{"
)
_LIFECYCLE_WORDS = frozenset({
    "create", "destroy", "alloc", "free", "init", "term", "setup", "cleanup",
    "open", "release", "close", "flush", "get", "put", "ref", "unref", "map",
    "unmap", "load", "unload", "reload", "enable", "disable", "start", "stop",
    "register", "unregister", "add", "remove", "insert", "erase", "grow",
    "shrink", "suspend", "resume", "schedule", "cancel", "arm", "disarm",
})
_CALLBACK_WORDS = frozenset({
    "callback", "cb", "timer", "work", "worker", "watchdog", "fops", "ops",
    "file_operations", "fn", "poll", "ioctl", "flush", "release",
})
_IMPORTANT_FIELDS = frozenset({
    "nr_pages", "pages", "alias_count", "gpu_mappings", "gpu_mappings_total",
    "ctx_count", "regions", "active", "ready", "state", "flags", "refcount",
    "data", "len", "size", "raw_len", "data_len", "enabled", "loaded",
    "initialized", "powered", "phys_addr", "fault_addr", "permission",
})
_GENERIC_FIELDS = frozenset({"next", "prev", "list", "node", "data", "name", "id"})
_VULN_TYPES = (
    "buffer_overflow, out_of_bounds, integer_overflow, use_after_free, "
    "double_free, double_close, null_deref, command_injection, format_string, "
    "path_traversal, toctou, missing_auth, permission_mismatch, wrong_constant, "
    "wrong_flag_semantic, type_confusion, stale_length, width_mismatch, info_leak, uninitialized_memory, "
    "copy_contract, arithmetic_chain_mismatch, resource_binding_order, policy_gate_before_sink, "
    "resource_validation_order, cleanup_ledger, async_event_order, size_propagation, stale_tracker_state, "
    "pm_runtime_sequence, secondary_element_omission, protected_mmu_protocol, sentinel_misuse, "
    "mmu_recovery_rollback, suspend_cleanup_ledger, suspend_size_sink, fault_clear_order, "
    "pm_callback_order, region_replace_erase, imported_mapping_policy, alias_extent_mismatch, "
    "named_lock_inversion, active_singleton_stale, zero_count_underflow, "
    "owner_liveness_allocation, user_buffer_permission, zone_shrink_validation, "
    "success_path_cleanup, jit_lock_protocol, teardown_order, queue_publish_init, "
    "fd_reuse_race, debugfs_permission, mmu_lockdrop_stale, mmu_teardown_order, "
    "partial_mapping_rollback, migration_metadata_race, "
    "state_transition_protocol, "
    "stale_after_unlock, missing_lock, lock_order, state_order, ordering_gap, "
    "teardown_race, deferred_uaf, callback_lifecycle, refcount_imbalance, "
    "accounting_drift, partial_cleanup, rollback_gap, cleanup_symmetry, cross_file_lock_cycle, "
    "file_ops_lifecycle_gap, stale_pointer, other"
)
_STATE_FIELD_RE = re.compile(
    r"\b(?:(?:[A-Za-z_][A-Za-z0-9_]*(?:->|\.))?"
    r"(?:gpu_ready|ready|enabled|active|initialized|loaded|online|powered|runtime_active|state))\s*=\s*"
    r"(?:1|true|TRUE|[A-Z0-9_]*(?:ON|ACTIVE|READY|LOADED|ENABLED|POWERED)[A-Z0-9_]*)",
    re.IGNORECASE,
)
_STATE_RESET_RE = re.compile(
    r"\b(?:gpu_ready|ready|enabled|active|initialized|loaded|online|powered|runtime_active|state)\s*=\s*"
    r"(?:0|false|FALSE|[A-Z0-9_]*(?:OFF|DISABLED|IDLE|INVALID)[A-Z0-9_]*)",
    re.IGNORECASE,
)
_ERROR_PATH_RE = re.compile(r"\b(?:return\s+(?:-\d+|NULL|nullptr)|goto\s+(?:err|fail|out|cleanup)\w*)\b", re.IGNORECASE)
_PUBLISH_CALL_RE = re.compile(
    r"\b(?:rb_link_node|list_add|hash_add|insert|register|publish|xarray_insert|"
    r"xa_insert|idr_alloc|id_alloc|add)\s*\(",
    re.IGNORECASE,
)
_ROLLBACK_CALL_RE = re.compile(r"\b(?:rb_erase|list_del|hash_del|unregister|remove|erase|delete|del)\s*\(", re.IGNORECASE)
_ALLOC_ARITH_RE = re.compile(
    r"\b(?:malloc|kmalloc|realloc|krealloc|calloc|kcalloc|vzalloc|kvcalloc)\s*\([^;\n]*"
    r"(?:\*|sizeof)\s*[^;\n]*\)|\b[A-Za-z_][A-Za-z0-9_]*(?:count|cap|num|nr|n|len|size)[A-Za-z0-9_]*\s*\*\s*sizeof\s*\(",
    re.IGNORECASE,
)
_OVERFLOW_GUARD_RE = re.compile(r"\b(?:SIZE_MAX|__builtin_mul_overflow|check_mul_overflow|array_size|struct_size|kmalloc_array|kcalloc|kvcalloc)\b|/\s*sizeof\s*\(", re.IGNORECASE)
_LOG_CALL_RE = re.compile(
    r"\b(?:fprintf|printf|snprintf|sprintf|vfprintf|util_log|debug_log|trace|printk|"
    r"dev_info|dev_warn|dev_err|gpu_debug_log|gpu_debug)\s*\(",
    re.IGNORECASE,
)
_SENSITIVE_TOKEN_RE = re.compile(r"\b(?:phys|phys_addr|paddr|dma|addr|fault_addr|pointer|token|key|secret)\b", re.IGNORECASE)
_SENSITIVE_FORMAT_RE = re.compile(r"%(?:0?\d+)?(?:llx|lx|p|x)", re.IGNORECASE)
_VARIADIC_WRAPPER_RE = re.compile(r"\b(?:vfprintf|vprintf|vsprintf|vsnprintf|printf|fprintf|sprintf|snprintf)\s*\(", re.IGNORECASE)
_LOCK_CALL_RE = re.compile(
    r"\b(?P<fn>pthread_mutex_lock|pthread_mutex_unlock|mutex_lock|mutex_unlock|"
    r"spin_lock(?:_irqsave|_irq)?|spin_unlock(?:_irqrestore|_irq)?)\s*\(\s*(?P<arg>[^,\)]+)",
    re.IGNORECASE,
)
_UNLOCK_WORD_RE = re.compile(r"unlock", re.IGNORECASE)
_ASSIGN_FROM_FIELD_RE = re.compile(r"\b(?P<var>(?:cached|saved|old|tmp)[A-Za-z0-9_]*)\s*=\s*[^;\n]*(?:->|\.)[A-Za-z_][A-Za-z0-9_]*")
_DISABLE_NAME_RE = re.compile(r"(?:disable|stop|clear|term|shutdown|release)", re.IGNORECASE)
_DISABLE_STATE_RE = re.compile(
    r"\b(?:enabled|active|powered|ready|pending|state)\s*=\s*(?:0|false|FALSE|[A-Z0-9_]*(?:OFF|DISABLED|IDLE)[A-Z0-9_]*)",
    re.IGNORECASE,
)
_CALLBACK_STORE_RE = re.compile(
    r"(?:callback|work|timer|watchdog)\s*(?:->|\.)\s*(?:data|ctx|fn)\s*=|"
    r"(?:queue|alias|ctx|grp|obj|task|session)\s*(?:->|\.)\s*(?:ctx|pages|data|callback|work|timer)\s*=",
    re.IGNORECASE,
)
_CANCEL_OR_REF_RE = re.compile(r"\b(?:cancel|flush|drain|unregister|del_timer|destroy_workqueue|refcount|kref|get|put|pin|unpin|clear|NULL)\b", re.IGNORECASE)
_PROTOCOL_TOKEN_WORDS = frozenset({
    "protected", "protm", "active", "enable", "enabled", "disable", "disabled",
    "enter", "entered", "exit", "ack", "wait", "flush", "ready", "pending",
    "state", "resume", "suspend", "start", "stop", "mmu", "scheduler", "sched",
    "firmware", "fw", "hwcnt", "counter", "clock", "clk", "power", "reset",
    "doorbell", "gpu", "fault", "irq", "interrupt", "completion", "event",
    "fence", "serialize", "serialise", "sync", "transition",
})
_PROTOCOL_TOKEN_ALIASES = {
    "enabled": "enable",
    "disabled": "disable",
    "entered": "enter",
    "sched": "scheduler",
    "fw": "firmware",
    "clk": "clock",
    "serialise": "serialize",
    "sync": "serialize",
}
_WAIT_ACK_TOKENS = frozenset({"wait", "ack", "completion", "event", "fence"})
_STATE_VERIFY_TOKENS = frozenset({"active", "protected", "protm", "ready", "state", "enter", "enable"})
_TRANSITION_TOKENS = frozenset({
    "protected", "protm", "active", "enable", "disable", "enter", "exit",
    "ready", "pending", "state", "resume", "suspend", "start", "stop",
})
_SUBSYSTEM_TOKENS = frozenset({
    "mmu", "scheduler", "firmware", "hwcnt", "counter", "clock", "power",
    "doorbell", "gpu", "irq", "interrupt",
})
_NOTIFIER_WORDS = frozenset({
    "notifier", "notify", "notification", "event", "completion", "wait",
    "ack", "irq", "interrupt", "workqueue", "work", "callback",
})
_PROTOCOL_TOKEN_RE = re.compile(
    r"\b(?:protected|protm|active|enabled?|disabled?|enter(?:ed)?|exit|ack|wait|"
    r"flush|ready|pending|state|resume|suspend|start|stop|mmu|sched(?:uler)?|"
    r"firmware|fw|hwcnt|counter|clock|clk|power|reset|doorbell|gpu|fault|irq|"
    r"interrupt|completion|event|fence|seriali[sz]e|sync|transition)\w*\b",
    re.IGNORECASE,
)
_NOTIFIER_RE = re.compile(
    r"\b(?:notifier|notify|notification|event|completion|wait|ack|irq|interrupt|workqueue)\w*\b",
    re.IGNORECASE,
)
_COPY_CONTRACT_APIS = frozenset({
    "memcpy", "memmove", "copy_to_user", "copy_from_user", "copy_in_user",
    "read", "write", "kernel_read", "kernel_write", "simple_read_from_buffer",
    "simple_write_to_buffer",
})
_COPY_API_RE = re.compile(
    r"\b(?:memcpy|memmove|copy_to_user|copy_from_user|copy_in_user|read|write|"
    r"kernel_read|kernel_write|simple_read_from_buffer|simple_write_to_buffer)\s*\(",
    re.IGNORECASE,
)
_COUNT_SIZE_WORDS = frozenset({
    "count", "len", "length", "size", "bytes", "nbytes", "nr", "num", "nents",
    "stride", "pages", "page_count", "groups", "offset",
})
_RESOURCE_WORDS = frozenset({
    "doorbell", "mapping", "mappings", "map", "pages", "page", "token", "ctx",
    "context", "session", "queue", "alias", "region", "gpu_va", "same_va",
    "imported", "dma_buf", "exporter", "pfn", "mmu", "protected", "protm",
})
_POLICY_GUARD_WORDS = frozenset({
    "imported", "same_va", "protected", "protm", "permission", "permissions",
    "owner", "owned", "capable", "access", "allowed", "trusted", "exporter",
    "importer", "dma_buf", "privileged", "user", "readonly", "writable",
})
_POLICY_SINK_APIS = frozenset({
    "mmap", "vm_fault", "remap_pfn_range", "vm_insert_pfn", "vmf_insert_pfn",
    "vm_insert_page", "copy_to_user", "copy_from_user", "dma_buf_mmap",
    "dma_buf_map_attachment", "dma_buf_begin_cpu_access", "kbase_gpu_mmap",
    "insert_pfn", "io_remap_pfn_range", "map", "import", "export",
})
_GUARD_COMPARE_RE = re.compile(
    r"\b(?P<lhs>[A-Za-z_][A-Za-z0-9_]*(?:(?:->|\.)[A-Za-z_][A-Za-z0-9_]*)?)\s*"
    r"(?P<op><=|>=|<|>|==|!=)\s*(?P<rhs>[^;&|)]+)"
)
_ASSIGN_FACT_RE = re.compile(
    r"\b(?P<lhs>[A-Za-z_][A-Za-z0-9_]*(?:(?:->|\.)[A-Za-z_][A-Za-z0-9_]*)?)\s*"
    r"(?<![=!<>])=(?!=)\s*(?P<rhs>[^;]+)"
)
_UPDATE_FACT_RE = re.compile(
    r"(?P<target>[A-Za-z_][A-Za-z0-9_]*(?:(?:->|\.)[A-Za-z_][A-Za-z0-9_]*)?)\s*"
    r"(?P<op>\+\+|--|\+=|-=)"
)
_ARITH_EXPR_RE = re.compile(r"(\*|<<|>>|\bPAGE_SHIFT\b|\bsizeof\s*\()", re.IGNORECASE)
_ERROR_OR_EXIT_RE = re.compile(r"\b(?:return|goto\s+(?:err|fail|out|cleanup)\w*)\b", re.IGNORECASE)
_NULL_CLEAR_RE = re.compile(r"\b(?:NULL|nullptr|0|false|FALSE|INVALID|invalid)\b")
_QUEUE_LIVENESS_WORDS = frozenset({
    "enabled", "enable", "alive", "terminated", "terminating", "active",
    "drain_queue", "drain", "suspend", "suspended", "group_suspend", "stopped",
})
_TRACKER_WORDS = frozenset({"tracker", "tracking", "rbtree", "rb", "tree", "list", "node", "start_pfn", "inserted"})
_PM_WORDS = frozenset({"pm", "runtime", "power", "clock", "clk", "regulator", "register", "gpu_power"})
_SLOT_WORDS = frozenset({"slot", "slots", "atom", "atoms", "prio", "priority", "job", "jobs"})
_SUSPEND_WORDS = frozenset({
    "suspend", "suspended", "sus", "buf", "buffer", "pages", "nr_pages",
    "normal", "group", "queue", "drain", "wait", "cqs", "same_va",
})
_MAPPING_POLICY_WORDS = frozenset({
    "imported", "same_va", "dma_buf", "umm", "protected", "native",
    "vmap", "vmap_prot", "mmap", "fault", "pfn", "softjob", "kcpu",
})
_METADATA_SOURCE_RE = re.compile(r"\b(?:page_private|folio_get_private|private|metadata|opaque|pfn|phys|addr)\b", re.IGNORECASE)
_STRUCT_CAST_RE = re.compile(
    r"(?P<target>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"\((?P<type>(?:const\s+)?struct\s+[A-Za-z_][A-Za-z0-9_]*\s*\*)\)\s*(?P<src>[^;]+)"
)
_SENTINEL_COMPARE_RE = re.compile(
    r"\b(?P<expr>(?:[A-Za-z_][A-Za-z0-9_]*\s*\([^;\n]*?\)|"
    r"[A-Za-z_][A-Za-z0-9_]*(?:(?:->|\.)[A-Za-z_][A-Za-z0-9_]*)?))\s*"
    r"(?P<op>==|!=)\s*(?P<value>0|NULL|nullptr)\b"
)
_PAGE_ROUND_RE = re.compile(r"\b(?:PFN_UP|PFN_DOWN|DIV_ROUND_UP|PAGE_ALIGN|round_up|round_down)\s*\(", re.IGNORECASE)
_PM_RUNTIME_API_RE = re.compile(r"\b(?:pm_runtime_get_sync|pm_runtime_resume_and_get|pm_runtime_get_if_in_use|pm_runtime_get)\s*\(", re.IGNORECASE)
_PM_SENSITIVE_API_RE = re.compile(
    r"\b(?:enable_gpu_power_control|disable_gpu_power_control|clk_prepare_enable|clk_enable|regulator_enable|readl|writel|"
    r"regmap_read|regmap_write|kbase_reg_read|kbase_reg_write|reset_control_deassert)\s*\(",
    re.IGNORECASE,
)
_ASYNC_SCHEDULE_RE = re.compile(
    r"\b(?:queue_work|schedule_work|irq_work_queue|tasklet_schedule|kthread_queue_work|wake_up|notify)\w*\s*\(",
    re.IGNORECASE,
)
_ASYNC_CLEAR_RE = re.compile(r"\b(?:clear|ack|reset)\w*\s*\(", re.IGNORECASE)
_PROTECTED_ACTIVE_RE = re.compile(r"\b(?:protected|protm)[A-Za-z0-9_]*(?:->|\.)?(?:active|entered|enabled|state)\b", re.IGNORECASE)
_FAULT_CLEAR_RE = re.compile(
    r"\b(?:GPU_COMMAND_CLEAR_FAULT|CLEAR_FAULT|clear[_\s-]*fault|fault[_\s-]*clear|ack[_\s-]*fault|"
    r"reset[_\s-]*fault|FAULT_CLEAR)\b|"
    r"\b(?:writel|kbase_reg_write|regmap_write)\s*\([^;\n]*(?:FAULT|IRQ|INTERRUPT)[^;\n]*(?:CLEAR|ACK|RESET)",
    re.IGNORECASE,
)
_SUSPEND_RELEASE_RE = re.compile(
    r"\b(?:put_page|unpin_user_pages|release_pages|kbase_mem_phy_alloc_put|"
    r"kbase_mem_phy_alloc_kernel_unmapped|free_pages|vunmap|unmap)\w*\s*\(",
    re.IGNORECASE,
)
_SUSPEND_SOURCE_RE = re.compile(
    r"\b(?:get_user_pages|pin_user_pages|normal_suspend_buf|sus_buf|suspend_buf|"
    r"nr_pages|PFN_UP|GROUP_SUSPEND|CQS_WAIT|drain_queue)\b",
    re.IGNORECASE,
)
_REGION_REPLACE_RE = re.compile(
    r"\b(?:replace|replacement|exact|merge|split|ENOMEM|rblink|rb_node|rb_erase|"
    r"region_refcnt_free|start_pfn)\b",
    re.IGNORECASE,
)
_ACTIVE_SINGLETON_RE = re.compile(
    r"\b(?:active_(?:protm|protected)?_?grp|active_(?:protm|protected)?_?group|"
    r"active_protm_grp|active_group)\b",
    re.IGNORECASE,
)
_ZERO_COUNT_UNDERFLOW_RE = re.compile(
    r"\b(?:count|nr|num|n)\s*-\s*1\b|--\s*(?:i|idx|index)|"
    r"\b(?:for|while)\s*\([^)]*(?:>=\s*0|--)[^)]*\)",
    re.IGNORECASE,
)
_DOORBELL_BIND_RE = re.compile(
    r"\b(?:assign_user_doorbell_to_queue|doorbell|USER_DOORBELL|real[_\s-]*doorbell|"
    r"program_cs|program.*doorbell|doorbell.*(?:assign|program|map|bind|base|offset))\b",
    re.IGNORECASE,
)
_QUEUE_LIVENESS_RE = re.compile(
    r"\b(?:queue|csi|cs|group|kctx)[^;\n]*(?:enabled?|alive|terminat(?:ed|ing)|stopped|"
    r"dying|run_state|KBASE_CSF_QUEUE)\b|"
    r"\b(?:enabled?|alive|terminat(?:ed|ing)|stopped|dying)\b[^;\n]*(?:queue|csi|cs|group)",
    re.IGNORECASE,
)
_OWNER_LIVENESS_RE = re.compile(
    r"\b(?:signal_pending|fatal_signal_pending|task_is_oom_victim|oom_victim|PF_EXITING|"
    r"exit_state|mmget_not_zero|kthread_should_stop|process_exiting|task.*exiting|task.*dying)\b",
    re.IGNORECASE,
)
_POOL_ALLOC_RE = re.compile(
    r"\b(?:kbase_mem_pool_(?:grow|alloc_pages)|mem_pool_(?:grow|alloc)|alloc_pages|"
    r"kbase_alloc_phy_pages|kbase_mem_alloc_page|new_page|page_alloc)\w*\s*\(",
    re.IGNORECASE,
)
_USER_BUFFER_RE = re.compile(r"\b(?:USER_BUFFER|user_buffer|from_user_buffer|KBASE_MEM_TYPE_IMPORTED_USER_BUF)\b", re.IGNORECASE)
_GUP_RE = re.compile(r"\b(?:get_user_pages|pin_user_pages|get_user_pages_fast|pin_user_pages_fast)\w*\s*\(", re.IGNORECASE)
_GPU_WRITE_FLAG_RE = re.compile(r"\b(?:KBASE_REG_GPU_WR|GPU_WR|GPU.*WRITE|gpu_wr|gpu_write|KBASE_REG_CPU_WR|CPU_WR)\b", re.IGNORECASE)
_ZONE_SHRINK_RE = re.compile(
    r"\b(?:init_(?:jit|exec)|region_tracker_init|shrink|split|resize|trim|zone|free.*zone|"
    r"same_va|imported|dma_buf|user_buffer|overlap)\b",
    re.IGNORECASE,
)
_SUCCESS_FD_RE = re.compile(r"\b(?:anon_inode_getfd|get_unused_fd_flags|fd_install|sync_fence_fdget|fdget)\s*\(", re.IGNORECASE)
_JIT_STATE_RE = re.compile(
    r"\b(?:jit|jit_alloc|jit_free|jit_active|jit_pool|jit_list|evict_list|pending_alloc|"
    r"jit_allow_allocate|kbase_jit_(?:allocate|free))\b",
    re.IGNORECASE,
)
_TEARDOWN_ORDER_RE = re.compile(
    r"\b(?:context.*term|common_term|region_tracker_term|mmu_term|schedule_out|sched.*out|"
    r"disable.*as|as.*disable|address.*space|free.*region|va_region|mmu.*teardown)\b",
    re.IGNORECASE,
)
_MMU_LOCKDROP_UNLOCK_RE = re.compile(
    r"\b(?:mutex_unlock|spin_unlock(?:_irqrestore|_irq)?|up_read|up_write|"
    r"read_unlock|write_unlock)\s*\([^;\n]*(?:mmu|mmap|vm|region|reg|lock|sem)[^;\n]*\)",
    re.IGNORECASE,
)
_MMU_LOCKDROP_RELOCK_RE = re.compile(
    r"\b(?:mutex_lock|spin_lock(?:_irqsave|_irq)?|down_read|down_write|"
    r"read_lock|write_lock)\s*\([^;\n]*(?:mmu|mmap|vm|region|reg|lock|sem)[^;\n]*\)",
    re.IGNORECASE,
)
_MMU_STALE_ASSIGN_RE = re.compile(
    r"\b(?P<var>(?:reg|region|alloc|old|tmp|parent|pgd|pmd|pte|metadata|meta|page|phys|pfn)"
    r"[A-Za-z0-9_]*)\s*=\s*[^;\n]*(?:->|\[|page_private|folio_get_private|"
    r"kbase_region|kbase_mem|pgd|pmd|pte|metadata)",
    re.IGNORECASE,
)
_MMU_STALE_REVALIDATE_RE = re.compile(
    r"\b(?:find|lookup|validate|verify|WARN_ON|BUG_ON|VM_BUG_ON|"
    r"if\s*\([^)]*(?:reg|region|alloc|pgd|pmd|pte|metadata|page)[^)]*(?:!=|==|NULL|valid|find))",
    re.IGNORECASE,
)
_MMU_TEARDOWN_FREE_RE = re.compile(
    r"\b(?:region_tracker_term|kbase_mmu_term|free.*region|kbase_free_alloced_region|"
    r"rb_erase|kbase_mmu_teardown|free_pgd|pgd_free|pmd_free|pte_free|"
    r"free_page_table|free.*pgd|free.*pmd|free.*pte)\w*\s*\(",
    re.IGNORECASE,
)
_HW_QUIESCE_RE = re.compile(
    r"\b(?:schedule_out|sched.*out|disable.*as|as.*disable|disable_as|mmu_disable|"
    r"cache_flush|flush_cache|flush.*cache|kbase_gpu_cache|tlb|quiesce|stop.*gpu|"
    r"wait.*idle|drain.*gpu|as_busy|address.*space.*disable)\b",
    re.IGNORECASE,
)
_PARTIAL_MAPPING_INSTALL_RE = re.compile(
    r"\b(?:insert_pages|mmu_insert|map_pages|alias|remap|vm_insert|vmf_insert|insert_pfn|"
    r"vmap|map_attachment|kbase_mmu_insert|kbase_mmu_update|kbase_mmu_insert_pages)\w*\s*\(",
    re.IGNORECASE,
)
_PARTIAL_MAPPING_ROLLBACK_RE = re.compile(
    r"\b(?:unmap|zap|teardown|rollback|invalidate|flush|cache|kbase_mmu_teardown|"
    r"kbase_mmu_update|kbase_mmu_flush|put_page|free_pages)\w*\s*\(",
    re.IGNORECASE,
)
_MIGRATION_METADATA_RE = re.compile(
    r"\b(?:migration|migrate|movable|isolate|shrink|shrinker|compact|compaction|"
    r"page_private|folio_get_private|metadata|dma_addr_t|huge|2mb|2m|compound)\b",
    re.IGNORECASE,
)
_QUEUE_PUBLISH_RE = re.compile(
    r"\b(?:kcpu_queues|queue_new|in_use|inuse|bitmap|array|slots?|queue\s*\[|"
    r"set_bit|bitmap_set|atomic_set)\b",
    re.IGNORECASE,
)
_DEBUGFS_AUTH_RE = re.compile(
    r"\b(?:debugfs_create_file|debugfs|timeline|tlstream|profil(?:e|ing)|S_IRUGO|0444|"
    r"\w*timeline_io_acquire|capable|ptrace_may_access|S_IWUSR|0600)\b",
    re.IGNORECASE,
)
_BUS_FAULT_REPORT_RE = re.compile(
    r"\b(?:kbase_gpu_report_bus_fault_and_kill|bus[_\s-]*fault|cacheability|shareability|"
    r"fault->addr|fault\.addr|PA\s*0x|physical address)\b",
    re.IGNORECASE,
)
_DOMAIN_ROOT_TOKENS = frozenset({
    "doorbell", "queue", "fault", "irq", "interrupt", "slot", "atom", "pm",
    "runtime", "power", "clock", "clk", "same_va", "imported", "umm",
    "dma_buf", "protected", "protm", "mmu", "page_private", "start_pfn", "tracker",
    "hwaccess", "hwcnt", "backend", "suspend", "drain_queue", "group_suspend",
    "cqs_wait", "alias", "nents", "stride", "pfn", "phys", "dma",
    "sus_buf", "normal_suspend_buf", "clear_fault", "native", "vmap_prot",
    "active_protm_grp", "zero_count",
    "user_buffer", "zone", "jit", "mem_pool", "oom", "fd", "debugfs",
    "tlstream", "bus_fault", "kcpu_queue", "pgd", "pmd", "pte",
    "migration", "shrinker", "compaction", "quiesce", "partial_mapping",
})
_MMU_RECOVERY_WORDS = frozenset({"mmu", "insert", "pages", "recovery", "rollback", "failure", "phys", "unmap"})
_MMU_RECOVERY_LOOP_RE = re.compile(r"\b(?:for|while)\s*\([^)]*(?:i|idx|page|count|nr|remain)[^)]*(?:<|>|<=|>=|--|\+\+)", re.IGNORECASE)
_MMU_RECOVERY_ACTION_RE = re.compile(r"\b(?:unmap|zap|clear|write|free|put|rollback|recover|pte|pgd|pfn|phys)\w*\s*\(", re.IGNORECASE)
_PARTIAL_VULN_ALIASES = {
    "wrong_flag_semantic": "wrong_constant",
    "callback_lifecycle": "teardown_race",
    "file_ops_lifecycle_gap": "file_ops_lifecycle_gap",
    "allocation_overflow": "integer_overflow",
    "copy_contract": "copy_contract",
    "arithmetic_chain_mismatch": "arithmetic_chain_mismatch",
    "resource_binding_order": "resource_binding_order",
    "policy_gate_before_sink": "policy_gate_before_sink",
    "cross_file_lock_cycle": "cross_file_lock_cycle",
    "state_transition_protocol": "state_transition_protocol",
    "resource_validation_order": "resource_validation_order",
    "cleanup_ledger": "cleanup_ledger",
    "async_event_order": "async_event_order",
    "size_propagation": "size_propagation",
    "stale_tracker_state": "stale_tracker_state",
    "pm_runtime_sequence": "pm_runtime_sequence",
    "secondary_element_omission": "secondary_element_omission",
    "protected_mmu_protocol": "protected_mmu_protocol",
    "mmu_recovery_rollback": "mmu_recovery_rollback",
    "suspend_cleanup_ledger": "suspend_cleanup_ledger",
    "suspend_size_sink": "suspend_size_sink",
    "fault_clear_order": "fault_clear_order",
    "pm_callback_order": "pm_callback_order",
    "region_replace_erase": "region_replace_erase",
    "imported_mapping_policy": "imported_mapping_policy",
    "alias_extent_mismatch": "alias_extent_mismatch",
    "named_lock_inversion": "named_lock_inversion",
    "active_singleton_stale": "active_singleton_stale",
    "zero_count_underflow": "zero_count_underflow",
    "owner_liveness_allocation": "owner_liveness_allocation",
    "user_buffer_permission": "user_buffer_permission",
    "zone_shrink_validation": "zone_shrink_validation",
    "success_path_cleanup": "success_path_cleanup",
    "jit_lock_protocol": "jit_lock_protocol",
    "teardown_order": "teardown_order",
    "queue_publish_init": "queue_publish_init",
    "fd_reuse_race": "fd_reuse_race",
    "debugfs_permission": "debugfs_permission",
    "mmu_lockdrop_stale": "mmu_lockdrop_stale",
    "mmu_teardown_order": "mmu_teardown_order",
    "partial_mapping_rollback": "partial_mapping_rollback",
    "migration_metadata_race": "migration_metadata_race",
    "sentinel_misuse": "wrong_constant",
}
_PARTIAL_CWE_OVERRIDES = {
    "width_mismatch": "CWE-681",
    "stale_length": "CWE-131",
    "info_leak": "CWE-532",
    "wrong_constant": "CWE-697",
    "wrong_flag_semantic": "CWE-697",
    "copy_contract": "CWE-120",
    "arithmetic_chain_mismatch": "CWE-190",
    "resource_binding_order": "CWE-696",
    "policy_gate_before_sink": "CWE-284",
    "resource_validation_order": "CWE-696",
    "cleanup_ledger": "CWE-459",
    "async_event_order": "CWE-362",
    "size_propagation": "CWE-131",
    "stale_tracker_state": "CWE-664",
    "pm_runtime_sequence": "CWE-696",
    "secondary_element_omission": "CWE-670",
    "protected_mmu_protocol": "CWE-696",
    "mmu_recovery_rollback": "CWE-193",
    "suspend_cleanup_ledger": "CWE-459",
    "suspend_size_sink": "CWE-131",
    "fault_clear_order": "CWE-362",
    "pm_callback_order": "CWE-696",
    "region_replace_erase": "CWE-664",
    "imported_mapping_policy": "CWE-284",
    "alias_extent_mismatch": "CWE-190",
    "named_lock_inversion": "CWE-833",
    "active_singleton_stale": "CWE-416",
    "zero_count_underflow": "CWE-191",
    "owner_liveness_allocation": "CWE-400",
    "user_buffer_permission": "CWE-863",
    "zone_shrink_validation": "CWE-787",
    "success_path_cleanup": "CWE-401",
    "jit_lock_protocol": "CWE-362",
    "teardown_order": "CWE-416",
    "queue_publish_init": "CWE-416",
    "fd_reuse_race": "CWE-362",
    "debugfs_permission": "CWE-862",
    "mmu_lockdrop_stale": "CWE-416",
    "mmu_teardown_order": "CWE-416",
    "partial_mapping_rollback": "CWE-459",
    "migration_metadata_race": "CWE-362",
    "accounting_drift": "CWE-682",
    "missing_lock": "CWE-820",
    "state_order": "CWE-696",
    "ordering_gap": "CWE-696",
    "cross_file_lock_cycle": "CWE-833",
    "state_transition_protocol": "CWE-696",
    "teardown_race": "CWE-362",
    "callback_lifecycle": "CWE-362",
    "deferred_uaf": "CWE-416",
    "integer_overflow": "CWE-190",
    "partial_cleanup": "CWE-459",
    "rollback_gap": "CWE-460",
    "file_ops_lifecycle_gap": "CWE-362",
    "format_string": "CWE-134",
    "path_traversal": "CWE-22",
    "command_injection": "CWE-78",
}
_PARTIAL_PASS_PRIORITY = {
    "partial_format_and_info_leak": 0,
    "partial_state_publication": 1,
    "partial_publish_rollback": 2,
    "partial_copy_contract": 3,
    "partial_cleanup_symmetry": 4,
    "partial_suspend_cleanup_ledger": 5,
    "partial_accounting_drift": 6,
    "partial_cleanup_ledger": 7,
    "partial_suspend_size_sink": 8,
    "partial_alias_extent_mismatch": 9,
    "partial_resource_validation_order": 10,
    "partial_arithmetic_chain_mismatch": 11,
    "partial_size_propagation": 12,
    "partial_fault_clear_order": 13,
    "partial_pm_callback_order": 14,
    "partial_resource_binding_order": 15,
    "partial_async_event_order": 16,
    "partial_stale_tracker_state": 17,
    "partial_region_replace_erase": 18,
    "partial_metadata_type_confusion": 19,
    "partial_pm_runtime_sequence": 20,
    "partial_secondary_element_omission": 21,
    "partial_zero_count_underflow": 22,
    "partial_policy_gate_before_sink": 23,
    "partial_imported_mapping_policy": 24,
    "partial_sentinel_misuse": 25,
    "partial_active_singleton_stale": 26,
    "partial_protected_mmu_protocol": 27,
    "partial_named_lock_inversion": 28,
    "partial_mmu_recovery_rollback": 29,
    "partial_mmu_lockdrop_stale": 30,
    "partial_mmu_teardown_order": 31,
    "partial_partial_mapping_rollback": 32,
    "partial_migration_metadata_race": 33,
    "partial_owner_liveness_allocation": 34,
    "partial_user_buffer_permission": 35,
    "partial_zone_shrink_validation": 36,
    "partial_success_path_cleanup": 37,
    "partial_jit_lock_protocol": 38,
    "partial_teardown_order": 39,
    "partial_queue_publish_init": 40,
    "partial_fd_reuse_race": 41,
    "partial_debugfs_permission": 42,
    "partial_allocation_arithmetic": 43,
    "partial_fops_lifecycle": 44,
    "partial_cross_file_lock_cycle": 45,
    "partial_state_transition_protocol": 46,
    "partial_partial_exact_fallback": 47,
    "partial_lock_and_stale": 48,
    "partial_lifecycle": 49,
    "partial_shared_state": 50,
    "partial_inbound_contract": 51,
    "partial_outbound_misuse": 52,
    "partial_target_intra": 53,
    "partial_concurrency": 54,
}


@dataclass
class SymbolDef:
    name: str
    file_path: str
    line_number: int
    signature: str = ""
    body_start: int = 0
    body_end: int = 0


@dataclass
class SymbolMeta:
    has_security_api: bool = False
    has_lifecycle_words: bool = False
    has_callback_words: bool = False
    has_lock_api: bool = False
    has_protocol_words: bool = False
    has_notifier_words: bool = False
    is_source_like: bool = False
    is_sink_like: bool = False
    sink_type_hint: str = ""


@dataclass
class CallSite:
    caller_name: str
    caller_file: str
    caller_line: int
    callee_name: str
    line_number: int
    line_text: str = ""


@dataclass
class FieldUse:
    field: str
    file_path: str
    function_name: str
    line_number: int
    line_text: str = ""


@dataclass(frozen=True)
class LockOrderEdge:
    first_lock: str
    second_lock: str
    file_path: str
    function_name: str
    line_number: int
    line_text: str = ""


@dataclass(frozen=True)
class CopyUse:
    api: str
    line_number: int
    dst_expr: str = ""
    src_expr: str = ""
    size_expr: str = ""
    line_text: str = ""


@dataclass(frozen=True)
class GuardFact:
    token: str
    lhs: str
    op: str
    rhs: str
    line_number: int
    line_text: str = ""


@dataclass(frozen=True)
class AssignmentFact:
    target: str
    value: str
    tokens: tuple[str, ...]
    line_number: int
    line_text: str = ""
    is_field: bool = False
    is_arithmetic: bool = False


@dataclass(frozen=True)
class CleanupFact:
    action: str
    kind: str
    resource: str
    line_number: int
    line_text: str = ""


@dataclass(frozen=True)
class SinkFact:
    api: str
    token: str
    line_number: int
    line_text: str = ""


@dataclass(frozen=True)
class EventFact:
    kind: str
    token: str
    line_number: int
    line_text: str = ""
    detail: str = ""


@dataclass(frozen=True)
class FormulaFact:
    target: str
    expr: str
    normalized: str
    tokens: tuple[str, ...]
    operators: tuple[str, ...]
    line_number: int
    line_text: str = ""


@dataclass(frozen=True)
class CastFact:
    target: str
    target_type: str
    source: str
    line_number: int
    line_text: str = ""


@dataclass(frozen=True)
class SentinelFact:
    expr: str
    value: str
    token: str
    line_number: int
    line_text: str = ""


@dataclass
class SymbolIndex:
    definitions: dict[str, list[SymbolDef]]
    callsites: dict[str, list[CallSite]]
    field_uses: dict[str, list[FieldUse]]
    globals: list[GlobalConstruct]
    files_indexed: int = 0
    defs_by_file: dict[str, list[SymbolDef]] = field(default_factory=dict)
    defs_by_file_and_name: dict[tuple[str, str], SymbolDef] = field(default_factory=dict)
    calls_by_caller: dict[tuple[str, str], list[str]] = field(default_factory=dict)
    field_uses_by_file: dict[str, list[FieldUse]] = field(default_factory=dict)
    locks_by_symbol: dict[str, list[str]] = field(default_factory=dict)
    lock_edges_by_symbol: dict[str, list[LockOrderEdge]] = field(default_factory=dict)
    symbols_by_lock: dict[str, list[SymbolDef]] = field(default_factory=dict)
    state_tokens_by_symbol: dict[str, list[str]] = field(default_factory=dict)
    symbols_by_state_token: dict[str, list[SymbolDef]] = field(default_factory=dict)
    copy_uses_by_symbol: dict[str, list[CopyUse]] = field(default_factory=dict)
    guards_by_symbol: dict[str, list[GuardFact]] = field(default_factory=dict)
    assignments_by_symbol: dict[str, list[AssignmentFact]] = field(default_factory=dict)
    cleanup_facts_by_symbol: dict[str, list[CleanupFact]] = field(default_factory=dict)
    sink_facts_by_symbol: dict[str, list[SinkFact]] = field(default_factory=dict)
    event_facts_by_symbol: dict[str, list[EventFact]] = field(default_factory=dict)
    formula_facts_by_symbol: dict[str, list[FormulaFact]] = field(default_factory=dict)
    cast_facts_by_symbol: dict[str, list[CastFact]] = field(default_factory=dict)
    sentinel_facts_by_symbol: dict[str, list[SentinelFact]] = field(default_factory=dict)
    symbols_by_guard_token: dict[str, list[SymbolDef]] = field(default_factory=dict)
    symbols_by_sink_token: dict[str, list[SymbolDef]] = field(default_factory=dict)
    symbols_by_event_token: dict[str, list[SymbolDef]] = field(default_factory=dict)
    meta_by_symbol: dict[str, SymbolMeta] = field(default_factory=dict)
    lifecycle_symbols: list[SymbolDef] = field(default_factory=list)
    callback_symbols: list[SymbolDef] = field(default_factory=list)
    notifier_related_symbols: list[SymbolDef] = field(default_factory=list)
    security_symbols: list[SymbolDef] = field(default_factory=list)


@dataclass
class PartialReviewContext:
    target_file: str
    target_nodes: list[FunctionNode]
    inbound_callers: list[FunctionNode]
    outbound_callees: list[FunctionNode]
    shared_state_nodes: list[FunctionNode]
    lifecycle_pair_nodes: list[FunctionNode]
    callback_nodes: list[FunctionNode]
    companion_nodes: list[FunctionNode]
    globals: list[GlobalConstruct]
    candidate_paths: list[ReachabilityPath]


@dataclass
class PartialDetectorResult:
    state_publication_notes: list[str] = None
    publish_rollback_notes: list[str] = None
    allocation_arithmetic_notes: list[str] = None
    format_notes: list[str] = None
    info_leak_notes: list[str] = None
    fops_notes: list[str] = None
    lock_order_notes: list[str] = None
    stale_after_unlock_notes: list[str] = None
    disable_stale_notes: list[str] = None
    callback_lifetime_notes: list[str] = None
    cross_file_lock_notes: list[str] = None
    protocol_notes: list[str] = None
    copy_contract_notes: list[str] = None
    cleanup_symmetry_notes: list[str] = None
    accounting_drift_notes: list[str] = None
    arithmetic_chain_notes: list[str] = None
    resource_binding_notes: list[str] = None
    policy_gate_notes: list[str] = None
    resource_validation_notes: list[str] = None
    cleanup_ledger_notes: list[str] = None
    async_order_notes: list[str] = None
    size_propagation_notes: list[str] = None
    stale_tracker_notes: list[str] = None
    metadata_type_confusion_notes: list[str] = None
    pm_sequence_notes: list[str] = None
    secondary_omission_notes: list[str] = None
    protected_mmu_notes: list[str] = None
    mmu_recovery_notes: list[str] = None
    sentinel_misuse_notes: list[str] = None
    suspend_cleanup_ledger_notes: list[str] = None
    suspend_size_sink_notes: list[str] = None
    fault_clear_order_notes: list[str] = None
    pm_callback_order_notes: list[str] = None
    region_replace_erase_notes: list[str] = None
    imported_mapping_policy_notes: list[str] = None
    alias_extent_mismatch_notes: list[str] = None
    named_lock_inversion_notes: list[str] = None
    active_singleton_stale_notes: list[str] = None
    zero_count_underflow_notes: list[str] = None
    owner_liveness_notes: list[str] = None
    user_buffer_permission_notes: list[str] = None
    zone_shrink_notes: list[str] = None
    success_path_cleanup_notes: list[str] = None
    jit_lock_protocol_notes: list[str] = None
    teardown_order_notes: list[str] = None
    queue_publish_init_notes: list[str] = None
    fd_reuse_notes: list[str] = None
    debugfs_permission_notes: list[str] = None
    mmu_lockdrop_stale_notes: list[str] = None
    mmu_teardown_order_notes: list[str] = None
    partial_mapping_rollback_notes: list[str] = None
    migration_metadata_race_notes: list[str] = None
    nodes: list[FunctionNode] = None
    globals: list[GlobalConstruct] = None

    def __post_init__(self):
        for name in (
            "state_publication_notes", "publish_rollback_notes",
            "allocation_arithmetic_notes", "format_notes", "info_leak_notes",
            "fops_notes", "lock_order_notes", "stale_after_unlock_notes",
            "disable_stale_notes", "callback_lifetime_notes",
            "cross_file_lock_notes", "protocol_notes", "copy_contract_notes",
            "cleanup_symmetry_notes", "accounting_drift_notes",
            "arithmetic_chain_notes", "resource_binding_notes",
            "policy_gate_notes", "resource_validation_notes",
            "cleanup_ledger_notes", "async_order_notes", "size_propagation_notes",
            "stale_tracker_notes", "metadata_type_confusion_notes", "pm_sequence_notes",
            "secondary_omission_notes", "protected_mmu_notes", "mmu_recovery_notes",
            "sentinel_misuse_notes",
            "suspend_cleanup_ledger_notes", "suspend_size_sink_notes",
            "fault_clear_order_notes", "pm_callback_order_notes",
            "region_replace_erase_notes", "imported_mapping_policy_notes",
            "alias_extent_mismatch_notes", "named_lock_inversion_notes",
            "active_singleton_stale_notes", "zero_count_underflow_notes",
            "owner_liveness_notes", "user_buffer_permission_notes", "zone_shrink_notes",
            "success_path_cleanup_notes", "jit_lock_protocol_notes", "teardown_order_notes",
            "queue_publish_init_notes", "fd_reuse_notes", "debugfs_permission_notes",
            "mmu_lockdrop_stale_notes", "mmu_teardown_order_notes",
            "partial_mapping_rollback_notes", "migration_metadata_race_notes",
            "nodes", "globals",
        ):
            if getattr(self, name) is None:
                setattr(self, name, [])

    def count(self, name: str) -> int:
        return len(getattr(self, name, []) or [])


@dataclass
class PartialPostFilterStats:
    suppressed_null: int = 0
    suppressed_lock: int = 0
    suppressed_generic: int = 0
    suppressed_non_target: int = 0


@dataclass
class PartialContextCaps:
    max_inbound: int = 80
    max_outbound: int = 80
    max_shared: int = 120
    max_lifecycle: int = 80
    max_callbacks: int = 80
    max_companions: int = 48
    max_total_context_functions: int = 250


def _rel_path(path: str, codebase_path: str) -> str:
    base = os.path.abspath(codebase_path)
    abs_path = path if os.path.isabs(path) else os.path.join(base, path)
    return os.path.relpath(os.path.abspath(abs_path), base).replace("\\", "/")


def _abs_path(rel_or_abs: str, codebase_path: str) -> str:
    if os.path.isabs(rel_or_abs):
        return os.path.abspath(rel_or_abs)
    return os.path.abspath(os.path.join(codebase_path, rel_or_abs))


def _line_number_at(text: str, index: int) -> int:
    return text[:index].count("\n") + 1


def _find_body_end(text: str, open_brace_index: int) -> tuple[int, int]:
    depth = 0
    quote = None
    escape = False
    for idx in range(open_brace_index, len(text)):
        ch = text[idx]
        if quote:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = None
            continue
        if ch in ("'", '"'):
            quote = ch
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth <= 0:
                return idx, _line_number_at(text, idx)
    return len(text), text.count("\n") + 1


def _body_lines(content: str, sym: SymbolDef) -> list[str]:
    lines = content.splitlines()
    return _body_lines_from_lines(lines, sym)


def _body_lines_from_lines(lines: list[str], sym: SymbolDef) -> list[str]:
    start = max(0, sym.body_start - 1)
    end = min(len(lines), max(sym.body_end, sym.body_start))
    return lines[start:end]


def _symbol_unique_name(sym: SymbolDef) -> str:
    return f"{sym.file_path}::{sym.name}"


def _tokens(name: str) -> list[str]:
    return [t for t in re.split(r"[^a-z0-9]+", str(name or "").lower()) if t]


def _module_stem(name: str) -> str:
    parts = _tokens(name)
    while parts and parts[-1] in _LIFECYCLE_WORDS:
        parts.pop()
    return "_".join(parts[:3]) if parts else str(name or "").lower()


def _name_has_any(name: str, words: set[str] | frozenset[str]) -> bool:
    lowered = str(name or "").lower()
    return any(word in lowered for word in words)


def _canonical_protocol_token(token: str) -> str:
    token = str(token or "").lower()
    if token.endswith("ing") and token[:-3] in _PROTOCOL_TOKEN_WORDS:
        token = token[:-3]
    elif token.endswith("ed") and token[:-2] in _PROTOCOL_TOKEN_WORDS:
        token = token[:-2]
    return _PROTOCOL_TOKEN_ALIASES.get(token, token)


def _protocol_tokens_from_text(text: str) -> list[str]:
    tokens = []
    for match in _PROTOCOL_TOKEN_RE.finditer(str(text or "")):
        raw = match.group(0).lower()
        for token in _tokens(raw):
            canonical = _canonical_protocol_token(token)
            if canonical in _PROTOCOL_TOKEN_WORDS:
                tokens.append(canonical)
    return list(dict.fromkeys(tokens))


def _notifier_related_text(text: str) -> bool:
    return bool(_NOTIFIER_RE.search(str(text or "")))


def _fact_tokens(text: str) -> set[str]:
    return {
        _canonical_protocol_token(t)
        for t in _tokens(text)
        if len(t) > 1
    }


def _has_any_fact_token(text: str, words: frozenset[str] | set[str]) -> bool:
    return bool(_fact_tokens(text) & set(words))


def _short_expr(expr: str, limit: int = 90) -> str:
    return " ".join(str(expr or "").split())[:limit]


def _formula_operators(expr: str) -> tuple[str, ...]:
    text = str(expr or "")
    ops = []
    if "*" in text:
        ops.append("mul")
    if "<<" in text or ">>" in text or "PAGE_SHIFT" in text:
        ops.append("shift")
    if _PAGE_ROUND_RE.search(text):
        ops.append("round")
    if re.search(r"\bsizeof\s*\(", text):
        ops.append("sizeof")
    if "+" in text or "-" in text:
        ops.append("add")
    return tuple(dict.fromkeys(ops))


def _normalise_formula_expr(expr: str) -> str:
    text = str(expr or "").lower()
    text = re.sub(r"/\*.*?\*/", "", text)
    text = re.sub(r"\bsizeof\s*\([^)]*\)", "sizeof", text)
    text = re.sub(r"\b(?:pfn_up|pfn_down|div_round_up|page_align|round_up|round_down)\s*\(", "round(", text)
    text = re.sub(r"\bpage_shift\b", "page_shift", text)
    text = re.sub(r"0x[0-9a-f]+|\b\d+\b", "num", text)
    text = text.replace("->", ".")
    text = re.sub(r"\s+", "", text)
    return text[:180]


def _function_body_from_symbol(codebase_path: str, sym: SymbolDef, max_chars: int = 5000) -> str:
    node = FunctionNode(
        unique_name=f"{sym.file_path}::{sym.name}",
        file_path=sym.file_path,
        name=sym.name,
        line_number=sym.line_number,
        is_source=False,
        is_sink=False,
    )
    return _read_function_body(codebase_path, node, max_chars=max_chars)


def _normalise_partial_vuln_type(raw) -> str:
    text = str(raw or "other").strip().lower().replace("-", "_").replace(" ", "_")
    return _PARTIAL_VULN_ALIASES.get(text, _normalise_vuln_type(text))


def _split_args(args_text: str) -> list[str]:
    args, current = [], []
    depth = 0
    quote = None
    escape = False
    for ch in str(args_text or ""):
        if quote:
            current.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = None
            continue
        if ch in ("'", '"'):
            quote = ch
            current.append(ch)
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}" and depth > 0:
            depth -= 1
        if ch == "," and depth == 0:
            args.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
    if current or args_text:
        args.append("".join(current).strip())
    return args


def _first_call_args(line: str, fn_name: str) -> list[str]:
    match = re.search(r"\b" + re.escape(fn_name) + r"\s*\((.*)\)", line)
    return _split_args(match.group(1)) if match else []


def _is_string_literal(expr: str) -> bool:
    expr = str(expr or "").strip()
    return bool(re.match(r'^(?:L|u8|u|U)?"(?:\\.|[^"\\])*"$', expr))


def _line_excerpt(line: str, limit: int = 180) -> str:
    text = " ".join(str(line or "").strip().split())
    return text[:limit]


def _normalise_lock_expr(expr: str) -> str:
    expr = re.sub(r"/\*.*?\*/", "", str(expr or ""))
    expr = re.sub(r"\s+", "", expr).strip("&()")
    expr = re.sub(r"^\([^)]*\)", "", expr)
    expr = expr.replace("->", ".").strip("&()")
    if not expr:
        return ""
    for stable in (
        "hwaccess_lock", "scheduler_lock", "clk_rtm.lock", "hwcnt.lock",
        "backend.lock", "state_lock", "state.lock", "ctx.lock", "queue.lock",
        "pm.lock", "mmu.lock", "mmu_hw_mutex",
    ):
        if stable in expr:
            return stable
    if "clk_rtm" in expr and "lock" in expr:
        return "clk_rtm.lock"
    if "hwaccess" in expr and "lock" in expr:
        return "hwaccess_lock"
    if ("hwcnt" in expr or "backend" in expr) and "state" in expr and "lock" in expr:
        return "hwcnt_state.lock"
    if "hwcnt" in expr and "lock" in expr:
        return "hwcnt.lock"
    if "backend" in expr and "lock" in expr:
        return "backend.lock"
    if expr.endswith(".lock"):
        return ".".join(expr.split(".")[-2:])
    return expr


def _partial_note_tokens(text: str) -> set[str]:
    return {
        t for t in re.split(r"[^a-z0-9]+", str(text or "").lower())
        if len(t) > 2 and t not in {"the", "and", "for", "with", "from", "this", "that"}
    }


def _domain_root_tokens(text: str) -> set[str]:
    tokens = _fact_tokens(text)
    if "page" in tokens and "private" in tokens:
        tokens.add("page_private")
    if "same" in tokens and "va" in tokens:
        tokens.add("same_va")
    if "drain" in tokens and "queue" in tokens:
        tokens.add("drain_queue")
    if "group" in tokens and "suspend" in tokens:
        tokens.add("group_suspend")
    if "cqs" in tokens and "wait" in tokens:
        tokens.add("cqs_wait")
    if "sus" in tokens and "buf" in tokens:
        tokens.add("sus_buf")
    if "normal" in tokens and "suspend" in tokens and "buf" in tokens:
        tokens.add("normal_suspend_buf")
    if "clear" in tokens and "fault" in tokens:
        tokens.add("clear_fault")
    if "vmap" in tokens and "prot" in tokens:
        tokens.add("vmap_prot")
    if "active" in tokens and ("protm" in tokens or "protected" in tokens) and ("grp" in tokens or "group" in tokens):
        tokens.add("active_protm_grp")
    if "zero" in tokens and "count" in tokens:
        tokens.add("zero_count")
    if "user" in tokens and "buffer" in tokens:
        tokens.add("user_buffer")
    if "mem" in tokens and "pool" in tokens:
        tokens.add("mem_pool")
    if "bus" in tokens and "fault" in tokens:
        tokens.add("bus_fault")
    if "kcpu" in tokens and "queue" in tokens:
        tokens.add("kcpu_queue")
    if "partial" in tokens and ("mapping" in tokens or "map" in tokens):
        tokens.add("partial_mapping")
    return tokens & _DOMAIN_ROOT_TOKENS


class PartialAnalysisCache:
    """Shared per-review cache for partial single-file analysis."""

    def __init__(self, codebase_path: str, index: SymbolIndex | None = None):
        self._cb = os.path.abspath(codebase_path)
        self._index = index
        self._lock = threading.RLock()
        self._content_by_file: dict[str, str] = {}
        self._lines_by_file: dict[str, list[str]] = {}
        self._body_by_symbol: dict[tuple[str, int, bool], str] = {}
        self._node_by_symbol: dict[str, FunctionNode] = {}
        self._fallback_body_by_node: dict[tuple[str, int], str] = {}

    def bind_index(self, index: SymbolIndex | None):
        if index is not None:
            with self._lock:
                if self._index is None:
                    self._index = index

    def content(self, rel_file: str) -> str:
        rel = self._normalise_rel(rel_file)
        with self._lock:
            cached = self._content_by_file.get(rel)
        if cached is not None:
            return cached
        content = read_file_content(_abs_path(rel, self._cb)) or ""
        with self._lock:
            return self._content_by_file.setdefault(rel, content)

    def file_lines(self, rel_file: str) -> list[str]:
        rel = self._normalise_rel(rel_file)
        with self._lock:
            cached = self._lines_by_file.get(rel)
        if cached is not None:
            return cached
        lines = self.content(rel).splitlines()
        with self._lock:
            return self._lines_by_file.setdefault(rel, lines)

    def symbol_lines(self, sym: SymbolDef) -> list[tuple[int, str]]:
        lines = self.file_lines(sym.file_path)
        if sym.body_start > 0 and sym.body_end >= sym.body_start:
            start = max(0, sym.body_start - 1)
            end = min(len(lines), max(sym.body_end, sym.body_start))
            return [(start + offset + 1, line) for offset, line in enumerate(lines[start:end])]
        body = self.symbol_body(sym, max_chars=12000, numbered=False)
        return [(sym.line_number + offset, line) for offset, line in enumerate(body.splitlines())]

    def symbol_body(self, sym: SymbolDef, max_chars: int | None = None, *, numbered: bool = False) -> str:
        unique = _symbol_unique_name(sym)
        limit = -1 if max_chars is None else int(max_chars)
        key = (unique, limit, numbered)
        with self._lock:
            cached = self._body_by_symbol.get(key)
        if cached is not None:
            return cached

        if sym.body_start > 0 and sym.body_end >= sym.body_start:
            pairs = self.symbol_lines(sym)
            if numbered:
                body = "\n".join(f"{line_no}: {line}" for line_no, line in pairs)
            else:
                body = "\n".join(line for _, line in pairs)
            if max_chars is not None and len(body) > max_chars:
                body = body[:max_chars] + "\n"
        else:
            node = FunctionNode(
                unique_name=unique,
                file_path=sym.file_path,
                name=sym.name,
                line_number=sym.line_number,
                is_source=False,
                is_sink=False,
            )
            body = _read_function_body(self._cb, node, max_chars=max_chars or 3000)
            if not numbered:
                body = re.sub(r"(?m)^\s*\d+:\s?", "", body)

        with self._lock:
            return self._body_by_symbol.setdefault(key, body)

    def symbol_for_node(self, index: SymbolIndex | None, node: FunctionNode) -> SymbolDef | None:
        index = index or self._index
        if index is None:
            return None
        return _lookup_symbol(index, self._normalise_rel(node.file_path), node.name)

    def node_body(self, node: FunctionNode, *, max_chars: int = 3000) -> str:
        sym = self.symbol_for_node(self._index, node)
        if sym:
            return self.symbol_body(sym, max_chars=max_chars, numbered=True)
        unique = node.unique_name or f"{node.file_path}::{node.name}"
        key = (unique, int(max_chars))
        with self._lock:
            cached = self._fallback_body_by_node.get(key)
        if cached is not None:
            return cached
        body = _read_function_body(self._cb, node, max_chars=max_chars)
        with self._lock:
            return self._fallback_body_by_node.setdefault(key, body)

    def node_for_symbol(self, index: SymbolIndex | None, sym: SymbolDef) -> FunctionNode:
        index = index or self._index
        unique = _symbol_unique_name(sym)
        with self._lock:
            cached = self._node_by_symbol.get(unique)
        if cached is not None:
            return cached

        calls = _symbol_calls(index, sym) if index else []
        meta = index.meta_by_symbol.get(unique) if index else None
        if meta:
            is_source = meta.is_source_like
            is_sink = meta.is_sink_like
            sink_type = meta.sink_type_hint if is_sink else ""
        else:
            body = self.symbol_body(sym, max_chars=8000, numbered=False)
            match_text = f"{sym.name} {' '.join(calls)} {body}"
            is_source = bool(_SOURCE_RE.search(match_text))
            is_sink = bool(_SINK_KIND_RE.search(match_text) or _SECURITY_API_RE.search(match_text))
            sink_type = _sink_type_for_text(match_text) if is_sink else ""
        node = FunctionNode(
            unique_name=unique,
            file_path=sym.file_path,
            name=sym.name,
            line_number=sym.line_number,
            is_source=is_source,
            is_sink=is_sink,
            calls=calls,
            source_reason="deterministic source-like entry or external input use" if is_source else "",
            sink_type=sink_type,
            sink_reason="deterministic sink-like API/state/lifecycle use" if is_sink else "",
        )
        with self._lock:
            return self._node_by_symbol.setdefault(unique, node)

    def _normalise_rel(self, rel_file: str) -> str:
        rel = str(rel_file or "").replace("\\", "/")
        if os.path.isabs(rel):
            return _rel_path(rel, self._cb)
        return rel


class SymbolIndexBuilder:
    def build(self, files, codebase_path) -> SymbolIndex:
        definitions: dict[str, list[SymbolDef]] = defaultdict(list)
        callsites: dict[str, list[CallSite]] = defaultdict(list)
        field_uses: dict[str, list[FieldUse]] = defaultdict(list)
        field_uses_by_file: dict[str, list[FieldUse]] = defaultdict(list)
        defs_by_file: dict[str, list[SymbolDef]] = defaultdict(list)
        defs_by_file_and_name: dict[tuple[str, str], SymbolDef] = {}
        calls_by_caller: dict[tuple[str, str], list[str]] = {}
        locks_by_symbol: dict[str, list[str]] = {}
        lock_edges_by_symbol: dict[str, list[LockOrderEdge]] = {}
        symbols_by_lock: dict[str, list[SymbolDef]] = defaultdict(list)
        state_tokens_by_symbol: dict[str, list[str]] = {}
        symbols_by_state_token: dict[str, list[SymbolDef]] = defaultdict(list)
        copy_uses_by_symbol: dict[str, list[CopyUse]] = {}
        guards_by_symbol: dict[str, list[GuardFact]] = {}
        assignments_by_symbol: dict[str, list[AssignmentFact]] = {}
        cleanup_facts_by_symbol: dict[str, list[CleanupFact]] = {}
        sink_facts_by_symbol: dict[str, list[SinkFact]] = {}
        event_facts_by_symbol: dict[str, list[EventFact]] = {}
        formula_facts_by_symbol: dict[str, list[FormulaFact]] = {}
        cast_facts_by_symbol: dict[str, list[CastFact]] = {}
        sentinel_facts_by_symbol: dict[str, list[SentinelFact]] = {}
        symbols_by_guard_token: dict[str, list[SymbolDef]] = defaultdict(list)
        symbols_by_sink_token: dict[str, list[SymbolDef]] = defaultdict(list)
        symbols_by_event_token: dict[str, list[SymbolDef]] = defaultdict(list)
        meta_by_symbol: dict[str, SymbolMeta] = {}
        lifecycle_symbols: list[SymbolDef] = []
        callback_symbols: list[SymbolDef] = []
        notifier_related_symbols: list[SymbolDef] = []
        security_symbols: list[SymbolDef] = []
        globals_: list[GlobalConstruct] = []
        files_indexed = 0

        for file_path in files:
            rel = _rel_path(file_path, codebase_path)
            if os.path.splitext(rel)[1].lower() not in _C_CPP_EXTS:
                continue
            content = read_file_content(_abs_path(file_path, codebase_path))
            if not content:
                continue
            files_indexed += 1
            file_lines = content.splitlines()
            defs = self._extract_definitions(content, rel)
            for sym in defs:
                definitions[sym.name].append(sym)
                defs_by_file[sym.file_path].append(sym)
                defs_by_file_and_name.setdefault((sym.file_path, sym.name), sym)
                body_lines = _body_lines_from_lines(file_lines, sym)
                calls = self._extract_function_uses(body_lines, sym, callsites, field_uses, field_uses_by_file)
                caller_key = (sym.file_path, sym.name)
                calls_by_caller[caller_key] = list(dict.fromkeys(
                    calls_by_caller.get(caller_key, []) + calls
                ))
                locks, lock_edges, state_tokens = self._symbol_lock_and_protocol_metadata(sym, body_lines)
                unique = _symbol_unique_name(sym)
                locks_by_symbol[unique] = locks
                lock_edges_by_symbol[unique] = lock_edges
                state_tokens_by_symbol[unique] = state_tokens
                for lock in locks:
                    symbols_by_lock[lock].append(sym)
                for token in state_tokens:
                    symbols_by_state_token[token].append(sym)
                (
                    copy_uses, guards, assignments, cleanup_facts, sinks,
                    event_facts, formula_facts, cast_facts, sentinel_facts,
                ) = self._extract_semantic_facts(sym, body_lines)
                copy_uses_by_symbol[unique] = copy_uses
                guards_by_symbol[unique] = guards
                assignments_by_symbol[unique] = assignments
                cleanup_facts_by_symbol[unique] = cleanup_facts
                sink_facts_by_symbol[unique] = sinks
                event_facts_by_symbol[unique] = event_facts
                formula_facts_by_symbol[unique] = formula_facts
                cast_facts_by_symbol[unique] = cast_facts
                sentinel_facts_by_symbol[unique] = sentinel_facts
                for guard in guards:
                    symbols_by_guard_token[guard.token].append(sym)
                for sink in sinks:
                    symbols_by_sink_token[sink.token].append(sym)
                for event in event_facts:
                    symbols_by_event_token[event.token].append(sym)
                body_text = "\n".join(body_lines)
                meta = self._symbol_meta(sym, calls, body_text, locks, state_tokens)
                meta_by_symbol[unique] = meta
                if meta.has_lifecycle_words:
                    lifecycle_symbols.append(sym)
                if meta.has_callback_words:
                    callback_symbols.append(sym)
                if meta.has_notifier_words:
                    notifier_related_symbols.append(sym)
                if meta.has_security_api:
                    security_symbols.append(sym)
            globals_.extend(self._extract_globals(content, rel))

        return SymbolIndex(
            definitions=dict(definitions),
            callsites=dict(callsites),
            field_uses=dict(field_uses),
            globals=globals_,
            files_indexed=files_indexed,
            defs_by_file=dict(defs_by_file),
            defs_by_file_and_name=defs_by_file_and_name,
            calls_by_caller=calls_by_caller,
            field_uses_by_file=dict(field_uses_by_file),
            locks_by_symbol=locks_by_symbol,
            lock_edges_by_symbol=lock_edges_by_symbol,
            symbols_by_lock=dict(symbols_by_lock),
            state_tokens_by_symbol=state_tokens_by_symbol,
            symbols_by_state_token=dict(symbols_by_state_token),
            copy_uses_by_symbol=copy_uses_by_symbol,
            guards_by_symbol=guards_by_symbol,
            assignments_by_symbol=assignments_by_symbol,
            cleanup_facts_by_symbol=cleanup_facts_by_symbol,
            sink_facts_by_symbol=sink_facts_by_symbol,
            event_facts_by_symbol=event_facts_by_symbol,
            formula_facts_by_symbol=formula_facts_by_symbol,
            cast_facts_by_symbol=cast_facts_by_symbol,
            sentinel_facts_by_symbol=sentinel_facts_by_symbol,
            symbols_by_guard_token=dict(symbols_by_guard_token),
            symbols_by_sink_token=dict(symbols_by_sink_token),
            symbols_by_event_token=dict(symbols_by_event_token),
            meta_by_symbol=meta_by_symbol,
            lifecycle_symbols=lifecycle_symbols,
            callback_symbols=callback_symbols,
            notifier_related_symbols=notifier_related_symbols,
            security_symbols=security_symbols,
        )

    def _extract_definitions(self, content: str, rel_file: str) -> list[SymbolDef]:
        defs: list[SymbolDef] = []
        consumed_until = -1
        for match in _FUNCTION_DEF_RE.finditer(content):
            if match.start() < consumed_until:
                continue
            name = match.group("name")
            if name in _CONTROL_CALLS:
                continue
            signature = " ".join(match.group("signature").split())
            line = _line_number_at(content, match.start())
            end_idx, end_line = _find_body_end(content, match.end() - 1)
            consumed_until = max(consumed_until, end_idx)
            defs.append(SymbolDef(
                name=name,
                file_path=rel_file,
                line_number=line,
                signature=signature,
                body_start=line,
                body_end=end_line,
            ))
        return defs

    def _extract_function_uses(self, lines, sym, callsites, field_uses, field_uses_by_file):
        calls = []
        for offset, line_text in enumerate(lines):
            line_number = sym.body_start + offset
            for call in _CALL_RE.findall(line_text):
                if call in _CONTROL_CALLS:
                    continue
                if line_number == sym.body_start and call == sym.name:
                    continue
                calls.append(call)
                callsites[call].append(CallSite(
                    caller_name=sym.name,
                    caller_file=sym.file_path,
                    caller_line=sym.line_number,
                    callee_name=call,
                    line_number=line_number,
                    line_text=line_text.strip(),
                ))
            for field in _FIELD_RE.findall(line_text):
                use = FieldUse(
                    field=field,
                    file_path=sym.file_path,
                    function_name=sym.name,
                    line_number=line_number,
                    line_text=line_text.strip(),
                )
                field_uses[field].append(use)
                field_uses_by_file[sym.file_path].append(use)
        return list(dict.fromkeys(calls))

    def _symbol_lock_and_protocol_metadata(self, sym: SymbolDef, lines: list[str]) -> tuple[list[str], list[LockOrderEdge], list[str]]:
        locks = []
        edges: list[LockOrderEdge] = []
        held: list[str] = []
        for offset, line_text in enumerate(lines):
            line_number = sym.body_start + offset
            for match in _LOCK_CALL_RE.finditer(line_text):
                lock = _normalise_lock_expr(match.group("arg"))
                if not lock:
                    continue
                locks.append(lock)
                if _UNLOCK_WORD_RE.search(match.group("fn")):
                    if lock in held:
                        held.remove(lock)
                    continue
                for prior in held:
                    if prior == lock:
                        continue
                    edges.append(LockOrderEdge(
                        first_lock=prior,
                        second_lock=lock,
                        file_path=sym.file_path,
                        function_name=sym.name,
                        line_number=line_number,
                        line_text=line_text.strip(),
                    ))
                if lock not in held:
                    held.append(lock)
        text = f"{sym.name}\n{sym.signature}\n" + "\n".join(lines)
        state_tokens = _protocol_tokens_from_text(text)
        return list(dict.fromkeys(locks)), list(dict.fromkeys(edges)), state_tokens

    def _extract_semantic_facts(
        self,
        sym: SymbolDef,
        lines: list[str],
    ) -> tuple[
        list[CopyUse], list[GuardFact], list[AssignmentFact], list[CleanupFact], list[SinkFact],
        list[EventFact], list[FormulaFact], list[CastFact], list[SentinelFact],
    ]:
        copy_uses: list[CopyUse] = []
        guards: list[GuardFact] = []
        assignments: list[AssignmentFact] = []
        cleanup_facts: list[CleanupFact] = []
        sinks: list[SinkFact] = []
        event_facts: list[EventFact] = []
        formula_facts: list[FormulaFact] = []
        cast_facts: list[CastFact] = []
        sentinel_facts: list[SentinelFact] = []

        for offset, line_text in enumerate(lines):
            line_number = sym.body_start + offset
            stripped = line_text.strip()
            lower = stripped.lower()
            if not stripped or stripped.startswith(("//", "/*", "*")):
                continue
            if _COPY_API_RE.search(stripped):
                copy_uses.extend(self._copy_uses_from_line(stripped, line_number))
            guards.extend(self._guards_from_line(stripped, line_number))
            assignments.extend(self._assignments_from_line(stripped, line_number))
            cleanup_facts.extend(self._cleanup_facts_from_line(stripped, line_number))
            sinks.extend(self._sink_facts_from_line(stripped, line_number))
            event_facts.extend(self._event_facts_from_line(stripped, line_number))
            formula_facts.extend(self._formula_facts_from_line(stripped, line_number))
            cast_facts.extend(self._cast_facts_from_line(stripped, line_number))
            sentinel_facts.extend(self._sentinel_facts_from_line(stripped, line_number))
            if "return" in lower or "goto" in lower:
                cleanup_facts.append(CleanupFact(
                    action="exit",
                    kind="exit",
                    resource="return" if "return" in lower else "goto",
                    line_number=line_number,
                    line_text=stripped,
                ))
        return copy_uses, guards, assignments, cleanup_facts, sinks, event_facts, formula_facts, cast_facts, sentinel_facts

    def _copy_uses_from_line(self, line: str, line_number: int) -> list[CopyUse]:
        uses = []
        for api in _CALL_RE.findall(line):
            api_l = api.lower()
            if api_l not in _COPY_CONTRACT_APIS:
                continue
            args = _first_call_args(line, api)
            if not args:
                continue
            dst = args[0] if len(args) > 0 else ""
            src = args[1] if len(args) > 1 else ""
            size = args[2] if len(args) > 2 else ""
            if api_l in {"simple_read_from_buffer", "simple_write_to_buffer"}:
                size = args[1] if len(args) > 1 else size
                src = args[3] if len(args) > 3 else src
            uses.append(CopyUse(
                api=api_l,
                line_number=line_number,
                dst_expr=_short_expr(dst),
                src_expr=_short_expr(src),
                size_expr=_short_expr(size),
                line_text=line,
            ))
        return uses

    def _guards_from_line(self, line: str, line_number: int) -> list[GuardFact]:
        guards = []
        for match in _GUARD_COMPARE_RE.finditer(line):
            lhs = _short_expr(match.group("lhs"))
            rhs = _short_expr(match.group("rhs"))
            op = match.group("op")
            tokens = _fact_tokens(f"{lhs} {rhs}")
            interesting = tokens & (_COUNT_SIZE_WORDS | _RESOURCE_WORDS | _POLICY_GUARD_WORDS | _PROTOCOL_TOKEN_WORDS)
            for token in sorted(interesting):
                guards.append(GuardFact(
                    token=token,
                    lhs=lhs,
                    op=op,
                    rhs=rhs,
                    line_number=line_number,
                    line_text=line,
                ))
        return guards

    def _assignments_from_line(self, line: str, line_number: int) -> list[AssignmentFact]:
        facts = []
        for match in _ASSIGN_FACT_RE.finditer(line):
            lhs = _short_expr(match.group("lhs"))
            rhs = _short_expr(match.group("rhs"))
            tokens = tuple(sorted(_fact_tokens(f"{lhs} {rhs}") & (
                _COUNT_SIZE_WORDS | _RESOURCE_WORDS | _PROTOCOL_TOKEN_WORDS | _POLICY_GUARD_WORDS
            )))
            if not tokens and not _ARITH_EXPR_RE.search(rhs):
                continue
            facts.append(AssignmentFact(
                target=lhs,
                value=rhs,
                tokens=tokens,
                line_number=line_number,
                line_text=line,
                is_field=("->" in lhs or "." in lhs),
                is_arithmetic=bool(_ARITH_EXPR_RE.search(rhs)),
            ))
        for match in _UPDATE_FACT_RE.finditer(line):
            target = _short_expr(match.group("target"))
            op = match.group("op")
            tokens = tuple(sorted(_fact_tokens(target) & (_COUNT_SIZE_WORDS | _RESOURCE_WORDS | _PROTOCOL_TOKEN_WORDS)))
            if not tokens:
                continue
            facts.append(AssignmentFact(
                target=target,
                value=op,
                tokens=tokens,
                line_number=line_number,
                line_text=line,
                is_field=("->" in target or "." in target),
                is_arithmetic=False,
            ))
        return facts

    def _cleanup_facts_from_line(self, line: str, line_number: int) -> list[CleanupFact]:
        facts = []
        for api in _CALL_RE.findall(line):
            api_l = api.lower()
            args = _first_call_args(line, api)
            resource = _short_expr(args[0] if args else "")
            action, kind = self._cleanup_action(api_l)
            if action:
                facts.append(CleanupFact(
                    action=action,
                    kind=kind,
                    resource=resource or api_l,
                    line_number=line_number,
                    line_text=line,
                ))
        for match in _UPDATE_FACT_RE.finditer(line):
            op = match.group("op")
            target = _short_expr(match.group("target"))
            tokens = _fact_tokens(target)
            if not tokens & (_COUNT_SIZE_WORDS | {"refcount", "mappings", "pages", "groups"}):
                continue
            facts.append(CleanupFact(
                action="inc" if op in {"++", "+="} else "dec",
                kind="acquire" if op in {"++", "+="} else "release",
                resource=target,
                line_number=line_number,
                line_text=line,
            ))
        return facts

    def _cleanup_action(self, api: str) -> tuple[str, str]:
        if re.search(r"(?:alloc|malloc|calloc|get|map|register|list_add|hash_add|insert|link_node|idr_alloc|xa_insert|enable)", api):
            if re.search(r"(?:free|unmap|unregister|remove|erase|delete|del|disable)", api):
                return "", ""
            if "get" in api and api in {"forget", "target"}:
                return "", ""
            if "map" in api and api.startswith("un"):
                return "unmap", "release"
            if "register" in api and api.startswith("un"):
                return "unregister", "release"
            if "enable" in api:
                return "enable", "acquire"
            if "map" in api:
                return "map", "acquire"
            if "register" in api:
                return "register", "acquire"
            if "get" in api:
                return "get", "acquire"
            if "insert" in api or "add" in api or "link_node" in api or "idr_alloc" in api:
                return "insert", "acquire"
            return "alloc", "acquire"
        if re.search(r"(?:free|put|unmap|unregister|list_del|hash_del|erase|remove|delete|del|idr_remove|xa_erase|disable)", api):
            if "disable" in api:
                return "disable", "release"
            if "unmap" in api:
                return "unmap", "release"
            if "unregister" in api:
                return "unregister", "release"
            if "put" in api:
                return "put", "release"
            if re.search(r"(?:erase|remove|delete|del|xa_erase)", api):
                return "erase", "release"
            return "free", "release"
        return "", ""

    def _sink_facts_from_line(self, line: str, line_number: int) -> list[SinkFact]:
        facts = []
        for api in _CALL_RE.findall(line):
            api_l = api.lower()
            if api_l not in _POLICY_SINK_APIS and not any(token in api_l for token in _POLICY_SINK_APIS):
                continue
            tokens = _fact_tokens(f"{api_l} {line}") & (_POLICY_GUARD_WORDS | _RESOURCE_WORDS | _PROTOCOL_TOKEN_WORDS)
            token = sorted(tokens)[0] if tokens else api_l
            facts.append(SinkFact(api=api_l, token=token, line_number=line_number, line_text=line))
        return facts

    def _event_facts_from_line(self, line: str, line_number: int) -> list[EventFact]:
        facts: list[EventFact] = []
        lower = line.lower()
        tokens = _fact_tokens(line)
        resource_tokens = sorted(tokens & (_RESOURCE_WORDS | _QUEUE_LIVENESS_WORDS | _TRACKER_WORDS | _PM_WORDS | _SLOT_WORDS))

        if re.search(r"\bif\s*\(|\bWARN_ON\b|\bBUG_ON\b|\breturn\s+-", line) and resource_tokens:
            for token in resource_tokens[:4]:
                facts.append(EventFact("validation", token, line_number, line, "guard"))

        if tokens & _RESOURCE_WORDS:
            if _ASSIGN_FACT_RE.search(line) and not _NULL_CLEAR_RE.search(line):
                for token in sorted(tokens & _RESOURCE_WORDS)[:4]:
                    facts.append(EventFact("resource_bind", token, line_number, line, "assignment"))
            if _NULL_CLEAR_RE.search(line) or re.search(r"\b(?:clear|reset|invalidate|unmap|unbind)\w*\s*\(", lower):
                for token in sorted(tokens & _RESOURCE_WORDS)[:4]:
                    facts.append(EventFact("resource_clear", token, line_number, line, "clear"))

        if _ASYNC_SCHEDULE_RE.search(line) and tokens & {"fault", "irq", "interrupt", "event", "work", "worker"}:
            token = sorted(tokens & {"fault", "irq", "interrupt", "event", "work", "worker"})[0]
            facts.append(EventFact("async_schedule", token, line_number, line, "schedule"))
        if _ASYNC_CLEAR_RE.search(line) and tokens & {"fault", "irq", "interrupt", "event", "state"}:
            token = sorted(tokens & {"fault", "irq", "interrupt", "event", "state"})[0]
            facts.append(EventFact("async_clear", token, line_number, line, "clear"))
        if _FAULT_CLEAR_RE.search(line):
            facts.append(EventFact("fault_clear", "fault", line_number, line, "clear_fault"))

        if _SUSPEND_SOURCE_RE.search(line):
            for token in sorted(tokens & (_SUSPEND_WORDS | {"size", "pages", "nr"}))[:4]:
                facts.append(EventFact("suspend_resource", token, line_number, line, "suspend"))

        if _PM_RUNTIME_API_RE.search(line):
            facts.append(EventFact("pm_runtime_get", "pm", line_number, line, "runtime"))
        if _PM_SENSITIVE_API_RE.search(line):
            token = "register" if re.search(r"\b(?:readl|writel|regmap_|kbase_reg_)", lower) else "power"
            facts.append(EventFact("pm_sensitive_action", token, line_number, line, "pm_sensitive"))
        if re.search(r"\b(?:pm_runtime_put|pm_runtime_put_sync|disable_gpu_power_control|clk_disable|regulator_disable)\w*\s*\(", lower):
            facts.append(EventFact("pm_runtime_put", "pm", line_number, line, "runtime"))

        if tokens & _TRACKER_WORDS:
            if re.search(r"\b(?:rb_erase|list_del|delete|remove|erase|del)\w*\s*\(", lower):
                facts.append(EventFact("tracker_remove", sorted(tokens & _TRACKER_WORDS)[0], line_number, line, "remove"))
            if _NULL_CLEAR_RE.search(line) or re.search(r"\b(?:invalid|clear|reset)\b", lower):
                facts.append(EventFact("tracker_invalidate", sorted(tokens & _TRACKER_WORDS)[0], line_number, line, "invalidate"))

        if tokens & _SLOT_WORDS:
            if re.search(r"\[\s*0\s*\]|\bfirst\b|\bslot0\b|\bslot\s*=\s*0\b|\bkatom\b", lower):
                facts.append(EventFact("slot_first", "slot", line_number, line, "first"))
            if re.search(r"\[\s*1\s*\]|\bsecond\b|\bslot1\b|\bslot\s*\+\s*1\b|\bnext\b|\bother\b|\bpair", lower):
                facts.append(EventFact("slot_second", "slot", line_number, line, "second"))
            if re.search(r"\b(?:return|continue|break|goto)\b", lower) and ({"prio", "priority"} & tokens or re.search(r"!\s*katom|reset|stop|different", lower)):
                facts.append(EventFact("slot_skip", "slot", line_number, line, "priority_skip"))

        if {"protected", "protm"} & tokens:
            if tokens & _WAIT_ACK_TOKENS:
                facts.append(EventFact("protected_wait", "protected", line_number, line, "wait"))
            if _PROTECTED_ACTIVE_RE.search(line) or re.search(r"\b(?:active|entered|enabled)\b", lower):
                facts.append(EventFact("protected_verify", "protected", line_number, line, "verify"))
        if "mmu" in tokens and _LOCK_CALL_RE.search(line):
            facts.append(EventFact("mmu_lock", "mmu", line_number, line, "lock"))
        if _ACTIVE_SINGLETON_RE.search(line):
            facts.append(EventFact("active_singleton", "active_protm_grp", line_number, line, "active_singleton"))

        return facts

    def _formula_facts_from_line(self, line: str, line_number: int) -> list[FormulaFact]:
        facts = []
        for match in _ASSIGN_FACT_RE.finditer(line):
            lhs = _short_expr(match.group("lhs"))
            rhs = _short_expr(match.group("rhs"), limit=160)
            operators = _formula_operators(rhs)
            if not operators:
                continue
            tokens = tuple(sorted(_fact_tokens(f"{lhs} {rhs}") & (_COUNT_SIZE_WORDS | _RESOURCE_WORDS | _PROTOCOL_TOKEN_WORDS)))
            facts.append(FormulaFact(
                target=lhs,
                expr=rhs,
                normalized=_normalise_formula_expr(rhs),
                tokens=tokens,
                operators=operators,
                line_number=line_number,
                line_text=line,
            ))
        return facts

    def _cast_facts_from_line(self, line: str, line_number: int) -> list[CastFact]:
        facts = []
        for match in _STRUCT_CAST_RE.finditer(line):
            src = _short_expr(match.group("src"), limit=160)
            if not _METADATA_SOURCE_RE.search(src):
                continue
            facts.append(CastFact(
                target=match.group("target"),
                target_type=" ".join(match.group("type").split()),
                source=src,
                line_number=line_number,
                line_text=line,
            ))
        if "container_of" in line and _METADATA_SOURCE_RE.search(line):
            args = _first_call_args(line, "container_of")
            if len(args) >= 2:
                target = re.split(r"\s*=\s*", line, maxsplit=1)[0].strip().split()[-1]
                facts.append(CastFact(
                    target=target,
                    target_type=_short_expr(args[1]),
                    source=_short_expr(args[0], limit=160),
                    line_number=line_number,
                    line_text=line,
                ))
        return facts

    def _sentinel_facts_from_line(self, line: str, line_number: int) -> list[SentinelFact]:
        facts = []
        tokens = _fact_tokens(line)
        if not tokens & {"phys", "phys_addr", "pfn", "addr", "address", "dma", "pa"}:
            return facts
        for match in _SENTINEL_COMPARE_RE.finditer(line):
            expr = _short_expr(match.group("expr"))
            expr_tokens = _fact_tokens(expr)
            token = sorted((expr_tokens | tokens) & {"phys", "phys_addr", "pfn", "addr", "address", "dma", "pa"})[0]
            facts.append(SentinelFact(
                expr=expr,
                value=match.group("value"),
                token=token,
                line_number=line_number,
                line_text=line,
            ))
        return facts

    def _symbol_meta(
        self,
        sym: SymbolDef,
        calls: list[str],
        body: str,
        locks: list[str],
        state_tokens: list[str],
    ) -> SymbolMeta:
        match_text = f"{sym.name} {' '.join(calls)} {body}"
        call_text = " ".join(calls)
        has_security_api = bool(_SECURITY_API_RE.search(match_text))
        has_lifecycle_words = (
            _name_has_any(sym.name, _LIFECYCLE_WORDS)
            or _name_has_any(call_text, _LIFECYCLE_WORDS)
        )
        has_callback_words = (
            _name_has_any(sym.name, _CALLBACK_WORDS)
            or _name_has_any(call_text, _CALLBACK_WORDS)
            or _name_has_any(body, _CALLBACK_WORDS)
        )
        has_lock_api = bool(locks)
        has_protocol_words = bool(state_tokens)
        has_notifier_words = _name_has_any(sym.name, _NOTIFIER_WORDS) or _notifier_related_text(match_text)
        is_source_like = bool(_SOURCE_RE.search(match_text))
        is_sink_like = bool(_SINK_KIND_RE.search(match_text) or has_security_api)
        return SymbolMeta(
            has_security_api=has_security_api,
            has_lifecycle_words=has_lifecycle_words,
            has_callback_words=has_callback_words,
            has_lock_api=has_lock_api,
            has_protocol_words=has_protocol_words,
            has_notifier_words=has_notifier_words,
            is_source_like=is_source_like,
            is_sink_like=is_sink_like,
            sink_type_hint=_sink_type_for_text(match_text) if is_sink_like else "",
        )

    def _extract_globals(self, content: str, rel_file: str) -> list[GlobalConstruct]:
        lines = content.splitlines()
        globals_: list[GlobalConstruct] = []
        idx = 0
        while idx < len(lines):
            line = lines[idx]
            if not _GLOBAL_START_RE.search(line):
                idx += 1
                continue
            start = idx
            block = [line]
            while idx + 1 < len(lines) and "};" not in lines[idx] and idx - start < 80:
                idx += 1
                block.append(lines[idx])
                if "};" in lines[idx]:
                    break
            text = "\n".join(block)
            refs = list(dict.fromkeys(_GLOBAL_REF_RE.findall(text)))
            if refs or any(word in text.lower() for word in _CALLBACK_WORDS):
                name = self._global_name(text, start + 1)
                kind = "callback_table"
                if "file_operations" in text or "fops" in text.lower():
                    kind = "file_operations"
                elif "timer" in text.lower():
                    kind = "timer"
                elif "work" in text.lower() or "worker" in text.lower():
                    kind = "work"
                elif "watchdog" in text.lower():
                    kind = "watchdog"
                globals_.append(GlobalConstruct(
                    unique_name=f"{rel_file}::{name}",
                    file_path=rel_file,
                    name=name,
                    line_number=start + 1,
                    kind=kind,
                    initializer=text[:3000],
                    referenced_functions=refs,
                ))
            idx += 1
        return globals_

    def _global_name(self, text: str, fallback_line: int) -> str:
        match = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*(?:=\s*)?\{", text)
        if match:
            return match.group(1)
        return f"global_{fallback_line}"


def _symbol_calls(index: SymbolIndex, sym: SymbolDef) -> list[str]:
    if not index:
        return []
    if index.calls_by_caller:
        return list(index.calls_by_caller.get((sym.file_path, sym.name), []))
    calls = []
    for callee, sites in index.callsites.items():
        for site in sites:
            if site.caller_file == sym.file_path and site.caller_name == sym.name:
                calls.append(callee)
                break
    return list(dict.fromkeys(calls))


def _symbols_for_file(index: SymbolIndex, file_path: str) -> list[SymbolDef]:
    file_path = file_path.replace("\\", "/")
    if index.defs_by_file:
        return list(index.defs_by_file.get(file_path, []))
    return [
        sym for defs in index.definitions.values()
        for sym in defs if sym.file_path == file_path
    ]


def _lookup_symbol(index: SymbolIndex, file_path: str, name: str) -> SymbolDef | None:
    file_path = file_path.replace("\\", "/")
    sym = index.defs_by_file_and_name.get((file_path, name))
    if sym:
        return sym
    if index.defs_by_file:
        for candidate in index.defs_by_file.get(file_path, []):
            if candidate.name == name:
                return candidate
        return None
    for candidate in index.definitions.get(name, []):
        if candidate.file_path == file_path:
            return candidate
    return None


def _field_uses_for_file(index: SymbolIndex, file_path: str) -> list[FieldUse]:
    file_path = file_path.replace("\\", "/")
    if index.field_uses_by_file:
        return list(index.field_uses_by_file.get(file_path, []))
    return [
        use for uses in index.field_uses.values()
        for use in uses if use.file_path == file_path
    ]


def _all_symbols(index: SymbolIndex) -> list[SymbolDef]:
    if index.defs_by_file:
        return [sym for symbols in index.defs_by_file.values() for sym in symbols]
    return [sym for defs in index.definitions.values() for sym in defs]


def _lifecycle_symbol_candidates(index: SymbolIndex) -> list[SymbolDef]:
    if index.lifecycle_symbols or index.meta_by_symbol:
        return list(index.lifecycle_symbols)
    return [sym for sym in _all_symbols(index) if _name_has_any(sym.name, _LIFECYCLE_WORDS)]


def _callback_symbol_candidates(index: SymbolIndex) -> list[SymbolDef]:
    if index.callback_symbols or index.meta_by_symbol:
        return list(index.callback_symbols)
    return [sym for sym in _all_symbols(index) if _name_has_any(sym.name, _CALLBACK_WORDS)]


def _notifier_symbol_candidates(index: SymbolIndex) -> list[SymbolDef]:
    if index.notifier_related_symbols or index.meta_by_symbol:
        return list(index.notifier_related_symbols)
    return [sym for sym in _all_symbols(index) if _name_has_any(sym.name, _NOTIFIER_WORDS)]


def _security_symbol_candidates(index: SymbolIndex) -> list[SymbolDef]:
    if index.security_symbols or index.meta_by_symbol:
        return list(index.security_symbols)
    return _all_symbols(index)


def _symbol_locks(index: SymbolIndex, sym: SymbolDef) -> set[str]:
    return set(index.locks_by_symbol.get(_symbol_unique_name(sym), []))


def _symbol_state_tokens(index: SymbolIndex, sym: SymbolDef) -> set[str]:
    return set(index.state_tokens_by_symbol.get(_symbol_unique_name(sym), []))


def _symbol_lock_edges(index: SymbolIndex, sym: SymbolDef) -> list[LockOrderEdge]:
    return list(index.lock_edges_by_symbol.get(_symbol_unique_name(sym), []))


def _symbol_copy_uses(index: SymbolIndex, sym: SymbolDef) -> list[CopyUse]:
    return list(index.copy_uses_by_symbol.get(_symbol_unique_name(sym), []))


def _symbol_guards(index: SymbolIndex, sym: SymbolDef) -> list[GuardFact]:
    return list(index.guards_by_symbol.get(_symbol_unique_name(sym), []))


def _symbol_assignments(index: SymbolIndex, sym: SymbolDef) -> list[AssignmentFact]:
    return list(index.assignments_by_symbol.get(_symbol_unique_name(sym), []))


def _symbol_cleanup_facts(index: SymbolIndex, sym: SymbolDef) -> list[CleanupFact]:
    return list(index.cleanup_facts_by_symbol.get(_symbol_unique_name(sym), []))


def _symbol_sink_facts(index: SymbolIndex, sym: SymbolDef) -> list[SinkFact]:
    return list(index.sink_facts_by_symbol.get(_symbol_unique_name(sym), []))


def _symbol_event_facts(index: SymbolIndex, sym: SymbolDef) -> list[EventFact]:
    return list(index.event_facts_by_symbol.get(_symbol_unique_name(sym), []))


def _symbol_formula_facts(index: SymbolIndex, sym: SymbolDef) -> list[FormulaFact]:
    return list(index.formula_facts_by_symbol.get(_symbol_unique_name(sym), []))


def _symbol_cast_facts(index: SymbolIndex, sym: SymbolDef) -> list[CastFact]:
    return list(index.cast_facts_by_symbol.get(_symbol_unique_name(sym), []))


def _symbol_sentinel_facts(index: SymbolIndex, sym: SymbolDef) -> list[SentinelFact]:
    return list(index.sentinel_facts_by_symbol.get(_symbol_unique_name(sym), []))


def _sink_type_for_text(text: str) -> str:
    tl = text.lower()
    if re.search(r"\b(system|popen|exec)", tl):
        return "command_injection"
    if re.search(r"\b(v?fprintf|printf|sprintf|snprintf)\s*\(", tl):
        return "format_string"
    if re.search(r"\b(fopen|open|stat|lstat|access|unlink|rename)\s*\(", tl):
        return "path_traversal"
    if re.search(r"\b(memcpy|memmove|strcpy|strcat|sprintf|vsprintf)\s*\(", tl):
        return "buffer_overflow"
    if re.search(r"\b(free|kfree|vfree|release|destroy)\b", tl):
        return "use_after_free"
    if re.search(r"\b(mutex|spin|lock|unlock|work|timer|watchdog|callback)\b", tl):
        return "teardown_race"
    if re.search(r"\b(power|ready|enabled|active|mmu|dma|flush|fence)\b", tl):
        return "state_order"
    return "other"


def _symbol_to_node(
    index: SymbolIndex,
    codebase_path: str,
    sym: SymbolDef,
    cache: PartialAnalysisCache | None = None,
) -> FunctionNode:
    if cache is not None:
        return cache.node_for_symbol(index, sym)
    calls = _symbol_calls(index, sym)
    meta = index.meta_by_symbol.get(_symbol_unique_name(sym)) if index else None
    if meta:
        is_source = meta.is_source_like
        is_sink = meta.is_sink_like
        sink_type = meta.sink_type_hint if is_sink else ""
    else:
        body = _function_body_from_symbol(codebase_path, sym, max_chars=8000)
        match_text = f"{sym.name} {' '.join(calls)} {body}"
        is_source = bool(_SOURCE_RE.search(match_text))
        is_sink = bool(_SINK_KIND_RE.search(match_text) or _SECURITY_API_RE.search(match_text))
        sink_type = _sink_type_for_text(match_text) if is_sink else ""
    return FunctionNode(
        unique_name=_symbol_unique_name(sym),
        file_path=sym.file_path,
        name=sym.name,
        line_number=sym.line_number,
        is_source=is_source,
        is_sink=is_sink,
        calls=calls,
        source_reason="deterministic source-like entry or external input use" if is_source else "",
        sink_type=sink_type,
        sink_reason="deterministic sink-like API/state/lifecycle use" if is_sink else "",
    )


class PartialContextBuilder:
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


class PartialGraphBuilder:
    def build(self, context: PartialReviewContext, symbol_index: SymbolIndex, codebase_path: str) -> ReachabilityGraph:
        graph = ReachabilityGraph()
        for node in self._all_nodes(context):
            graph.add_node(node)
        for g in context.globals:
            graph.add_global(g)
        graph.resolve_all_calls()
        return graph

    def candidate_paths(self, context: PartialReviewContext, graph: ReachabilityGraph) -> list[ReachabilityPath]:
        paths = list(context.candidate_paths)
        if graph.node_count() <= 260:
            paths.extend(PathTracer(graph, max_path_length=8, max_paths_per_source=80).find_all_paths())
        return _dedupe_paths(paths)

    def _all_nodes(self, context: PartialReviewContext) -> list[FunctionNode]:
        nodes = {}
        for group in (
            context.target_nodes, context.inbound_callers, context.outbound_callees,
            context.shared_state_nodes, context.lifecycle_pair_nodes,
            context.callback_nodes, context.companion_nodes,
        ):
            for node in group:
                nodes[node.unique_name] = node
        return list(nodes.values())


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
        self._detect_partial_mapping_rollback(index, result, target_syms, context)
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
        self._detect_mmu_lockdrop_stale(index, result, target_syms)
        self._detect_migration_metadata_race(index, result, target_syms)
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
        self._detect_mmu_teardown_order(index, result, target_syms, context)
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
                and (
                    re.search(r"\bkbase_page_metadata\b|page_metadata", line)
                    or re.search(r"\(\s*(?:const\s+)?struct\s+[A-Za-z_][A-Za-z0-9_]*\s*\*", line)
                )
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
                f"`{_line_excerpt(line)}` to a struct pointer and dereferences `{target}` at line "
                f"{deref[0]} `{_line_excerpt(deref[1])}` without proving the private value has that type."
            )
            self._add_node(index, result, sym)
            return True
        return False

    def _detect_mmu_lockdrop_stale(self, index, result, target_syms):
        for sym in target_syms:
            text = f"{sym.name} {sym.signature} {self._body_text(sym)[:18000]}"
            tokens = _fact_tokens(text)
            if not (tokens & {"mmu", "vm", "region", "alloc", "pgd", "pmd", "pte", "metadata", "migration"}):
                continue
            if not (_MMU_LOCKDROP_UNLOCK_RE.search(text) and _MMU_LOCKDROP_RELOCK_RE.search(text)):
                continue
            cached: dict[str, tuple[int, str]] = {}
            unlock_line: tuple[int, str] | None = None
            relock_seen = False
            revalidated: set[str] = set()
            for line_no, line in self._lines(sym):
                assign = _MMU_STALE_ASSIGN_RE.search(line)
                if assign and unlock_line is None:
                    var = assign.group("var")
                    if _fact_tokens(var) & {"reg", "region", "alloc", "pgd", "pmd", "pte", "metadata", "meta", "page", "phys", "pfn"}:
                        cached[var] = (line_no, line)
                if _MMU_LOCKDROP_UNLOCK_RE.search(line):
                    unlock_line = (line_no, line)
                    continue
                if unlock_line is None:
                    continue
                if _MMU_STALE_REVALIDATE_RE.search(line):
                    for var in cached:
                        if re.search(r"\b" + re.escape(var) + r"\b", line):
                            revalidated.add(var)
                if _MMU_LOCKDROP_RELOCK_RE.search(line):
                    relock_seen = True
                    continue
                if not relock_seen:
                    continue
                for var, (assign_no, assign_line) in list(cached.items()):
                    if var in revalidated or line_no <= unlock_line[0] + 1:
                        continue
                    if not re.search(r"\b" + re.escape(var) + r"\b", line):
                        continue
                    if not re.search(r"(?:->|\.|\[|\b(?:free|unmap|write|read|set|clear|put|get|memcpy|copy)\w*\s*\()", line):
                        continue
                    result.mmu_lockdrop_stale_notes.append(
                        f"{sym.file_path}::{sym.name} caches MMU/VM state at line {assign_no} "
                        f"`{_line_excerpt(assign_line)}`, drops the VM/MMU lock at line {unlock_line[0]} "
                        f"`{_line_excerpt(unlock_line[1])}`, then reuses `{var}` at line {line_no} "
                        f"`{_line_excerpt(line)}` after relock without visible lookup/revalidation."
                    )
                    self._add_node(index, result, sym)
                    if len(result.mmu_lockdrop_stale_notes) >= 8:
                        return
                    cached.pop(var, None)
                    break

    def _detect_migration_metadata_race(self, index, result, target_syms):
        for sym in target_syms:
            text = f"{sym.name} {sym.signature} {self._body_text(sym)[:18000]}"
            if not _MIGRATION_METADATA_RE.search(text):
                continue
            if not (_MMU_LOCKDROP_UNLOCK_RE.search(text) or re.search(r"\b(?:set_page_private|page_private|folio_get_private)\b", text)):
                continue
            lines = self._lines(sym)
            private_line = next((
                (line_no, line) for line_no, line in lines
                if re.search(r"\b(?:page_private|folio_get_private|set_page_private|metadata|movable|migration)\b", line, re.IGNORECASE)
            ), None)
            if not private_line:
                continue
            unlock_line = next((
                (line_no, line) for line_no, line in lines
                if line_no > private_line[0] and _MMU_LOCKDROP_UNLOCK_RE.search(line)
            ), None)
            if not unlock_line:
                continue
            reuse_line = next((
                (line_no, line) for line_no, line in lines
                if line_no > unlock_line[0]
                and re.search(r"\b(?:page_private|folio_get_private|metadata|movable|migration|compound|huge|dma)\b", line, re.IGNORECASE)
                and re.search(r"(?:->|\.|\[|set_page_private|clear|free|put|sync|cache|migrate)", line, re.IGNORECASE)
            ), None)
            if not reuse_line:
                continue
            between = "\n".join(
                line for line_no, line in lines
                if unlock_line[0] < line_no < reuse_line[0]
            )
            if _MMU_STALE_REVALIDATE_RE.search(between):
                continue
            result.migration_metadata_race_notes.append(
                f"{sym.file_path}::{sym.name} reads or mutates migration/page-private metadata at line {private_line[0]} "
                f"`{_line_excerpt(private_line[1])}`, drops the VM/MMU lock at line {unlock_line[0]} "
                f"`{_line_excerpt(unlock_line[1])}`, then reuses metadata at line {reuse_line[0]} "
                f"`{_line_excerpt(reuse_line[1])}` without proving the page/private metadata stayed valid."
            )
            self._add_node(index, result, sym)
            if len(result.migration_metadata_race_notes) >= 8:
                return

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

    def _detect_mmu_teardown_order(self, index, result, target_syms, context):
        context_syms = self._context_symbols(index, context, target_syms)
        quiesce_companion = next((
            sym for sym in context_syms
            if sym not in target_syms
            and _HW_QUIESCE_RE.search(f"{sym.name} {self._body_text(sym)[:8000]}")
        ), None)
        for sym in target_syms:
            text = f"{sym.name} {sym.signature} {self._body_text(sym)[:18000]}"
            if not re.search(r"\b(?:mmu|region|va_region|address\s*space|pgd|pmd|pte)\b", text, re.IGNORECASE):
                continue
            if not re.search(r"\b(?:term|teardown|destroy|free|release|remove|unmap)\b", text, re.IGNORECASE):
                continue
            if not re.search(r"\b(?:gpu|cache|writeback|tlb|as|address\s*space|dirty|flush|schedule)\b", text, re.IGNORECASE):
                continue
            lines = self._lines(sym)
            teardown_line = next((
                (line_no, line) for line_no, line in lines
                if _MMU_TEARDOWN_FREE_RE.search(line)
            ), None)
            if not teardown_line:
                continue
            prior_quiesce = next((
                (line_no, line) for line_no, line in lines
                if line_no < teardown_line[0] and _HW_QUIESCE_RE.search(line)
            ), None)
            if prior_quiesce:
                continue
            later_quiesce = next((
                (line_no, line) for line_no, line in lines
                if line_no > teardown_line[0] and line_no - teardown_line[0] <= 120 and _HW_QUIESCE_RE.search(line)
            ), None)
            result.mmu_teardown_order_notes.append(
                f"{sym.file_path}::{sym.name} line {teardown_line[0]} tears down MMU/VA resources "
                f"`{_line_excerpt(teardown_line[1])}` before a visible GPU address-space disable, schedule-out, "
                f"TLB/cache flush, or hardware quiescence point"
                f"{' (later line ' + str(later_quiesce[0]) + ' `' + _line_excerpt(later_quiesce[1]) + '`)' if later_quiesce else ''}"
                f"{' shown only in companion ' + quiesce_companion.file_path + '::' + quiesce_companion.name if quiesce_companion and not later_quiesce else ''}."
            )
            self._add_node(index, result, sym)
            if quiesce_companion:
                self._add_node(index, result, quiesce_companion)
            if len(result.mmu_teardown_order_notes) >= 8:
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

    def _detect_partial_mapping_rollback(self, index, result, target_syms, context):
        context_syms = self._context_symbols(index, context, target_syms)
        companion = next((
            sym for sym in context_syms
            if sym not in target_syms
            and re.search(r"\b(?:unmap|rollback|teardown|invalidate|flush|cache)\b", f"{sym.name} {self._body_text(sym)[:8000]}", re.IGNORECASE)
        ), None)
        for sym in target_syms:
            text = f"{sym.name} {sym.signature} {self._body_text(sym)[:18000]}"
            tokens = _fact_tokens(text)
            if not (tokens & {"mmu", "alias", "mapping", "map", "pages", "pfn", "phys", "region"}):
                continue
            if not re.search(r"\b(?:fail|failure|rollback|partial|ENOMEM|goto\s+(?:err|fail|out)|return\s+-)\b", text, re.IGNORECASE):
                continue
            lines = self._lines(sym)
            for install_no, install_line in lines:
                if not _PARTIAL_MAPPING_INSTALL_RE.search(install_line):
                    continue
                install_tokens = _fact_tokens(install_line)
                if not (install_tokens & {"mmu", "alias", "map", "pages", "pfn", "phys", "gpu_va", "region"}):
                    continue
                failure = next((
                    (line_no, line) for line_no, line in lines
                    if line_no > install_no
                    and line_no - install_no <= 100
                    and (_ERROR_PATH_RE.search(line) or re.search(r"\b(?:fail|failure|ENOMEM|rollback|partial)\b", line, re.IGNORECASE))
                ), None)
                if not failure:
                    continue
                path_lines = [
                    (line_no, line) for line_no, line in lines
                    if install_no <= line_no <= min(failure[0] + 70, sym.body_end or failure[0] + 70)
                ]
                rollback_lines = [
                    (line_no, line) for line_no, line in path_lines
                    if line_no > install_no and _PARTIAL_MAPPING_ROLLBACK_RE.search(line)
                ]
                if not rollback_lines:
                    result.partial_mapping_rollback_notes.append(
                        f"{sym.file_path}::{sym.name} line {install_no} partially installs mapping/MMU state "
                        f"`{_line_excerpt(install_line)}`, then failure path line {failure[0]} "
                        f"`{_line_excerpt(failure[1])}` has no visible unmap/invalidate/cache-maintenance rollback"
                        f"{' despite companion rollback context ' + companion.file_path + '::' + companion.name if companion else ''}."
                    )
                    self._add_node(index, result, sym)
                    if companion:
                        self._add_node(index, result, companion)
                    if len(result.partial_mapping_rollback_notes) >= 8:
                        return
                    continue
                rollback_no, rollback_line = rollback_lines[0]
                rollback_tokens = _fact_tokens(rollback_line)
                extent_tokens = {"pages", "pfn", "phys", "gpu_va", "addr", "level", "count", "nr", "num", "region"}
                shared_extent = (install_tokens & rollback_tokens & extent_tokens)
                has_cache_or_invalidate = bool(re.search(r"\b(?:unmap|invalidate|flush|cache|tlb|zap|teardown)\b", rollback_line, re.IGNORECASE))
                if shared_extent and has_cache_or_invalidate:
                    continue
                result.partial_mapping_rollback_notes.append(
                    f"{sym.file_path}::{sym.name} line {install_no} installs mapping/MMU state "
                    f"`{_line_excerpt(install_line)}`, but failure rollback line {rollback_no} "
                    f"`{_line_excerpt(rollback_line)}` is not visibly tied to the same extent/level or cache/TLB invalidation "
                    f"before failure path line {failure[0]}."
                )
                self._add_node(index, result, sym)
                if companion:
                    self._add_node(index, result, companion)
                if len(result.partial_mapping_rollback_notes) >= 8:
                    return
                break

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
            range_mismatch = self._mmu_recovery_range_mismatch(lines, loop_line[0])
            if not mismatch and not range_mismatch:
                continue
            caller = self._advanced_phys_pointer_caller(index, sym, context_syms)
            caller_suffix = ""
            if caller:
                caller_sym, caller_line, caller_text = caller
                caller_suffix = (
                    f" Caller {caller_sym.file_path}::{caller_sym.name} line {caller_line} passes an advanced "
                    f"phys/base pointer `{_line_excerpt(caller_text)}`, so caller/callee rollback uses the wrong base or remaining count."
                )
            range_suffix = f" {range_mismatch}" if range_mismatch else ""
            result.mmu_recovery_notes.append(
                f"{sym.file_path}::{sym.name} recovery loop line {loop_line[0]} `{_line_excerpt(loop_line[1])}` "
                f"uses rollback/page bounds that are not visibly tied to phys-base adjustment"
                f"{' line ' + str(phys_formula.line_number) + ' `' + _line_excerpt(phys_formula.line_text) + '`' if phys_formula else ''}; "
                f"recovery action line {action_line[0]} `{_line_excerpt(action_line[1])}` may unmap/write/free the wrong rollback range."
                f"{range_suffix}"
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

    def _mmu_recovery_range_mismatch(self, lines: list[tuple[int, str]], loop_line: int) -> str:
        window = "\n".join(
            line for line_no, line in lines
            if max(1, loop_line - 18) <= line_no <= loop_line + 24
        )
        inclusive_count = re.search(
            r"\b(?:num_pages|nr_pages|count|pages)\s*=\s*(?:to|end)[A-Za-z0-9_]*\s*-\s*(?:from|start)[A-Za-z0-9_]*\s*\+\s*1\b",
            window,
            re.IGNORECASE,
        )
        exclusive_loop = re.search(
            r"\b(?:for|while)\s*\([^)]*(?:<\s*(?:to|end)|<=\s*(?:to|end)|<\s*(?:num_pages|nr_pages|count|pages))",
            window,
            re.IGNORECASE,
        )
        advanced_base = re.search(
            r"\b(?:phys|pfn|base|start)[A-Za-z0-9_]*(?:\s*\+|(?:\+\+)|\s*\+=)\s*(?:i|idx|inserted|done|nr|count|pages)",
            window,
            re.IGNORECASE,
        )
        if inclusive_count and exclusive_loop:
            return (
                "The nearby range calculation appears to mix inclusive page count (`end-start+1`) "
                "with rollback loop bounds, which can overrun or under-rollback the recovery range."
            )
        if advanced_base and exclusive_loop:
            return (
                "The nearby rollback range uses an advanced phys/PFN/base expression with loop bounds, "
                "so recovery may start from the wrong base page."
            )
        return ""

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
    "mmu_teardown_order": (
        "Exact MMU/cache teardown-order bugs: MMU tables, VA regions, or parent page tables are freed before GPU address-space "
        "disable, schedule-out, TLB/cache flush, or hardware quiescence. Report the exact teardown and missing quiescence point."
    ),
    "mmu_lockdrop_stale": (
        "Exact MMU/VM lock-drop stale-state bugs: region/allocation/PGD/metadata state is cached, the MMU/VM lock is dropped "
        "and reacquired, then the cached value is reused without lookup/revalidation. Report exact cache, unlock, and reuse lines."
    ),
    "partial_mapping_rollback": (
        "Partial mapping rollback bugs: a mapping/MMU/alias install partially succeeds, a later failure path runs, and rollback "
        "uses the wrong extent/level or skips unmap/cache/TLB invalidation. Report exact install, failure, and rollback statements."
    ),
    "migration_metadata_race": (
        "Migration/shrinker metadata races: page_private/movable/huge-page metadata is read or mutated across a VM/MMU lock drop "
        "and then reused without proving the private metadata still has the same type or ownership."
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


class TargetedFileReviewer:
    def __init__(
        self,
        llm_provider,
        model,
        usage_runtime,
        codebase_path: str,
        max_tokens: int = 8192,
        cache: PartialAnalysisCache | None = None,
        symbol_index: SymbolIndex | None = None,
    ):
        self._p = llm_provider
        self._m = model
        self._u = usage_runtime
        self._cb = os.path.abspath(codebase_path)
        self._t = max_tokens
        self._cache = cache or PartialAnalysisCache(codebase_path, symbol_index)
        self._cache.bind_index(symbol_index)

    def review(self, context: PartialReviewContext, partial_graph: ReachabilityGraph, *,
               detector_result: PartialDetectorResult | None = None,
               max_workers=4, progress_callback=None) -> list[VulnerabilityFinding]:
        detector_result = detector_result or PartialDetectorResult()
        passes = self._build_passes(context, partial_graph, detector_result)
        if not passes:
            return []
        if progress_callback:
            progress_callback({"event": "partial_review_start", "passes": len(passes)})
        findings: list[VulnerabilityFinding] = []
        with ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(passes)))) as ex:
            futs = {
                submit_with_current_context(ex, self._run_pass, context, partial_graph, item, detector_result): item[0]
                for item in passes
            }
            for fut in as_completed(futs):
                pass_name = futs[fut]
                try:
                    findings.extend(fut.result())
                except Exception as exc:
                    logger.warning("Partial review pass failed for %s: %s", pass_name, exc)
        if progress_callback:
            progress_callback({"event": "partial_review_raw_done", "raw_findings": len(findings)})
        return findings

    def _build_passes(self, context, graph, detector_result):
        detector_nodes = detector_result.nodes or []
        copy_nodes = self._nodes_for_notes(detector_nodes, detector_result.copy_contract_notes)
        cleanup_nodes = self._nodes_for_notes(detector_nodes, detector_result.cleanup_symmetry_notes)
        accounting_nodes = self._nodes_for_notes(detector_nodes, detector_result.accounting_drift_notes)
        arithmetic_nodes = self._nodes_for_notes(detector_nodes, detector_result.arithmetic_chain_notes)
        resource_nodes = self._nodes_for_notes(detector_nodes, detector_result.resource_binding_notes)
        policy_nodes = self._nodes_for_notes(detector_nodes, detector_result.policy_gate_notes)
        resource_validation_nodes = self._nodes_for_notes(detector_nodes, detector_result.resource_validation_notes)
        cleanup_ledger_nodes = self._nodes_for_notes(detector_nodes, detector_result.cleanup_ledger_notes)
        async_nodes = self._nodes_for_notes(detector_nodes, detector_result.async_order_notes)
        size_nodes = self._nodes_for_notes(detector_nodes, detector_result.size_propagation_notes)
        tracker_nodes = self._nodes_for_notes(detector_nodes, detector_result.stale_tracker_notes)
        type_nodes = self._nodes_for_notes(detector_nodes, detector_result.metadata_type_confusion_notes)
        pm_nodes = self._nodes_for_notes(detector_nodes, detector_result.pm_sequence_notes)
        secondary_nodes = self._nodes_for_notes(detector_nodes, detector_result.secondary_omission_notes)
        protected_nodes = self._nodes_for_notes(detector_nodes, detector_result.protected_mmu_notes, cap=40)
        mmu_recovery_nodes = self._nodes_for_notes(detector_nodes, detector_result.mmu_recovery_notes, cap=32)
        sentinel_nodes = self._nodes_for_notes(detector_nodes, detector_result.sentinel_misuse_notes)
        suspend_cleanup_nodes = self._nodes_for_notes(detector_nodes, detector_result.suspend_cleanup_ledger_notes, cap=40)
        suspend_size_nodes = self._nodes_for_notes(detector_nodes, detector_result.suspend_size_sink_notes, cap=40)
        fault_clear_nodes = self._nodes_for_notes(detector_nodes, detector_result.fault_clear_order_notes, cap=40)
        pm_callback_nodes = self._nodes_for_notes(detector_nodes, detector_result.pm_callback_order_notes, cap=32)
        region_replace_nodes = self._nodes_for_notes(detector_nodes, detector_result.region_replace_erase_notes, cap=32)
        imported_mapping_nodes = self._nodes_for_notes(detector_nodes, detector_result.imported_mapping_policy_notes, cap=40)
        alias_extent_nodes = self._nodes_for_notes(detector_nodes, detector_result.alias_extent_mismatch_notes, cap=40)
        named_lock_nodes = self._nodes_for_notes(detector_nodes, detector_result.named_lock_inversion_notes, cap=48)
        active_singleton_nodes = self._nodes_for_notes(detector_nodes, detector_result.active_singleton_stale_notes, cap=40)
        zero_count_nodes = self._nodes_for_notes(detector_nodes, detector_result.zero_count_underflow_notes, cap=24)
        owner_liveness_nodes = self._nodes_for_notes(detector_nodes, detector_result.owner_liveness_notes, cap=32)
        user_buffer_nodes = self._nodes_for_notes(detector_nodes, detector_result.user_buffer_permission_notes, cap=32)
        zone_shrink_nodes = self._nodes_for_notes(detector_nodes, detector_result.zone_shrink_notes, cap=32)
        success_cleanup_nodes = self._nodes_for_notes(detector_nodes, detector_result.success_path_cleanup_notes, cap=32)
        jit_lock_nodes = self._nodes_for_notes(detector_nodes, detector_result.jit_lock_protocol_notes, cap=48)
        teardown_order_nodes = self._nodes_for_notes(detector_nodes, detector_result.teardown_order_notes, cap=48)
        mmu_lockdrop_nodes = self._nodes_for_notes(detector_nodes, detector_result.mmu_lockdrop_stale_notes, cap=40)
        mmu_teardown_nodes = self._nodes_for_notes(detector_nodes, detector_result.mmu_teardown_order_notes, cap=48)
        partial_mapping_nodes = self._nodes_for_notes(detector_nodes, detector_result.partial_mapping_rollback_notes, cap=40)
        migration_metadata_nodes = self._nodes_for_notes(detector_nodes, detector_result.migration_metadata_race_notes, cap=40)
        queue_publish_nodes = self._nodes_for_notes(detector_nodes, detector_result.queue_publish_init_notes, cap=32)
        fd_reuse_nodes = self._nodes_for_notes(detector_nodes, detector_result.fd_reuse_notes, cap=32)
        debugfs_nodes = self._nodes_for_notes(detector_nodes, detector_result.debugfs_permission_notes, cap=32)
        lock_cycle_nodes = self._nodes_for_notes(detector_nodes, detector_result.cross_file_lock_notes, cap=48)
        protocol_nodes = self._nodes_for_notes(detector_nodes, detector_result.protocol_notes, cap=48)
        passes = [
            ("target_intra", context.target_nodes, []),
            ("inbound_contract", context.target_nodes, context.inbound_callers),
            ("outbound_misuse", context.target_nodes, context.outbound_callees),
            ("shared_state", context.target_nodes, context.shared_state_nodes),
            ("lifecycle", context.target_nodes, context.lifecycle_pair_nodes + context.callback_nodes),
            ("concurrency", context.target_nodes, context.shared_state_nodes + context.callback_nodes + context.lifecycle_pair_nodes),
        ]
        if detector_result.state_publication_notes or detector_result.disable_stale_notes:
            passes.append((
                "state_publication", context.target_nodes,
                context.shared_state_nodes + context.lifecycle_pair_nodes + context.callback_nodes + detector_nodes,
            ))
        if detector_result.publish_rollback_notes:
            passes.append(("publish_rollback", context.target_nodes, context.lifecycle_pair_nodes + detector_nodes))
        if detector_result.copy_contract_notes:
            passes.append(("copy_contract", context.target_nodes, copy_nodes))
        if detector_result.cleanup_symmetry_notes:
            passes.append(("cleanup_symmetry", context.target_nodes, context.lifecycle_pair_nodes + cleanup_nodes))
        if detector_result.accounting_drift_notes:
            passes.append(("accounting_drift", context.target_nodes, context.shared_state_nodes + accounting_nodes))
        if detector_result.cleanup_ledger_notes:
            passes.append(("cleanup_ledger", context.target_nodes, context.lifecycle_pair_nodes + context.companion_nodes + cleanup_ledger_nodes))
        if detector_result.suspend_cleanup_ledger_notes:
            passes.append(("suspend_cleanup_ledger", context.target_nodes, context.companion_nodes + suspend_cleanup_nodes))
        if detector_result.suspend_size_sink_notes:
            passes.append(("suspend_size_sink", context.target_nodes, context.outbound_callees + context.companion_nodes + suspend_size_nodes))
        if detector_result.resource_validation_notes:
            passes.append(("resource_validation_order", context.target_nodes, context.shared_state_nodes + context.companion_nodes + resource_validation_nodes))
        if detector_result.alias_extent_mismatch_notes:
            passes.append(("alias_extent_mismatch", context.target_nodes, context.outbound_callees + context.companion_nodes + alias_extent_nodes))
        if detector_result.partial_mapping_rollback_notes:
            passes.append(("partial_mapping_rollback", context.target_nodes, context.outbound_callees + context.companion_nodes + partial_mapping_nodes))
        if detector_result.arithmetic_chain_notes:
            passes.append(("arithmetic_chain_mismatch", context.target_nodes, context.outbound_callees + arithmetic_nodes))
        if detector_result.size_propagation_notes:
            passes.append(("size_propagation", context.target_nodes, context.outbound_callees + context.companion_nodes + size_nodes))
        if detector_result.resource_binding_notes:
            passes.append((
                "resource_binding_order", context.target_nodes,
                context.shared_state_nodes + context.lifecycle_pair_nodes + context.companion_nodes + resource_nodes,
            ))
        if detector_result.async_order_notes:
            passes.append(("async_event_order", context.target_nodes, context.callback_nodes + context.companion_nodes + async_nodes))
        if detector_result.fault_clear_order_notes:
            passes.append(("fault_clear_order", context.target_nodes, context.callback_nodes + context.companion_nodes + fault_clear_nodes))
        if detector_result.stale_tracker_notes:
            passes.append(("stale_tracker_state", context.target_nodes, context.shared_state_nodes + tracker_nodes))
        if detector_result.region_replace_erase_notes:
            passes.append(("region_replace_erase", context.target_nodes, context.shared_state_nodes + context.companion_nodes + region_replace_nodes))
        if detector_result.metadata_type_confusion_notes:
            passes.append(("metadata_type_confusion", context.target_nodes, type_nodes))
        if detector_result.mmu_lockdrop_stale_notes:
            passes.append(("mmu_lockdrop_stale", context.target_nodes, context.shared_state_nodes + context.companion_nodes + mmu_lockdrop_nodes))
        if detector_result.migration_metadata_race_notes:
            passes.append(("migration_metadata_race", context.target_nodes, context.shared_state_nodes + context.companion_nodes + migration_metadata_nodes))
        if detector_result.pm_sequence_notes:
            passes.append(("pm_runtime_sequence", context.target_nodes, context.companion_nodes + pm_nodes))
        if detector_result.pm_callback_order_notes:
            passes.append(("pm_callback_order", context.target_nodes, context.companion_nodes + pm_callback_nodes))
        if detector_result.secondary_omission_notes:
            passes.append(("secondary_element_omission", context.target_nodes, secondary_nodes))
        if detector_result.zero_count_underflow_notes:
            passes.append(("zero_count_underflow", context.target_nodes, zero_count_nodes))
        if detector_result.owner_liveness_notes:
            passes.append(("owner_liveness_allocation", context.target_nodes, context.companion_nodes + owner_liveness_nodes))
        if detector_result.user_buffer_permission_notes:
            passes.append(("user_buffer_permission", context.target_nodes, context.companion_nodes + user_buffer_nodes))
        if detector_result.zone_shrink_notes:
            passes.append(("zone_shrink_validation", context.target_nodes, context.shared_state_nodes + context.companion_nodes + zone_shrink_nodes))
        if detector_result.success_path_cleanup_notes:
            passes.append(("success_path_cleanup", context.target_nodes, success_cleanup_nodes))
        if detector_result.jit_lock_protocol_notes:
            passes.append(("jit_lock_protocol", context.target_nodes, context.companion_nodes + context.shared_state_nodes + jit_lock_nodes))
        if detector_result.teardown_order_notes:
            passes.append(("teardown_order", context.target_nodes, context.companion_nodes + context.lifecycle_pair_nodes + teardown_order_nodes))
        if detector_result.mmu_teardown_order_notes:
            passes.append(("mmu_teardown_order", context.target_nodes, context.companion_nodes + context.lifecycle_pair_nodes + mmu_teardown_nodes))
        if detector_result.queue_publish_init_notes:
            passes.append(("queue_publish_init", context.target_nodes, context.shared_state_nodes + queue_publish_nodes))
        if detector_result.fd_reuse_notes:
            passes.append(("fd_reuse_race", context.target_nodes, context.companion_nodes + fd_reuse_nodes))
        if detector_result.debugfs_permission_notes:
            passes.append(("debugfs_permission", context.target_nodes, debugfs_nodes))
        if detector_result.policy_gate_notes:
            passes.append((
                "policy_gate_before_sink", context.target_nodes,
                context.companion_nodes + context.outbound_callees + policy_nodes,
            ))
        if detector_result.imported_mapping_policy_notes:
            passes.append((
                "imported_mapping_policy", context.target_nodes,
                context.companion_nodes + context.outbound_callees + imported_mapping_nodes,
            ))
        if detector_result.sentinel_misuse_notes:
            passes.append(("sentinel_misuse", context.target_nodes, sentinel_nodes))
        if detector_result.mmu_recovery_notes:
            passes.append(("mmu_recovery_rollback", context.target_nodes, context.outbound_callees + mmu_recovery_nodes))
        if detector_result.allocation_arithmetic_notes:
            passes.append(("allocation_arithmetic", context.target_nodes, context.outbound_callees + detector_nodes))
        if detector_result.format_notes or detector_result.info_leak_notes:
            passes.append(("format_and_info_leak", context.target_nodes, context.outbound_callees + detector_nodes))
        if detector_result.fops_notes:
            passes.append(("fops_lifecycle", context.target_nodes, context.callback_nodes + context.lifecycle_pair_nodes + detector_nodes))
        if detector_result.lock_order_notes or detector_result.stale_after_unlock_notes:
            passes.append(("lock_and_stale", context.target_nodes, context.shared_state_nodes + context.lifecycle_pair_nodes + detector_nodes))
        if detector_result.cross_file_lock_notes:
            passes.append((
                "cross_file_lock_cycle", context.target_nodes,
                context.companion_nodes + context.callback_nodes + context.lifecycle_pair_nodes
                + context.shared_state_nodes + lock_cycle_nodes,
            ))
        if detector_result.named_lock_inversion_notes:
            passes.append((
                "named_lock_inversion", context.target_nodes,
                context.companion_nodes + context.callback_nodes + context.shared_state_nodes + named_lock_nodes,
            ))
        if detector_result.protocol_notes:
            passes.append((
                "state_transition_protocol", context.target_nodes,
                context.companion_nodes + context.lifecycle_pair_nodes + context.callback_nodes
                + context.shared_state_nodes + protocol_nodes,
            ))
        if detector_result.protected_mmu_notes:
            passes.append((
                "protected_mmu_protocol", context.target_nodes,
                context.companion_nodes + context.lifecycle_pair_nodes + context.callback_nodes + protected_nodes,
            ))
        if detector_result.active_singleton_stale_notes:
            passes.append((
                "active_singleton_stale", context.target_nodes,
                context.companion_nodes + context.lifecycle_pair_nodes + context.callback_nodes + active_singleton_nodes,
            ))
        if self._should_add_partial_exact_fallback(detector_result):
            fallback_nodes = (
                context.companion_nodes[:24] + context.shared_state_nodes[:24]
                + context.lifecycle_pair_nodes[:16] + context.outbound_callees[:16]
            )
            passes.append(("partial_exact_fallback", context.target_nodes, fallback_nodes))
        return passes

    def _should_add_partial_exact_fallback(self, detector_result: PartialDetectorResult) -> bool:
        strong = (
            detector_result.copy_contract_notes
            or detector_result.cleanup_symmetry_notes
            or detector_result.cleanup_ledger_notes
            or detector_result.suspend_cleanup_ledger_notes
            or detector_result.accounting_drift_notes
            or detector_result.arithmetic_chain_notes
            or detector_result.alias_extent_mismatch_notes
            or detector_result.size_propagation_notes
            or detector_result.suspend_size_sink_notes
            or detector_result.resource_binding_notes
            or detector_result.resource_validation_notes
            or detector_result.async_order_notes
            or detector_result.fault_clear_order_notes
            or detector_result.stale_tracker_notes
            or detector_result.region_replace_erase_notes
            or detector_result.metadata_type_confusion_notes
            or detector_result.pm_sequence_notes
            or detector_result.pm_callback_order_notes
            or detector_result.secondary_omission_notes
            or detector_result.zero_count_underflow_notes
            or detector_result.owner_liveness_notes
            or detector_result.user_buffer_permission_notes
            or detector_result.zone_shrink_notes
            or detector_result.success_path_cleanup_notes
            or detector_result.jit_lock_protocol_notes
            or detector_result.teardown_order_notes
            or detector_result.mmu_lockdrop_stale_notes
            or detector_result.mmu_teardown_order_notes
            or detector_result.partial_mapping_rollback_notes
            or detector_result.migration_metadata_race_notes
            or detector_result.queue_publish_init_notes
            or detector_result.fd_reuse_notes
            or detector_result.debugfs_permission_notes
            or detector_result.policy_gate_notes
            or detector_result.imported_mapping_policy_notes
            or detector_result.sentinel_misuse_notes
            or detector_result.cross_file_lock_notes
            or detector_result.named_lock_inversion_notes
            or detector_result.protocol_notes
            or detector_result.protected_mmu_notes
            or detector_result.active_singleton_stale_notes
            or detector_result.mmu_recovery_notes
        )
        return not bool(strong)

    def _nodes_for_notes(self, nodes: list[FunctionNode], notes: list[str], *, cap: int = 32) -> list[FunctionNode]:
        if not nodes or not notes:
            return []
        text = "\n".join(notes[:80])
        selected = []
        seen = set()
        for node in nodes:
            keys = (node.unique_name, f"{node.file_path}::{node.name}", node.name)
            if not any(key and key in text for key in keys):
                continue
            if node.unique_name in seen:
                continue
            seen.add(node.unique_name)
            selected.append(node)
            if len(selected) >= cap:
                break
        if selected:
            return sorted(
                selected,
                key=lambda node: min(
                    (text.find(key) for key in (node.unique_name, f"{node.file_path}::{node.name}", node.name) if key and text.find(key) >= 0),
                    default=len(text),
                ),
            )
        return self._dedupe_nodes(nodes)[:cap]

    def _dedupe_nodes(self, nodes: list[FunctionNode]) -> list[FunctionNode]:
        seen, out = set(), []
        for node in nodes:
            if node.unique_name in seen:
                continue
            seen.add(node.unique_name)
            out.append(node)
        return out

    def _run_pass(self, context, graph, pass_item, detector_result):
        pass_name, target_nodes, context_nodes = pass_item
        target_code = self._build_code(target_nodes, per_fn_chars=4500, max_total_chars=42000)
        context_per_fn, context_total = self._context_code_budget(pass_name)
        context_code = self._build_code(context_nodes, per_fn_chars=context_per_fn, max_total_chars=context_total)
        if not target_code:
            return []
        prompt = ChatPromptTemplate.from_messages([
            ("system", _PARTIAL_REVIEW_SYS),
            ("user", _PARTIAL_REVIEW_USR),
        ])
        kw = self._u.hooks.chat_model_kwargs()
        chat = self._p.get_chat_model(model=self._m, max_tokens=self._t, temperature=0.1, **kw)
        raw = (prompt | chat | StrOutputParser()).invoke({
            "target_file": context.target_file,
            "pass_name": pass_name,
            "focus": _PASS_FOCI[pass_name],
            "scope_rule": self._scope_rule_for_pass(pass_name, context.target_file),
            "paths_section": self._paths_section(context.candidate_paths, graph),
            "candidate_notes": self._candidate_notes_for_pass(pass_name, detector_result),
            "globals_section": self._globals_section(context.globals),
            "target_code": target_code,
            "context_code": context_code,
        }).strip()
        return self._parse_findings(raw, context, graph, analysis_type=f"partial_{pass_name}")

    def _context_code_budget(self, pass_name: str) -> tuple[int, int]:
        if pass_name in {
            "copy_contract", "cleanup_symmetry", "accounting_drift",
            "arithmetic_chain_mismatch", "resource_binding_order",
            "policy_gate_before_sink", "resource_validation_order",
            "cleanup_ledger", "async_event_order", "size_propagation",
            "stale_tracker_state", "metadata_type_confusion", "pm_runtime_sequence",
            "secondary_element_omission", "protected_mmu_protocol", "mmu_recovery_rollback",
            "sentinel_misuse", "suspend_cleanup_ledger", "suspend_size_sink",
            "fault_clear_order", "pm_callback_order", "region_replace_erase",
            "imported_mapping_policy", "alias_extent_mismatch", "named_lock_inversion",
            "active_singleton_stale", "zero_count_underflow", "owner_liveness_allocation",
            "user_buffer_permission", "zone_shrink_validation", "success_path_cleanup",
            "jit_lock_protocol", "teardown_order", "queue_publish_init", "fd_reuse_race",
            "debugfs_permission", "mmu_lockdrop_stale", "mmu_teardown_order",
            "partial_mapping_rollback", "migration_metadata_race",
        }:
            return 2600, 36000
        if pass_name == "partial_exact_fallback":
            return 2800, 42000
        return 3000, 52000

    def _scope_rule_for_pass(self, pass_name: str, target_file: str) -> str:
        if pass_name in {"cross_file_lock_cycle", "state_transition_protocol"}:
            return (
                f"Findings must still use primary_file={target_file}. Companion files may prove the other half of the "
                "deadlock/protocol failure, but the target file must contain the concrete defective edge, unsafe transition, "
                "missing verification, or unsafe participation."
            )
        if pass_name in {
            "copy_contract", "cleanup_symmetry", "accounting_drift",
            "arithmetic_chain_mismatch", "resource_binding_order",
            "policy_gate_before_sink", "resource_validation_order",
            "cleanup_ledger", "async_event_order", "size_propagation",
            "stale_tracker_state", "metadata_type_confusion", "pm_runtime_sequence",
            "secondary_element_omission", "protected_mmu_protocol", "mmu_recovery_rollback",
            "sentinel_misuse", "suspend_cleanup_ledger", "suspend_size_sink",
            "fault_clear_order", "pm_callback_order", "region_replace_erase",
            "imported_mapping_policy", "alias_extent_mismatch", "named_lock_inversion",
            "active_singleton_stale", "zero_count_underflow", "owner_liveness_allocation",
            "user_buffer_permission", "zone_shrink_validation", "success_path_cleanup",
            "jit_lock_protocol", "teardown_order", "queue_publish_init", "fd_reuse_race",
            "debugfs_permission", "mmu_lockdrop_stale", "mmu_teardown_order",
            "partial_mapping_rollback", "migration_metadata_race",
        }:
            return (
                f"Findings must use primary_file={target_file} and identify the exact target-file statement plus the exact "
                "missing check, missing rollback, mismatched formula, stale binding, missing serialization, wrong sentinel, "
                "bad cast, skipped second element, or missing policy gate. Do not report adjacent generic lifecycle/race/null/"
                "overflow/info-leak issues unless they are necessary to explain the same root cause."
            )
        if pass_name == "partial_exact_fallback":
            return (
                f"Findings must use primary_file={target_file}. This is a bounded recall fallback: report only concrete "
                "target-file root causes in ordering/race, cleanup/unwind, branch-specific release, size propagation, "
                "metadata reinterpretation, imported/SAME_VA policy, or sentinel misuse families. Do not report generic "
                "style, null, missing-lock, or adjacent helper issues."
            )
        return "Findings must be rooted in the target file. Other files are evidence/context only."

    def _build_code(self, nodes, *, per_fn_chars, max_total_chars):
        parts, total = [], 0
        seen = set()
        for node in sorted(nodes, key=lambda n: (n.file_path, n.line_number, n.name)):
            if node.unique_name in seen:
                continue
            seen.add(node.unique_name)
            body = self._cache.node_body(node, max_chars=per_fn_chars)
            if not body:
                continue
            entry = f"--- {node.unique_name} (line {node.line_number} in {node.file_path}) ---\n{body}"
            if total + len(entry) > max_total_chars and parts:
                break
            parts.append(entry)
            total += len(entry)
        return "\n\n".join(parts)

    def _paths_section(self, paths, graph):
        lines = []
        for i, path in enumerate(paths[:80]):
            lines.append(f"Path {i}: {' -> '.join(path.path)}")
        return "\n".join(lines) if lines else "(none)"

    def _globals_section(self, globals_):
        lines = []
        for g in globals_[:40]:
            refs = ", ".join(g.referenced_functions)
            lines.append(
                f"GLOBAL {g.unique_name} line {g.line_number} kind={g.kind}\n"
                f"refs: {refs}\n{g.initializer[:1600]}"
            )
        return "\n\n".join(lines) if lines else "(none)"

    def _candidate_notes_for_pass(self, pass_name: str, detector_result: PartialDetectorResult) -> str:
        mapping = {
            "state_publication": (
                ("STATE_PUBLICATION", detector_result.state_publication_notes),
                ("DISABLE_STALE", detector_result.disable_stale_notes),
            ),
            "publish_rollback": (("PUBLISH_ROLLBACK", detector_result.publish_rollback_notes),),
            "allocation_arithmetic": (("ALLOCATION_ARITHMETIC", detector_result.allocation_arithmetic_notes),),
            "copy_contract": (("COPY_CONTRACT", detector_result.copy_contract_notes),),
            "cleanup_symmetry": (("CLEANUP_SYMMETRY", detector_result.cleanup_symmetry_notes),),
            "accounting_drift": (("ACCOUNTING_DRIFT", detector_result.accounting_drift_notes),),
            "cleanup_ledger": (("CLEANUP_LEDGER", detector_result.cleanup_ledger_notes),),
            "suspend_cleanup_ledger": (
                ("SUSPEND_CLEANUP_LEDGER", detector_result.suspend_cleanup_ledger_notes),
                ("CLEANUP_LEDGER", detector_result.cleanup_ledger_notes[:8]),
            ),
            "suspend_size_sink": (
                ("SUSPEND_SIZE_SINK", detector_result.suspend_size_sink_notes),
                ("SIZE_PROPAGATION", detector_result.size_propagation_notes[:8]),
            ),
            "resource_validation_order": (("RESOURCE_VALIDATION_ORDER", detector_result.resource_validation_notes),),
            "arithmetic_chain_mismatch": (
                ("ARITHMETIC_CHAIN_MISMATCH", detector_result.arithmetic_chain_notes),
                ("ALLOCATION_ARITHMETIC", detector_result.allocation_arithmetic_notes[:12]),
            ),
            "alias_extent_mismatch": (
                ("ALIAS_EXTENT_MISMATCH", detector_result.alias_extent_mismatch_notes),
                ("ARITHMETIC_CHAIN_MISMATCH", detector_result.arithmetic_chain_notes[:8]),
            ),
            "partial_mapping_rollback": (
                ("PARTIAL_MAPPING_ROLLBACK", detector_result.partial_mapping_rollback_notes),
                ("ALIAS_EXTENT_MISMATCH", detector_result.alias_extent_mismatch_notes[:6]),
            ),
            "size_propagation": (
                ("SIZE_PROPAGATION", detector_result.size_propagation_notes),
                ("ARITHMETIC_CHAIN_MISMATCH", detector_result.arithmetic_chain_notes[:12]),
            ),
            "resource_binding_order": (
                ("RESOURCE_BINDING_ORDER", detector_result.resource_binding_notes),
                ("RESOURCE_VALIDATION_ORDER", detector_result.resource_validation_notes[:12]),
                ("STATE_PUBLICATION", detector_result.state_publication_notes[:12]),
                ("DISABLE_STALE", detector_result.disable_stale_notes[:12]),
            ),
            "async_event_order": (("ASYNC_EVENT_ORDER", detector_result.async_order_notes),),
            "fault_clear_order": (
                ("FAULT_CLEAR_ORDER", detector_result.fault_clear_order_notes),
                ("ASYNC_EVENT_ORDER", detector_result.async_order_notes[:8]),
            ),
            "stale_tracker_state": (("STALE_TRACKER_STATE", detector_result.stale_tracker_notes),),
            "region_replace_erase": (
                ("REGION_REPLACE_ERASE", detector_result.region_replace_erase_notes),
                ("STALE_TRACKER_STATE", detector_result.stale_tracker_notes[:8]),
            ),
            "metadata_type_confusion": (("METADATA_TYPE_CONFUSION", detector_result.metadata_type_confusion_notes),),
            "mmu_lockdrop_stale": (
                ("MMU_LOCKDROP_STALE", detector_result.mmu_lockdrop_stale_notes),
                ("METADATA_TYPE_CONFUSION", detector_result.metadata_type_confusion_notes[:6]),
            ),
            "migration_metadata_race": (
                ("MIGRATION_METADATA_RACE", detector_result.migration_metadata_race_notes),
                ("METADATA_TYPE_CONFUSION", detector_result.metadata_type_confusion_notes[:6]),
            ),
            "pm_runtime_sequence": (("PM_RUNTIME_SEQUENCE", detector_result.pm_sequence_notes),),
            "pm_callback_order": (
                ("PM_CALLBACK_ORDER", detector_result.pm_callback_order_notes),
                ("PM_RUNTIME_SEQUENCE", detector_result.pm_sequence_notes[:8]),
            ),
            "secondary_element_omission": (("SECONDARY_ELEMENT_OMISSION", detector_result.secondary_omission_notes),),
            "zero_count_underflow": (("ZERO_COUNT_UNDERFLOW", detector_result.zero_count_underflow_notes),),
            "owner_liveness_allocation": (("OWNER_LIVENESS_ALLOCATION", detector_result.owner_liveness_notes),),
            "user_buffer_permission": (("USER_BUFFER_PERMISSION", detector_result.user_buffer_permission_notes),),
            "zone_shrink_validation": (("ZONE_SHRINK_VALIDATION", detector_result.zone_shrink_notes),),
            "success_path_cleanup": (
                ("SUCCESS_PATH_CLEANUP", detector_result.success_path_cleanup_notes),
                ("CLEANUP_SYMMETRY", detector_result.cleanup_symmetry_notes[:6]),
            ),
            "jit_lock_protocol": (("JIT_LOCK_PROTOCOL", detector_result.jit_lock_protocol_notes),),
            "teardown_order": (("TEARDOWN_ORDER", detector_result.teardown_order_notes),),
            "mmu_teardown_order": (
                ("MMU_TEARDOWN_ORDER", detector_result.mmu_teardown_order_notes),
                ("TEARDOWN_ORDER", detector_result.teardown_order_notes[:6]),
            ),
            "queue_publish_init": (
                ("QUEUE_PUBLISH_INIT", detector_result.queue_publish_init_notes),
                ("STATE_PUBLICATION", detector_result.state_publication_notes[:6]),
            ),
            "fd_reuse_race": (("FD_REUSE_RACE", detector_result.fd_reuse_notes),),
            "debugfs_permission": (("DEBUGFS_PERMISSION", detector_result.debugfs_permission_notes),),
            "protected_mmu_protocol": (
                ("PROTECTED_MMU_PROTOCOL", detector_result.protected_mmu_notes),
                ("STATE_TRANSITION_PROTOCOL", detector_result.protocol_notes[:12]),
            ),
            "active_singleton_stale": (
                ("ACTIVE_SINGLETON_STALE", detector_result.active_singleton_stale_notes),
                ("PROTECTED_MMU_PROTOCOL", detector_result.protected_mmu_notes[:8]),
            ),
            "mmu_recovery_rollback": (("MMU_RECOVERY_ROLLBACK", detector_result.mmu_recovery_notes),),
            "sentinel_misuse": (("SENTINEL_MISUSE", detector_result.sentinel_misuse_notes),),
            "policy_gate_before_sink": (("POLICY_GATE_BEFORE_SINK", detector_result.policy_gate_notes),),
            "imported_mapping_policy": (
                ("IMPORTED_MAPPING_POLICY", detector_result.imported_mapping_policy_notes),
                ("POLICY_GATE_BEFORE_SINK", detector_result.policy_gate_notes[:8]),
            ),
            "format_and_info_leak": (
                ("FORMAT_WRAPPER", detector_result.format_notes),
                ("INFO_LEAK", detector_result.info_leak_notes),
            ),
            "fops_lifecycle": (
                ("FOPS_LIFECYCLE", detector_result.fops_notes),
                ("CALLBACK_LIFETIME", detector_result.callback_lifetime_notes),
            ),
            "lock_and_stale": (
                ("LOCK_ORDER", detector_result.lock_order_notes),
                ("STALE_AFTER_UNLOCK", detector_result.stale_after_unlock_notes),
            ),
            "cross_file_lock_cycle": (
                ("CROSS_FILE_LOCK_CYCLE", detector_result.cross_file_lock_notes),
                ("LOCK_ORDER", detector_result.lock_order_notes[:20]),
            ),
            "named_lock_inversion": (
                ("NAMED_LOCK_INVERSION", detector_result.named_lock_inversion_notes),
                ("CROSS_FILE_LOCK_CYCLE", detector_result.cross_file_lock_notes[:8]),
            ),
            "state_transition_protocol": (
                ("STATE_TRANSITION_PROTOCOL", detector_result.protocol_notes),
                ("STATE_PUBLICATION", detector_result.state_publication_notes[:20]),
                ("DISABLE_STALE", detector_result.disable_stale_notes[:20]),
            ),
            "lifecycle": (
                ("CALLBACK_LIFETIME", detector_result.callback_lifetime_notes[:20]),
                ("FOPS_LIFECYCLE", detector_result.fops_notes[:20]),
            ),
            "concurrency": (
                ("LOCK_ORDER", detector_result.lock_order_notes[:20]),
                ("STALE_AFTER_UNLOCK", detector_result.stale_after_unlock_notes[:20]),
            ),
            "target_intra": (
                ("STATE_PUBLICATION", detector_result.state_publication_notes[:12]),
                ("ALLOCATION_ARITHMETIC", detector_result.allocation_arithmetic_notes[:12]),
                ("FORMAT_OR_INFO", (detector_result.format_notes + detector_result.info_leak_notes)[:12]),
            ),
            "shared_state": (
                ("DISABLE_STALE", detector_result.disable_stale_notes[:12]),
                ("CALLBACK_LIFETIME", detector_result.callback_lifetime_notes[:12]),
            ),
            "partial_exact_fallback": (
                ("STATE_PUBLICATION", detector_result.state_publication_notes[:8]),
                ("PUBLISH_ROLLBACK", detector_result.publish_rollback_notes[:8]),
                ("LOCK_ORDER", detector_result.lock_order_notes[:8]),
                ("CALLBACK_LIFETIME", detector_result.callback_lifetime_notes[:8]),
            ),
        }
        groups = mapping.get(pass_name, ())
        lines: list[str] = []
        for title, notes in groups:
            if not notes:
                continue
            lines.append(f"{title}:")
            lines.extend(f"- {note}" for note in notes[:40])
        if len(lines) > 90:
            lines = lines[:90] + ["- ..."]
        return "\n".join(lines) if lines else "(none)"

    def _parse_findings(self, raw, context, graph, analysis_type):
        parsed = parse_json_output(raw)
        if not isinstance(parsed, dict):
            return []
        entries = parsed.get("findings")
        if not isinstance(entries, list):
            return []
        by_name = {n.name: n for n in graph.nodes.values()}
        by_unique = dict(graph.nodes)
        target_default = context.target_nodes[0] if context.target_nodes else None
        results = []
        for entry in entries:
            if not isinstance(entry, dict) or entry.get("is_vulnerable") is False:
                continue
            fn = self._lookup_node(str(entry.get("function_name") or ""), by_name, by_unique) or target_default
            related = self._lookup_node(str(entry.get("related_function") or ""), by_name, by_unique)
            if not fn:
                continue
            line = _safe_int(entry.get("line"), fn.line_number)
            primary_file = str(entry.get("primary_file") or "").strip() or fn.file_path
            primary_function = str(entry.get("primary_function") or "").strip() or fn.unique_name
            primary_line = _safe_int(entry.get("primary_line"), line)
            canonical_key = str(entry.get("canonical_key") or "").strip()
            if not _same_file_ref(primary_file, context.target_file, self._cb):
                continue
            src = related or fn
            results.append(VulnerabilityFinding(
                id=os.urandom(8).hex(),
                vulnerability_type=_normalise_partial_vuln_type(entry.get("vulnerability_type") or "other"),
                severity=str(entry.get("severity") or "medium"),
                confidence=str(entry.get("confidence") or "medium"),
                source_function=src.unique_name,
                source_file=src.file_path,
                source_line=src.line_number,
                sink_function=fn.unique_name,
                sink_file=fn.file_path,
                sink_line=line,
                path=[src.unique_name, fn.unique_name] if related else [fn.unique_name],
                description=str(entry.get("description") or ""),
                root_cause=str(entry.get("root_cause") or ""),
                evidence=str(entry.get("evidence") or ""),
                analysis_type=analysis_type,
                primary_file=primary_file,
                primary_function=primary_function,
                primary_line=primary_line,
                canonical_key=canonical_key,
            ))
        return results

    def _lookup_node(self, name, by_name, by_unique):
        if not name:
            return None
        if name in by_unique:
            return by_unique[name]
        if name in by_name:
            return by_name[name]
        short = name.split("::")[-1]
        return by_name.get(short)


def _partial_finding_text(finding: VulnerabilityFinding) -> str:
    return " ".join(str(part or "") for part in (
        finding.description, finding.root_cause, finding.evidence, finding.canonical_key,
        finding.primary_function, finding.sink_function, finding.source_function,
    ))


def _partial_duplicate_family(vtype: str) -> str:
    normal = _normalise_partial_vuln_type(vtype)
    aliases = {
        "callback_lifecycle": "teardown_lifecycle",
        "deferred_uaf": "teardown_lifecycle",
        "teardown_race": "teardown_lifecycle",
        "file_ops_lifecycle_gap": "teardown_lifecycle",
        "stale_after_unlock": "lifetime",
        "stale_pointer": "lifetime",
        "use_after_free": "lifetime",
        "refcount_imbalance": "accounting",
        "wrong_constant": "semantic_mismatch",
        "wrong_flag_semantic": "semantic_mismatch",
        "permission_mismatch": "semantic_mismatch",
        "state_order": "state_order",
        "ordering_gap": "state_order",
        "stale_state": "state_order",
        "copy_contract": "copy_contract",
        "cleanup_symmetry": "cleanup",
        "accounting_drift": "accounting",
        "arithmetic_chain_mismatch": "arithmetic_chain",
        "resource_binding_order": "resource_binding",
        "policy_gate_before_sink": "policy_gate",
        "cross_file_lock_cycle": "lock_cycle",
        "state_transition_protocol": "state_order",
        "resource_validation_order": "resource_binding",
        "cleanup_ledger": "cleanup",
        "suspend_cleanup_ledger": "cleanup",
        "suspend_size_sink": "arithmetic_chain",
        "async_event_order": "state_order",
        "fault_clear_order": "state_order",
        "size_propagation": "arithmetic_chain",
        "alias_extent_mismatch": "arithmetic_chain",
        "stale_tracker_state": "resource_binding",
        "region_replace_erase": "resource_binding",
        "metadata_type_confusion": "type_confusion",
        "pm_runtime_sequence": "state_order",
        "pm_callback_order": "state_order",
        "secondary_element_omission": "logic_omission",
        "zero_count_underflow": "integer_underflow",
        "owner_liveness_allocation": "resource_exhaustion",
        "user_buffer_permission": "policy_gate",
        "zone_shrink_validation": "resource_binding",
        "success_path_cleanup": "cleanup",
        "jit_lock_protocol": "lock_cycle",
        "teardown_order": "lifetime",
        "mmu_lockdrop_stale": "lifetime",
        "mmu_teardown_order": "lifetime",
        "partial_mapping_rollback": "mmu_recovery",
        "migration_metadata_race": "type_confusion",
        "queue_publish_init": "lifetime",
        "fd_reuse_race": "lifetime",
        "debugfs_permission": "policy_gate",
        "protected_mmu_protocol": "state_order",
        "active_singleton_stale": "lifetime",
        "mmu_recovery_rollback": "mmu_recovery",
        "sentinel_misuse": "semantic_mismatch",
        "imported_mapping_policy": "policy_gate",
        "named_lock_inversion": "lock_cycle",
    }
    return aliases.get(normal, normal)


def _partial_canonical_key(key: str) -> str:
    text = re.sub(r"[^a-z0-9]+", "_", str(key or "").lower())
    noisy = {
        "unchecked", "direct", "same", "path", "same_path", "same_path_input",
        "input", "user", "attacker", "unsanitized", "untrusted", "source", "sink",
    }
    tokens = [t for t in text.split("_") if t and t not in noisy]
    return "_".join(tokens)


def _partial_overlap(a: VulnerabilityFinding, b: VulnerabilityFinding) -> float:
    ta = _partial_note_tokens(_partial_finding_text(a))
    tb = _partial_note_tokens(_partial_finding_text(b))
    if not ta or not tb:
        return 0.0
    common = len(ta & tb)
    return common / max(1, min(len(ta), len(tb)))


def _partial_same_root(a: VulnerabilityFinding, b: VulnerabilityFinding) -> bool:
    af = a.primary_file or a.sink_file or a.source_file
    bf = b.primary_file or b.sink_file or b.source_file
    if af != bf:
        return False
    family_a = _partial_duplicate_family(a.vulnerability_type)
    family_b = _partial_duplicate_family(b.vulnerability_type)
    if family_a != family_b:
        return False
    fn_a = a.primary_function or a.sink_function or a.source_function
    fn_b = b.primary_function or b.sink_function or b.source_function
    line_a = _safe_int(a.primary_line or a.sink_line or a.source_line, 0)
    line_b = _safe_int(b.primary_line or b.sink_line or b.source_line, 0)
    if fn_a == fn_b and line_a and line_b and abs(line_a - line_b) <= 10:
        return True
    if a.sink_line and b.sink_line and a.sink_line == b.sink_line:
        return True
    ca = _partial_canonical_key(a.canonical_key)
    cb = _partial_canonical_key(b.canonical_key)
    if ca and cb and ca == cb:
        return True
    return fn_a == fn_b and _partial_overlap(a, b) >= 0.58


def _pick_partial_best(findings: list[VulnerabilityFinding]) -> VulnerabilityFinding:
    sev = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    conf = {"high": 0, "medium": 1, "low": 2}
    return min(findings, key=lambda f: (
        _PARTIAL_PASS_PRIORITY.get(f.analysis_type, 50),
        sev.get(str(f.severity or "").lower(), 5),
        conf.get(str(f.confidence or "").lower(), 3),
        len(f.path or []),
        -len(_partial_finding_text(f)),
    ))


def _collapse_partial_duplicates(findings: list[VulnerabilityFinding]) -> list[VulnerabilityFinding]:
    clusters: list[list[VulnerabilityFinding]] = []
    for finding in findings:
        merged = False
        for cluster in clusters:
            if _partial_same_root(finding, cluster[0]):
                cluster.append(finding)
                merged = True
                break
        if not merged:
            clusters.append([finding])
    return [_pick_partial_best(cluster) for cluster in clusters]


def _dedupe_partial_findings(findings: list[VulnerabilityFinding], *, max_per_sink: int) -> list[VulnerabilityFinding]:
    collapsed = _collapse_partial_duplicates(findings)
    deduped, _, _ = Deduplicator.deduplicate(collapsed, max_per_sink=max_per_sink)
    return _collapse_partial_duplicates(deduped)


def _is_external_entrypoint_finding(finding: VulnerabilityFinding) -> bool:
    text = _partial_finding_text(finding).lower()
    fn = str(finding.primary_function or finding.sink_function or finding.source_function or "").lower()
    return bool(re.search(
        r"\b(ioctl|dispatch|sysfs|debugfs|netlink|fops|file_operations|open|read|write|"
        r"poll|flush|release|callback|handler|irq|interrupt|user|copy_from_user|main)\b",
        f"{fn} {text}",
    ))


def _suppress_generic_null(finding: VulnerabilityFinding) -> bool:
    if _normalise_partial_vuln_type(finding.vulnerability_type) != "null_deref":
        return False
    text = _partial_finding_text(finding).lower()
    if re.search(r"\b(lookup|find|malloc|calloc|realloc|returns?\s+null|no matching|after loop|task_find|session_get|store_get|get_)\b", text):
        return False
    if _is_external_entrypoint_finding(finding):
        return False
    return bool(re.search(
        r"(missing\s+null\s+check|missing\s+null-check|caller-supplied pointer|"
        r"inbound pointer contract|missing validation of .* pointer|missing null check on "
        r"(?:dev|ctx|queue|obj|session|task|region))",
        text,
    ))


def _suppress_generic_missing_lock(finding: VulnerabilityFinding, detector_result: PartialDetectorResult) -> bool:
    if _normalise_partial_vuln_type(finding.vulnerability_type) != "missing_lock":
        return False
    text = _partial_finding_text(finding).lower()
    concrete = re.search(r"\b(free|destroy|teardown|release|callback|work|timer|fops|poll|ioctl|use-after-free|uaf|corrupt)\b", text)
    if concrete:
        return False
    notes = " ".join(
        detector_result.lock_order_notes
        + detector_result.stale_after_unlock_notes
        + detector_result.callback_lifetime_notes
        + detector_result.fops_notes
    )
    if _partial_note_tokens(text) & _partial_note_tokens(notes):
        return False
    return True


def _suppress_generic_partial(finding: VulnerabilityFinding) -> bool:
    text = _partial_finding_text(finding).lower()
    severity = str(finding.severity or "").lower()
    vtype = _normalise_partial_vuln_type(finding.vulnerability_type)
    if ("overwrites global file handle" in text or "repeated init" in text) and severity not in {"high", "critical"}:
        if not re.search(r"\b(double|use-after-free|uaf|security|attacker|external)\b", text):
            return True
    if vtype in {"missing_auth", "permission_mismatch"} and not _is_external_entrypoint_finding(finding):
        if re.search(r"\b(primitive|helper|low-level|lacks built-in authorization|caller authorization)\b", text):
            return True
    return False


_EXACT_PARTIAL_ANALYSIS_TYPES = frozenset({
    "partial_copy_contract",
    "partial_cleanup_symmetry",
    "partial_accounting_drift",
    "partial_arithmetic_chain_mismatch",
    "partial_resource_binding_order",
    "partial_policy_gate_before_sink",
    "partial_cross_file_lock_cycle",
    "partial_state_transition_protocol",
    "partial_resource_validation_order",
    "partial_cleanup_ledger",
    "partial_suspend_cleanup_ledger",
    "partial_suspend_size_sink",
    "partial_async_event_order",
    "partial_fault_clear_order",
    "partial_size_propagation",
    "partial_alias_extent_mismatch",
    "partial_stale_tracker_state",
    "partial_region_replace_erase",
    "partial_metadata_type_confusion",
    "partial_pm_runtime_sequence",
    "partial_pm_callback_order",
    "partial_secondary_element_omission",
    "partial_zero_count_underflow",
    "partial_owner_liveness_allocation",
    "partial_user_buffer_permission",
    "partial_zone_shrink_validation",
    "partial_success_path_cleanup",
    "partial_jit_lock_protocol",
    "partial_teardown_order",
    "partial_mmu_lockdrop_stale",
    "partial_mmu_teardown_order",
    "partial_partial_mapping_rollback",
    "partial_migration_metadata_race",
    "partial_queue_publish_init",
    "partial_fd_reuse_race",
    "partial_debugfs_permission",
    "partial_protected_mmu_protocol",
    "partial_active_singleton_stale",
    "partial_mmu_recovery_rollback",
    "partial_sentinel_misuse",
    "partial_imported_mapping_policy",
    "partial_named_lock_inversion",
})
_WEAK_GENERIC_VTYPES = frozenset({
    "null_deref", "missing_lock", "teardown_race", "callback_lifecycle",
    "deferred_uaf", "integer_overflow", "buffer_overflow", "lock_order",
    "state_order", "ordering_gap", "info_leak", "format_string", "other",
})


def _prefer_exact_partial_findings(findings: list[VulnerabilityFinding]) -> list[VulnerabilityFinding]:
    exact = [f for f in findings if f.analysis_type in _EXACT_PARTIAL_ANALYSIS_TYPES]
    if not exact:
        return findings
    kept = []
    for finding in findings:
        if finding.analysis_type in _EXACT_PARTIAL_ANALYSIS_TYPES:
            if _is_weaker_exact_adjacent_to_stronger(finding, exact):
                continue
            kept.append(finding)
            continue
        if not _is_weaker_adjacent_to_exact(finding, exact):
            kept.append(finding)
    return kept


def _is_weaker_exact_adjacent_to_stronger(finding: VulnerabilityFinding, exact_findings: list[VulnerabilityFinding]) -> bool:
    weaker = {
        "partial_cross_file_lock_cycle", "partial_state_transition_protocol",
        "partial_resource_binding_order", "partial_allocation_arithmetic",
        "partial_async_event_order", "partial_cleanup_ledger",
        "partial_arithmetic_chain_mismatch", "partial_size_propagation",
        "partial_policy_gate_before_sink", "partial_stale_tracker_state",
        "partial_pm_runtime_sequence", "partial_teardown_order",
        "partial_owner_liveness_allocation",
        "partial_metadata_type_confusion", "partial_alias_extent_mismatch",
        "partial_zero_count_underflow",
    }
    if finding.analysis_type not in weaker:
        return False
    preferred_stronger = {
        "partial_alias_extent_mismatch": {"partial_partial_mapping_rollback"},
        "partial_arithmetic_chain_mismatch": {"partial_alias_extent_mismatch", "partial_partial_mapping_rollback"},
        "partial_size_propagation": {"partial_suspend_size_sink", "partial_partial_mapping_rollback"},
        "partial_teardown_order": {"partial_mmu_teardown_order"},
        "partial_metadata_type_confusion": {"partial_migration_metadata_race", "partial_mmu_lockdrop_stale"},
        "partial_zero_count_underflow": {
            "partial_mmu_recovery_rollback",
            "partial_metadata_type_confusion",
            "partial_migration_metadata_race",
        },
        "partial_owner_liveness_allocation": {
            "partial_mmu_teardown_order",
            "partial_mmu_lockdrop_stale",
            "partial_partial_mapping_rollback",
        },
    }
    own_priority = _PARTIAL_PASS_PRIORITY.get(finding.analysis_type, 50)
    fn = finding.primary_function or finding.sink_function or finding.source_function
    line = _safe_int(finding.primary_line or finding.sink_line or finding.source_line, 0)
    text = _partial_finding_text(finding).lower()
    finding_file = finding.primary_file or finding.sink_file or finding.source_file
    finding_domains = _domain_root_tokens(text)
    for exact in exact_findings:
        if exact is finding:
            continue
        exact_file = exact.primary_file or exact.sink_file or exact.source_file
        if finding_file and exact_file and finding_file != exact_file:
            continue
        exact_fn = exact.primary_function or exact.sink_function or exact.source_function
        exact_line = _safe_int(exact.primary_line or exact.sink_line or exact.source_line, 0)
        exact_text = _partial_finding_text(exact).lower()
        exact_domains = _domain_root_tokens(exact_text)
        if not (finding_domains & exact_domains):
            continue
        preferred = exact.analysis_type in preferred_stronger.get(finding.analysis_type, set())
        if _PARTIAL_PASS_PRIORITY.get(exact.analysis_type, 50) >= own_priority and not preferred:
            continue
        same_fn = bool(fn and exact_fn and fn == exact_fn)
        tight_line = bool(line and exact_line and abs(line - exact_line) <= 10)
        if same_fn or tight_line:
            return True
    return False


def _is_weaker_adjacent_to_exact(finding: VulnerabilityFinding, exact_findings: list[VulnerabilityFinding]) -> bool:
    vtype = _normalise_partial_vuln_type(finding.vulnerability_type)
    if vtype not in _WEAK_GENERIC_VTYPES and not finding.analysis_type.endswith(("target_intra", "concurrency", "lifecycle")):
        return False
    fn = finding.primary_function or finding.sink_function or finding.source_function
    line = _safe_int(finding.primary_line or finding.sink_line or finding.source_line, 0)
    weak_text = _partial_finding_text(finding).lower()
    weak_domains = _domain_root_tokens(weak_text)
    finding_file = finding.primary_file or finding.sink_file or finding.source_file
    for exact in exact_findings:
        exact_file = exact.primary_file or exact.sink_file or exact.source_file
        if finding_file and exact_file and finding_file != exact_file:
            continue
        exact_text = _partial_finding_text(exact).lower()
        exact_domains = _domain_root_tokens(exact_text)
        if not (weak_domains & exact_domains):
            continue
        exact_fn = exact.primary_function or exact.sink_function or exact.source_function
        exact_line = _safe_int(exact.primary_line or exact.sink_line or exact.source_line, 0)
        same_fn = bool(fn and exact_fn and fn == exact_fn)
        tight_line = bool(
            (line and exact_line and abs(line - exact_line) <= 10)
            or (exact.sink_line and finding.sink_line and abs(exact.sink_line - finding.sink_line) <= 10)
        )
        if same_fn or tight_line:
            return True
    return False


def _post_filter_partial_findings(
    findings: list[VulnerabilityFinding],
    target_file: str,
    detector_result: PartialDetectorResult,
    codebase_path: str,
) -> tuple[list[VulnerabilityFinding], PartialPostFilterStats]:
    stats = PartialPostFilterStats()
    kept: list[VulnerabilityFinding] = []
    for finding in findings:
        finding.vulnerability_type = _normalise_partial_vuln_type(finding.vulnerability_type)
        primary = finding.primary_file or finding.sink_file or finding.source_file
        if not primary or not _same_file_ref(primary, target_file, codebase_path):
            stats.suppressed_non_target += 1
            continue
        if _suppress_generic_null(finding):
            stats.suppressed_null += 1
            continue
        if _suppress_generic_missing_lock(finding, detector_result):
            stats.suppressed_lock += 1
            continue
        if _suppress_generic_partial(finding):
            stats.suppressed_generic += 1
            continue
        kept.append(finding)
    refined = _prefer_exact_partial_findings(kept)
    stats.suppressed_generic += len(kept) - len(refined)
    return refined, stats


def _partial_cwe(vtype: str, finding: VulnerabilityFinding) -> str | None:
    normal = _normalise_partial_vuln_type(vtype)
    if normal == "info_leak":
        text = _partial_finding_text(finding).lower()
        return "CWE-532" if re.search(r"\b(log|printf|debug|trace|printk)\b", text) else "CWE-200"
    return _PARTIAL_CWE_OVERRIDES.get(normal) or _VULN_TO_CWE.get(normal)


class PartialReachabilityFileService:
    def __init__(self, config: EngineConfig, repository: EngineRepository, llm_provider, usage_runtime):
        self._config = config
        self._repository = repository
        self._llm_provider = llm_provider
        self._usage_runtime = usage_runtime
        self._symbol_index: SymbolIndex | None = None
        self._index_lock = threading.Lock()

    def review_file(
        self,
        file_path,
        *,
        extraction_model="gpt-4.1-mini",
        review_model=None,
        max_workers=8,
        context_budget=250,
        max_paths_per_sink=3,
        progress_callback=None,
    ):
        abs_target, rel_target = self._normalize_target_file(file_path)
        if os.path.splitext(rel_target)[1].lower() not in _C_CPP_EXTS:
            return None

        index = self._ensure_symbol_index(progress_callback=progress_callback)
        cache = PartialAnalysisCache(self._config.codebase_path, index)
        target_nodes, target_globals = self._extract_target(
            abs_target, rel_target, extraction_model, max_workers, progress_callback, cache)

        caps = PartialContextCaps(max_total_context_functions=max(25, int(context_budget or 250)))
        if progress_callback:
            progress_callback({"event": "partial_context_start", "file": rel_target})
        context_builder = PartialContextBuilder(self._config.codebase_path, caps, cache)
        context = context_builder.build_for_file(rel_target, target_nodes, index)
        if target_globals:
            context.globals = self._merge_globals(context.globals, target_globals)
        context_builder.expand_companions(context, index, progress_callback=progress_callback)

        detector_result = PartialCandidateDetector(self._config.codebase_path, cache).detect(
            index, rel_target, context.target_nodes, context)
        self._merge_detector_context(context, detector_result)
        if progress_callback:
            progress_callback({
                "event": "partial_detectors_done",
                "state_publication": len(detector_result.state_publication_notes),
                "publish_rollback": len(detector_result.publish_rollback_notes),
                "allocation_arithmetic": len(detector_result.allocation_arithmetic_notes),
                "copy_contracts": len(detector_result.copy_contract_notes),
                "cleanup_symmetry": len(detector_result.cleanup_symmetry_notes),
                "cleanup_ledger": len(detector_result.cleanup_ledger_notes),
                "suspend_cleanup_ledger": len(detector_result.suspend_cleanup_ledger_notes),
                "accounting_drift": len(detector_result.accounting_drift_notes),
                "arithmetic_chain": len(detector_result.arithmetic_chain_notes),
                "alias_extent_mismatch": len(detector_result.alias_extent_mismatch_notes),
                "size_propagation": len(detector_result.size_propagation_notes),
                "suspend_size_sink": len(detector_result.suspend_size_sink_notes),
                "resource_binding": len(detector_result.resource_binding_notes),
                "resource_validation": len(detector_result.resource_validation_notes),
                "async_order": len(detector_result.async_order_notes),
                "fault_clear_order": len(detector_result.fault_clear_order_notes),
                "stale_tracker": len(detector_result.stale_tracker_notes),
                "region_replace_erase": len(detector_result.region_replace_erase_notes),
                "metadata_type_confusion": len(detector_result.metadata_type_confusion_notes),
                "pm_sequence": len(detector_result.pm_sequence_notes),
                "pm_callback_order": len(detector_result.pm_callback_order_notes),
                "secondary_omission": len(detector_result.secondary_omission_notes),
                "zero_count_underflow": len(detector_result.zero_count_underflow_notes),
                "owner_liveness_allocation": len(detector_result.owner_liveness_notes),
                "user_buffer_permission": len(detector_result.user_buffer_permission_notes),
                "zone_shrink_validation": len(detector_result.zone_shrink_notes),
                "success_path_cleanup": len(detector_result.success_path_cleanup_notes),
                "jit_lock_protocol": len(detector_result.jit_lock_protocol_notes),
                "teardown_order": len(detector_result.teardown_order_notes),
                "mmu_lockdrop_stale": len(detector_result.mmu_lockdrop_stale_notes),
                "mmu_teardown_order": len(detector_result.mmu_teardown_order_notes),
                "partial_mapping_rollback": len(detector_result.partial_mapping_rollback_notes),
                "migration_metadata_race": len(detector_result.migration_metadata_race_notes),
                "queue_publish_init": len(detector_result.queue_publish_init_notes),
                "fd_reuse_race": len(detector_result.fd_reuse_notes),
                "debugfs_permission": len(detector_result.debugfs_permission_notes),
                "protected_mmu": len(detector_result.protected_mmu_notes),
                "active_singleton_stale": len(detector_result.active_singleton_stale_notes),
                "mmu_recovery": len(detector_result.mmu_recovery_notes),
                "sentinel_misuse": len(detector_result.sentinel_misuse_notes),
                "policy_gates": len(detector_result.policy_gate_notes),
                "imported_mapping_policy": len(detector_result.imported_mapping_policy_notes),
                "format_wrappers": len(detector_result.format_notes),
                "info_leaks": len(detector_result.info_leak_notes),
                "fops": len(detector_result.fops_notes),
                "lock_order": len(detector_result.lock_order_notes),
                "stale_after_unlock": len(detector_result.stale_after_unlock_notes),
                "disable_stale": len(detector_result.disable_stale_notes),
                "callback_lifetime": len(detector_result.callback_lifetime_notes),
                "cross_file_lock_cycles": len(detector_result.cross_file_lock_notes),
                "named_lock_inversion": len(detector_result.named_lock_inversion_notes),
                "protocol_candidates": len(detector_result.protocol_notes),
            })
            if detector_result.cross_file_lock_notes:
                progress_callback({
                    "event": "partial_lock_cycle_candidates",
                    "candidates": len(detector_result.cross_file_lock_notes),
                })
            if detector_result.protocol_notes:
                progress_callback({
                    "event": "partial_protocol_candidates",
                    "candidates": len(detector_result.protocol_notes),
                })
            exact_count = (
                len(detector_result.copy_contract_notes)
                + len(detector_result.cleanup_symmetry_notes)
                + len(detector_result.cleanup_ledger_notes)
                + len(detector_result.suspend_cleanup_ledger_notes)
                + len(detector_result.accounting_drift_notes)
                + len(detector_result.arithmetic_chain_notes)
                + len(detector_result.alias_extent_mismatch_notes)
                + len(detector_result.size_propagation_notes)
                + len(detector_result.suspend_size_sink_notes)
                + len(detector_result.resource_binding_notes)
                + len(detector_result.resource_validation_notes)
                + len(detector_result.async_order_notes)
                + len(detector_result.fault_clear_order_notes)
                + len(detector_result.stale_tracker_notes)
                + len(detector_result.region_replace_erase_notes)
                + len(detector_result.metadata_type_confusion_notes)
                + len(detector_result.pm_sequence_notes)
                + len(detector_result.pm_callback_order_notes)
                + len(detector_result.secondary_omission_notes)
                + len(detector_result.zero_count_underflow_notes)
                + len(detector_result.owner_liveness_notes)
                + len(detector_result.user_buffer_permission_notes)
                + len(detector_result.zone_shrink_notes)
                + len(detector_result.success_path_cleanup_notes)
                + len(detector_result.jit_lock_protocol_notes)
                + len(detector_result.teardown_order_notes)
                + len(detector_result.mmu_lockdrop_stale_notes)
                + len(detector_result.mmu_teardown_order_notes)
                + len(detector_result.partial_mapping_rollback_notes)
                + len(detector_result.migration_metadata_race_notes)
                + len(detector_result.queue_publish_init_notes)
                + len(detector_result.fd_reuse_notes)
                + len(detector_result.debugfs_permission_notes)
                + len(detector_result.protected_mmu_notes)
                + len(detector_result.active_singleton_stale_notes)
                + len(detector_result.mmu_recovery_notes)
                + len(detector_result.sentinel_misuse_notes)
                + len(detector_result.policy_gate_notes)
                + len(detector_result.imported_mapping_policy_notes)
                + len(detector_result.named_lock_inversion_notes)
            )
            if exact_count:
                progress_callback({
                    "event": "partial_exact_root_cause_candidates",
                    "candidates": exact_count,
                })
        if progress_callback:
            progress_callback({
                "event": "partial_context_done",
                "target_nodes": len(context.target_nodes),
                "inbound": len(context.inbound_callers),
                "outbound": len(context.outbound_callees),
                "shared": len(context.shared_state_nodes),
                "lifecycle": len(context.lifecycle_pair_nodes),
                "callbacks": len(context.callback_nodes),
                "companions": len(context.companion_nodes),
                "total_selected": len(self._all_context_nodes(context)),
            })

        graph_builder = PartialGraphBuilder()
        partial_graph = graph_builder.build(context, index, self._config.codebase_path)
        context.candidate_paths = graph_builder.candidate_paths(context, partial_graph)
        if progress_callback:
            progress_callback({
                "event": "partial_graph_done",
                "nodes": partial_graph.node_count(),
                "edges": partial_graph.edge_count(),
                "paths": len(context.candidate_paths),
            })

        model = review_model or self._config.llama_query_model
        reviewer = TargetedFileReviewer(
            self._llm_provider, model, self._usage_runtime, self._config.codebase_path,
            cache=cache, symbol_index=index)
        findings = reviewer.review(
            context, partial_graph, detector_result=detector_result,
            max_workers=max_workers, progress_callback=progress_callback)
        raw_findings = len(findings)
        findings = _post_filter_findings(findings, self._config.codebase_path)
        findings, filter_stats = _post_filter_partial_findings(
            findings, rel_target, detector_result, self._config.codebase_path)
        deduped = _dedupe_partial_findings(findings, max_per_sink=max_paths_per_sink)
        if progress_callback:
            progress_callback({
                "event": "partial_review_done",
                "raw_findings": raw_findings,
                "post_filtered_findings": len(findings),
                "deduped_findings": len(deduped),
                "suppressed_null": filter_stats.suppressed_null,
                "suppressed_lock": filter_stats.suppressed_lock,
                "suppressed_generic": filter_stats.suppressed_generic,
                "suppressed_non_target": filter_stats.suppressed_non_target,
            })
        return {
            "file": rel_target,
            "file_path": abs_target,
            "reviews": [self._finding_to_review(f) for f in deduped],
        }

    def _ensure_symbol_index(self, *, progress_callback=None):
        with self._index_lock:
            if self._symbol_index is not None:
                return self._symbol_index
            files = self._c_cpp_files()
            if progress_callback:
                progress_callback({"event": "partial_symbol_index_start", "files": len(files)})
            self._symbol_index = SymbolIndexBuilder().build(files, self._config.codebase_path)
            if progress_callback:
                progress_callback({
                    "event": "partial_symbol_index_done",
                    "files_indexed": self._symbol_index.files_indexed,
                    "definitions": sum(len(v) for v in self._symbol_index.definitions.values()),
                    "callsites": sum(len(v) for v in self._symbol_index.callsites.values()),
                    "fields": len(self._symbol_index.field_uses),
                    "locks": len(self._symbol_index.symbols_by_lock),
                    "state_tokens": len(self._symbol_index.symbols_by_state_token),
                    "event_tokens": len(self._symbol_index.symbols_by_event_token),
                    "globals": len(self._symbol_index.globals),
                })
            return self._symbol_index

    def _extract_target(self, abs_target, rel_target, extraction_model, max_workers, progress_callback, cache):
        if progress_callback:
            progress_callback({"event": "partial_target_extract_start", "file": rel_target})
        try:
            graph = GraphBuilder(
                self._llm_provider, extraction_model, self._usage_runtime
            ).build([abs_target], self._config.codebase_path, max_workers=1)
            nodes = [n for n in graph.nodes.values() if n.file_path.replace("\\", "/") == rel_target]
            globals_ = [g for g in graph.get_globals() if g.file_path.replace("\\", "/") == rel_target]
            for node in nodes:
                node.file_path = node.file_path.replace("\\", "/")
                node.unique_name = f"{node.file_path}::{node.name}"
            for g in globals_:
                g.file_path = g.file_path.replace("\\", "/")
                g.unique_name = f"{g.file_path}::{g.name}"
        except Exception as exc:
            logger.warning("Partial target extraction failed for %s: %s", rel_target, exc)
            nodes, globals_ = [], []
        if not nodes and self._symbol_index is not None:
            defs = _symbols_for_file(self._symbol_index, rel_target)
            nodes = [_symbol_to_node(self._symbol_index, self._config.codebase_path, sym, cache) for sym in defs]
            globals_ = [g for g in self._symbol_index.globals if g.file_path == rel_target]
        if progress_callback:
            progress_callback({
                "event": "partial_target_extract_done",
                "file": rel_target,
                "target_nodes": len(nodes),
                "globals": len(globals_),
            })
        return nodes, globals_

    def _normalize_target_file(self, file_path):
        abs_target = _abs_path(str(file_path), self._config.codebase_path)
        rel_target = _rel_path(abs_target, self._config.codebase_path)
        return abs_target, rel_target

    def _c_cpp_files(self):
        return [
            f for f in self._repository.get_code_files()
            if os.path.splitext(f)[1].lower() in _C_CPP_EXTS
        ]

    def _merge_globals(self, a, b):
        seen = {}
        for g in list(a or []) + list(b or []):
            seen[g.unique_name] = g
        return list(seen.values())

    def _merge_detector_context(self, context: PartialReviewContext, detector_result: PartialDetectorResult):
        if detector_result.globals:
            context.globals = self._merge_globals(context.globals, detector_result.globals)
        if detector_result.nodes:
            context.lifecycle_pair_nodes = self._dedupe_nodes(
                list(context.lifecycle_pair_nodes or []) + list(detector_result.nodes))
        paths = list(context.candidate_paths or [])
        for target in context.target_nodes:
            for node in detector_result.nodes:
                if node.unique_name == target.unique_name:
                    continue
                if node.file_path == context.target_file:
                    continue
                paths.append(ReachabilityPath(
                    target.unique_name, node.unique_name,
                    [target.unique_name, node.unique_name],
                    node.sink_type,
                ))
        context.candidate_paths = _dedupe_paths(paths)

    def _dedupe_nodes(self, nodes: list[FunctionNode]) -> list[FunctionNode]:
        seen, out = set(), []
        for node in nodes:
            if node.unique_name in seen:
                continue
            seen.add(node.unique_name)
            out.append(node)
        return out

    def _all_context_nodes(self, context):
        seen = {}
        for group in (
            context.target_nodes, context.inbound_callers, context.outbound_callees,
            context.shared_state_nodes, context.lifecycle_pair_nodes,
            context.callback_nodes, context.companion_nodes,
        ):
            for node in group:
                seen[node.unique_name] = node
        return list(seen.values())

    def _filter_target_findings(self, findings, target_file):
        result = []
        for finding in findings:
            primary = finding.primary_file or finding.sink_file or finding.source_file
            if primary and _same_file_ref(primary, target_file, self._config.codebase_path):
                result.append(finding)
        return result

    def _finding_to_review(self, finding):
        line_number = int(finding.primary_line or finding.sink_line or finding.source_line or 1)
        vtype = _normalise_partial_vuln_type(finding.vulnerability_type)
        issue = str(finding.description).strip()
        if not issue:
            primary_fn = finding.primary_function or finding.sink_function
            issue = f"{vtype.replace('_', ' ')} in {primary_fn}"
        reasoning_parts = []
        if str(finding.evidence or "").strip():
            reasoning_parts.append(str(finding.evidence).strip())
        if finding.path:
            reasoning_parts.append(f"Reachability path: {' -> '.join(finding.path)}")
        if str(finding.root_cause or "").strip():
            reasoning_parts.append(f"Root cause: {str(finding.root_cause).strip()}")
        if finding.analysis_type:
            reasoning_parts.append(f"Analysis type: {finding.analysis_type}")
        if finding.canonical_key:
            reasoning_parts.append(f"Canonical key: {finding.canonical_key}")
        target_file = finding.primary_file or finding.sink_file or finding.source_file
        code_snippet = ""
        if target_file:
            code_snippet = _read_line_context(self._config.codebase_path, target_file, line_number, context=2)
        return {
            "issue": issue,
            "line_number": line_number,
            "code_snippet": code_snippet,
            "cwe": _partial_cwe(vtype, finding),
            "severity": _severity_title(finding.severity, "Medium"),
            "confidence": _severity_title(finding.confidence, "Medium"),
            "reasoning": "\n".join(reasoning_parts),
            "mitigation": str(finding.root_cause or "").strip(),
        }
