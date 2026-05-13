# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

# ruff: noqa: F401

"""Shared data structures and scanners for partial reachability file review."""

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

from ..reachability_common import (
    Deduplicator,
    FunctionNode,
    GlobalConstruct,
    PathTracer,
    ReachabilityGraph,
    ReachabilityPath,
    VulnerabilityFinding,
    _VULN_TO_CWE,
    _confidence_score,
    _dedupe_paths,
    _mitigation_text,
    _normalise_vuln_type,
    _post_filter_findings,
    _read_function_body,
    _read_line_context,
    _safe_int,
    _same_file_ref,
    _severity_title,
)
from ..repository import EngineRepository
from ..runtime import EngineConfig

logger = logging.getLogger("metis")

_CONTROL_CALLS = frozenset(
    {
        "if",
        "for",
        "while",
        "switch",
        "return",
        "sizeof",
        "alignof",
        "_Generic",
        "case",
        "do",
        "else",
        "typedef",
        "defined",
    }
)
_COMMON_LIBC_CALLS = frozenset(
    {
        "malloc",
        "calloc",
        "realloc",
        "free",
        "memcpy",
        "memmove",
        "memset",
        "strcpy",
        "strncpy",
        "strcat",
        "snprintf",
        "sprintf",
        "printf",
        "fprintf",
        "vfprintf",
        "fopen",
        "open",
        "close",
        "read",
        "write",
        "stat",
        "lstat",
        "access",
        "system",
        "popen",
    }
)
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
_LIFECYCLE_WORDS = frozenset(
    {
        "create",
        "destroy",
        "alloc",
        "free",
        "init",
        "term",
        "setup",
        "cleanup",
        "open",
        "release",
        "close",
        "flush",
        "get",
        "put",
        "ref",
        "unref",
        "map",
        "unmap",
        "load",
        "unload",
        "reload",
        "enable",
        "disable",
        "start",
        "stop",
        "register",
        "unregister",
        "add",
        "remove",
        "insert",
        "erase",
        "grow",
        "shrink",
        "suspend",
        "resume",
        "schedule",
        "cancel",
        "arm",
        "disarm",
    }
)
_CALLBACK_WORDS = frozenset(
    {
        "callback",
        "cb",
        "timer",
        "work",
        "worker",
        "watchdog",
        "fops",
        "ops",
        "file_operations",
        "fn",
        "poll",
        "ioctl",
        "flush",
        "release",
    }
)
_IMPORTANT_FIELDS = frozenset(
    {
        "nr_pages",
        "pages",
        "alias_count",
        "gpu_mappings",
        "gpu_mappings_total",
        "ctx_count",
        "regions",
        "active",
        "ready",
        "state",
        "flags",
        "refcount",
        "data",
        "len",
        "size",
        "raw_len",
        "data_len",
        "enabled",
        "loaded",
        "initialized",
        "powered",
        "phys_addr",
        "fault_addr",
        "permission",
    }
)
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
    "fd_reuse_race, debugfs_permission, "
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
_ERROR_PATH_RE = re.compile(
    r"\b(?:return\s+(?:-\d+|NULL|nullptr)|goto\s+(?:err|fail|out|cleanup)\w*)\b",
    re.IGNORECASE,
)
_PUBLISH_CALL_RE = re.compile(
    r"\b(?:rb_link_node|list_add|hash_add|insert|register|publish|xarray_insert|"
    r"xa_insert|idr_alloc|id_alloc|add)\s*\(",
    re.IGNORECASE,
)
_ROLLBACK_CALL_RE = re.compile(
    r"\b(?:rb_erase|list_del|hash_del|unregister|remove|erase|delete|del)\s*\(",
    re.IGNORECASE,
)
_ALLOC_ARITH_RE = re.compile(
    r"\b(?:malloc|kmalloc|realloc|krealloc|calloc|kcalloc|vzalloc|kvcalloc)\s*\([^;\n]*"
    r"(?:\*|sizeof)\s*[^;\n]*\)|\b[A-Za-z_][A-Za-z0-9_]*(?:count|cap|num|nr|n|len|size)[A-Za-z0-9_]*\s*\*\s*sizeof\s*\(",
    re.IGNORECASE,
)
_OVERFLOW_GUARD_RE = re.compile(
    r"\b(?:SIZE_MAX|__builtin_mul_overflow|check_mul_overflow|array_size|struct_size|kmalloc_array|kcalloc|kvcalloc)\b|/\s*sizeof\s*\(",
    re.IGNORECASE,
)
_LOG_CALL_RE = re.compile(
    r"\b(?:fprintf|printf|snprintf|sprintf|vfprintf|util_log|debug_log|trace|printk|"
    r"dev_info|dev_warn|dev_err|gpu_debug_log|gpu_debug)\s*\(",
    re.IGNORECASE,
)
_SENSITIVE_TOKEN_RE = re.compile(
    r"\b(?:phys|phys_addr|paddr|dma|addr|fault_addr|pointer|token|key|secret)\b",
    re.IGNORECASE,
)
_SENSITIVE_FORMAT_RE = re.compile(r"%(?:0?\d+)?(?:llx|lx|p|x)", re.IGNORECASE)
_VARIADIC_WRAPPER_RE = re.compile(
    r"\b(?:vfprintf|vprintf|vsprintf|vsnprintf|printf|fprintf|sprintf|snprintf)\s*\(",
    re.IGNORECASE,
)
_LOCK_CALL_RE = re.compile(
    r"\b(?P<fn>pthread_mutex_lock|pthread_mutex_unlock|mutex_lock|mutex_unlock|"
    r"spin_lock(?:_irqsave|_irq)?|spin_unlock(?:_irqrestore|_irq)?)\s*\(\s*(?P<arg>[^,\)]+)",
    re.IGNORECASE,
)
_UNLOCK_WORD_RE = re.compile(r"unlock", re.IGNORECASE)
_ASSIGN_FROM_FIELD_RE = re.compile(
    r"\b(?P<var>(?:cached|saved|old|tmp)[A-Za-z0-9_]*)\s*=\s*[^;\n]*(?:->|\.)[A-Za-z_][A-Za-z0-9_]*"
)
_DISABLE_NAME_RE = re.compile(
    r"(?:disable|stop|clear|term|shutdown|release)", re.IGNORECASE
)
_DISABLE_STATE_RE = re.compile(
    r"\b(?:enabled|active|powered|ready|pending|state)\s*=\s*(?:0|false|FALSE|[A-Z0-9_]*(?:OFF|DISABLED|IDLE)[A-Z0-9_]*)",
    re.IGNORECASE,
)
_CALLBACK_STORE_RE = re.compile(
    r"(?:callback|work|timer|watchdog)\s*(?:->|\.)\s*(?:data|ctx|fn)\s*=|"
    r"(?:queue|alias|ctx|grp|obj|task|session)\s*(?:->|\.)\s*(?:ctx|pages|data|callback|work|timer)\s*=",
    re.IGNORECASE,
)
_CANCEL_OR_REF_RE = re.compile(
    r"\b(?:cancel|flush|drain|unregister|del_timer|destroy_workqueue|refcount|kref|get|put|pin|unpin|clear|NULL)\b",
    re.IGNORECASE,
)
_PROTOCOL_TOKEN_WORDS = frozenset(
    {
        "protected",
        "protm",
        "active",
        "enable",
        "enabled",
        "disable",
        "disabled",
        "enter",
        "entered",
        "exit",
        "ack",
        "wait",
        "flush",
        "ready",
        "pending",
        "state",
        "resume",
        "suspend",
        "start",
        "stop",
        "mmu",
        "scheduler",
        "sched",
        "firmware",
        "fw",
        "hwcnt",
        "counter",
        "clock",
        "clk",
        "power",
        "reset",
        "doorbell",
        "gpu",
        "fault",
        "irq",
        "interrupt",
        "completion",
        "event",
        "fence",
        "serialize",
        "serialise",
        "sync",
        "transition",
    }
)
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
_STATE_VERIFY_TOKENS = frozenset(
    {"active", "protected", "protm", "ready", "state", "enter", "enable"}
)
_TRANSITION_TOKENS = frozenset(
    {
        "protected",
        "protm",
        "active",
        "enable",
        "disable",
        "enter",
        "exit",
        "ready",
        "pending",
        "state",
        "resume",
        "suspend",
        "start",
        "stop",
    }
)
_SUBSYSTEM_TOKENS = frozenset(
    {
        "mmu",
        "scheduler",
        "firmware",
        "hwcnt",
        "counter",
        "clock",
        "power",
        "doorbell",
        "gpu",
        "irq",
        "interrupt",
    }
)
_NOTIFIER_WORDS = frozenset(
    {
        "notifier",
        "notify",
        "notification",
        "event",
        "completion",
        "wait",
        "ack",
        "irq",
        "interrupt",
        "workqueue",
        "work",
        "callback",
    }
)
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
_COPY_CONTRACT_APIS = frozenset(
    {
        "memcpy",
        "memmove",
        "copy_to_user",
        "copy_from_user",
        "copy_in_user",
        "read",
        "write",
        "kernel_read",
        "kernel_write",
        "simple_read_from_buffer",
        "simple_write_to_buffer",
    }
)
_COPY_API_RE = re.compile(
    r"\b(?:memcpy|memmove|copy_to_user|copy_from_user|copy_in_user|read|write|"
    r"kernel_read|kernel_write|simple_read_from_buffer|simple_write_to_buffer)\s*\(",
    re.IGNORECASE,
)
_COUNT_SIZE_WORDS = frozenset(
    {
        "count",
        "len",
        "length",
        "size",
        "bytes",
        "nbytes",
        "nr",
        "num",
        "nents",
        "stride",
        "pages",
        "page_count",
        "groups",
        "offset",
    }
)
_RESOURCE_WORDS = frozenset(
    {
        "doorbell",
        "mapping",
        "mappings",
        "map",
        "pages",
        "page",
        "token",
        "ctx",
        "context",
        "session",
        "queue",
        "alias",
        "region",
        "gpu_va",
        "same_va",
        "imported",
        "dma_buf",
        "exporter",
        "pfn",
        "mmu",
        "protected",
        "protm",
    }
)
_POLICY_GUARD_WORDS = frozenset(
    {
        "imported",
        "same_va",
        "protected",
        "protm",
        "permission",
        "permissions",
        "owner",
        "owned",
        "capable",
        "access",
        "allowed",
        "trusted",
        "exporter",
        "importer",
        "dma_buf",
        "privileged",
        "user",
        "readonly",
        "writable",
    }
)
_POLICY_SINK_APIS = frozenset(
    {
        "mmap",
        "vm_fault",
        "remap_pfn_range",
        "vm_insert_pfn",
        "vmf_insert_pfn",
        "vm_insert_page",
        "copy_to_user",
        "copy_from_user",
        "dma_buf_mmap",
        "dma_buf_map_attachment",
        "dma_buf_begin_cpu_access",
        "kbase_gpu_mmap",
        "insert_pfn",
        "io_remap_pfn_range",
        "map",
        "import",
        "export",
    }
)
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
_NULL_CLEAR_RE = re.compile(r"\b(?:NULL|nullptr|0|false|FALSE|INVALID|invalid)\b")
_QUEUE_LIVENESS_WORDS = frozenset(
    {
        "enabled",
        "enable",
        "alive",
        "terminated",
        "terminating",
        "active",
        "drain_queue",
        "drain",
        "suspend",
        "suspended",
        "group_suspend",
        "stopped",
    }
)
_TRACKER_WORDS = frozenset(
    {
        "tracker",
        "tracking",
        "rbtree",
        "rb",
        "tree",
        "list",
        "node",
        "start_pfn",
        "inserted",
    }
)
_PM_WORDS = frozenset(
    {"pm", "runtime", "power", "clock", "clk", "regulator", "register", "gpu_power"}
)
_SLOT_WORDS = frozenset(
    {"slot", "slots", "atom", "atoms", "prio", "priority", "job", "jobs"}
)
_SUSPEND_WORDS = frozenset(
    {
        "suspend",
        "suspended",
        "sus",
        "buf",
        "buffer",
        "pages",
        "nr_pages",
        "normal",
        "group",
        "queue",
        "drain",
        "wait",
        "cqs",
        "same_va",
    }
)
_MAPPING_POLICY_WORDS = frozenset(
    {
        "imported",
        "same_va",
        "dma_buf",
        "umm",
        "protected",
        "native",
        "vmap",
        "vmap_prot",
        "mmap",
        "fault",
        "pfn",
        "softjob",
        "kcpu",
    }
)
_METADATA_SOURCE_RE = re.compile(
    r"\b(?:page_private|folio_get_private|private|metadata|opaque|pfn|phys|addr)\b",
    re.IGNORECASE,
)
_STRUCT_CAST_RE = re.compile(
    r"(?P<target>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"\((?P<type>(?:const\s+)?struct\s+[A-Za-z_][A-Za-z0-9_]*\s*\*)\)\s*(?P<src>[^;]+)"
)
_SENTINEL_COMPARE_RE = re.compile(
    r"\b(?P<expr>(?:[A-Za-z_][A-Za-z0-9_]*\s*\([^;\n]*?\)|"
    r"[A-Za-z_][A-Za-z0-9_]*(?:(?:->|\.)[A-Za-z_][A-Za-z0-9_]*)?))\s*"
    r"(?P<op>==|!=)\s*(?P<value>0|NULL|nullptr)\b"
)
_PAGE_ROUND_RE = re.compile(
    r"\b(?:PFN_UP|PFN_DOWN|DIV_ROUND_UP|PAGE_ALIGN|round_up|round_down)\s*\(",
    re.IGNORECASE,
)
_PM_RUNTIME_API_RE = re.compile(
    r"\b(?:pm_runtime_get_sync|pm_runtime_resume_and_get|pm_runtime_get_if_in_use|pm_runtime_get)\s*\(",
    re.IGNORECASE,
)
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
_PROTECTED_ACTIVE_RE = re.compile(
    r"\b(?:protected|protm)[A-Za-z0-9_]*(?:->|\.)?(?:active|entered|enabled|state)\b",
    re.IGNORECASE,
)
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
_USER_BUFFER_RE = re.compile(
    r"\b(?:USER_BUFFER|user_buffer|from_user_buffer|KBASE_MEM_TYPE_IMPORTED_USER_BUF)\b",
    re.IGNORECASE,
)
_GUP_RE = re.compile(
    r"\b(?:get_user_pages|pin_user_pages|get_user_pages_fast|pin_user_pages_fast)\w*\s*\(",
    re.IGNORECASE,
)
_GPU_WRITE_FLAG_RE = re.compile(
    r"\b(?:KBASE_REG_GPU_WR|GPU_WR|GPU.*WRITE|gpu_wr|gpu_write|KBASE_REG_CPU_WR|CPU_WR)\b",
    re.IGNORECASE,
)
_ZONE_SHRINK_RE = re.compile(
    r"\b(?:init_(?:jit|exec)|region_tracker_init|shrink|split|resize|trim|zone|free.*zone|"
    r"same_va|imported|dma_buf|user_buffer|overlap)\b",
    re.IGNORECASE,
)
_SUCCESS_FD_RE = re.compile(
    r"\b(?:anon_inode_getfd|get_unused_fd_flags|fd_install|sync_fence_fdget|fdget)\s*\(",
    re.IGNORECASE,
)
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
_DOMAIN_ROOT_TOKENS = frozenset(
    {
        "doorbell",
        "queue",
        "fault",
        "irq",
        "interrupt",
        "slot",
        "atom",
        "pm",
        "runtime",
        "power",
        "clock",
        "clk",
        "same_va",
        "imported",
        "umm",
        "dma_buf",
        "protected",
        "protm",
        "mmu",
        "page_private",
        "start_pfn",
        "tracker",
        "hwaccess",
        "hwcnt",
        "backend",
        "suspend",
        "drain_queue",
        "group_suspend",
        "cqs_wait",
        "alias",
        "nents",
        "stride",
        "pfn",
        "phys",
        "dma",
        "sus_buf",
        "normal_suspend_buf",
        "clear_fault",
        "native",
        "vmap_prot",
        "active_protm_grp",
        "zero_count",
        "user_buffer",
        "zone",
        "jit",
        "mem_pool",
        "oom",
        "fd",
        "debugfs",
        "tlstream",
        "bus_fault",
        "kcpu_queue",
    }
)
_MMU_RECOVERY_LOOP_RE = re.compile(
    r"\b(?:for|while)\s*\([^)]*(?:i|idx|page|count|nr|remain)[^)]*(?:<|>|<=|>=|--|\+\+)",
    re.IGNORECASE,
)
_MMU_RECOVERY_ACTION_RE = re.compile(
    r"\b(?:unmap|zap|clear|write|free|put|rollback|recover|pte|pgd|pfn|phys)\w*\s*\(",
    re.IGNORECASE,
)
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
    "partial_owner_liveness_allocation": 30,
    "partial_user_buffer_permission": 31,
    "partial_zone_shrink_validation": 32,
    "partial_success_path_cleanup": 33,
    "partial_jit_lock_protocol": 34,
    "partial_teardown_order": 35,
    "partial_queue_publish_init": 36,
    "partial_fd_reuse_race": 37,
    "partial_debugfs_permission": 38,
    "partial_allocation_arithmetic": 39,
    "partial_fops_lifecycle": 40,
    "partial_cross_file_lock_cycle": 41,
    "partial_state_transition_protocol": 42,
    "partial_partial_exact_fallback": 43,
    "partial_lock_and_stale": 44,
    "partial_lifecycle": 45,
    "partial_shared_state": 46,
    "partial_inbound_contract": 47,
    "partial_outbound_misuse": 48,
    "partial_target_intra": 49,
    "partial_concurrency": 50,
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
    """Repository-level symbol index used to select context around one file."""

    definitions: dict[str, list[SymbolDef]]
    callsites: dict[str, list[CallSite]]
    field_uses: dict[str, list[FieldUse]]
    globals: list[GlobalConstruct]
    files_indexed: int = 0
    defs_by_file: dict[str, list[SymbolDef]] = field(default_factory=dict)
    defs_by_file_and_name: dict[tuple[str, str], SymbolDef] = field(
        default_factory=dict
    )
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
    sentinel_facts_by_symbol: dict[str, list[SentinelFact]] = field(
        default_factory=dict
    )
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
    """Bounded context package passed from selection into LLM review passes."""

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
    """Static detector notes that steer targeted partial-review prompts."""

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
    nodes: list[FunctionNode] = None
    globals: list[GlobalConstruct] = None

    def __post_init__(self):
        for name in (
            "state_publication_notes",
            "publish_rollback_notes",
            "allocation_arithmetic_notes",
            "format_notes",
            "info_leak_notes",
            "fops_notes",
            "lock_order_notes",
            "stale_after_unlock_notes",
            "disable_stale_notes",
            "callback_lifetime_notes",
            "cross_file_lock_notes",
            "protocol_notes",
            "copy_contract_notes",
            "cleanup_symmetry_notes",
            "accounting_drift_notes",
            "arithmetic_chain_notes",
            "resource_binding_notes",
            "policy_gate_notes",
            "resource_validation_notes",
            "cleanup_ledger_notes",
            "async_order_notes",
            "size_propagation_notes",
            "stale_tracker_notes",
            "metadata_type_confusion_notes",
            "pm_sequence_notes",
            "secondary_omission_notes",
            "protected_mmu_notes",
            "mmu_recovery_notes",
            "sentinel_misuse_notes",
            "suspend_cleanup_ledger_notes",
            "suspend_size_sink_notes",
            "fault_clear_order_notes",
            "pm_callback_order_notes",
            "region_replace_erase_notes",
            "imported_mapping_policy_notes",
            "alias_extent_mismatch_notes",
            "named_lock_inversion_notes",
            "active_singleton_stale_notes",
            "zero_count_underflow_notes",
            "owner_liveness_notes",
            "user_buffer_permission_notes",
            "zone_shrink_notes",
            "success_path_cleanup_notes",
            "jit_lock_protocol_notes",
            "teardown_order_notes",
            "queue_publish_init_notes",
            "fd_reuse_notes",
            "debugfs_permission_notes",
            "nodes",
            "globals",
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
    return {_canonical_protocol_token(t) for t in _tokens(text) if len(t) > 1}


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
    text = re.sub(
        r"\b(?:pfn_up|pfn_down|div_round_up|page_align|round_up|round_down)\s*\(",
        "round(",
        text,
    )
    text = re.sub(r"\bpage_shift\b", "page_shift", text)
    text = re.sub(r"0x[0-9a-f]+|\b\d+\b", "num", text)
    text = text.replace("->", ".")
    text = re.sub(r"\s+", "", text)
    return text[:180]


def _function_body_from_symbol(
    codebase_path: str, sym: SymbolDef, max_chars: int = 5000
) -> str:
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
        "hwaccess_lock",
        "scheduler_lock",
        "clk_rtm.lock",
        "hwcnt.lock",
        "backend.lock",
        "state_lock",
        "state.lock",
        "ctx.lock",
        "queue.lock",
        "pm.lock",
        "mmu.lock",
        "mmu_hw_mutex",
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
        t
        for t in re.split(r"[^a-z0-9]+", str(text or "").lower())
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
    if (
        "active" in tokens
        and ("protm" in tokens or "protected" in tokens)
        and ("grp" in tokens or "group" in tokens)
    ):
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
            return [
                (start + offset + 1, line)
                for offset, line in enumerate(lines[start:end])
            ]
        body = self.symbol_body(sym, max_chars=12000, numbered=False)
        return [
            (sym.line_number + offset, line)
            for offset, line in enumerate(body.splitlines())
        ]

    def symbol_body(
        self, sym: SymbolDef, max_chars: int | None = None, *, numbered: bool = False
    ) -> str:
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

    def symbol_for_node(
        self, index: SymbolIndex | None, node: FunctionNode
    ) -> SymbolDef | None:
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

    def node_for_symbol(
        self, index: SymbolIndex | None, sym: SymbolDef
    ) -> FunctionNode:
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
            is_sink = bool(
                _SINK_KIND_RE.search(match_text) or _SECURITY_API_RE.search(match_text)
            )
            sink_type = _sink_type_for_text(match_text) if is_sink else ""
        node = FunctionNode(
            unique_name=unique,
            file_path=sym.file_path,
            name=sym.name,
            line_number=sym.line_number,
            is_source=is_source,
            is_sink=is_sink,
            calls=calls,
            source_reason=(
                "deterministic source-like entry or external input use"
                if is_source
                else ""
            ),
            sink_type=sink_type,
            sink_reason=(
                "deterministic sink-like API/state/lifecycle use" if is_sink else ""
            ),
        )
        with self._lock:
            return self._node_by_symbol.setdefault(unique, node)

    def _normalise_rel(self, rel_file: str) -> str:
        rel = str(rel_file or "").replace("\\", "/")
        if os.path.isabs(rel):
            return _rel_path(rel, self._cb)
        return rel


class SymbolIndexBuilder:
    """Build a coarse C-family symbol index without requiring a full graph."""

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
                calls = self._extract_function_uses(
                    body_lines, sym, callsites, field_uses, field_uses_by_file
                )
                caller_key = (sym.file_path, sym.name)
                calls_by_caller[caller_key] = list(
                    dict.fromkeys(calls_by_caller.get(caller_key, []) + calls)
                )
                locks, lock_edges, state_tokens = (
                    self._symbol_lock_and_protocol_metadata(sym, body_lines)
                )
                unique = _symbol_unique_name(sym)
                locks_by_symbol[unique] = locks
                lock_edges_by_symbol[unique] = lock_edges
                state_tokens_by_symbol[unique] = state_tokens
                for lock in locks:
                    symbols_by_lock[lock].append(sym)
                for token in state_tokens:
                    symbols_by_state_token[token].append(sym)
                (
                    copy_uses,
                    guards,
                    assignments,
                    cleanup_facts,
                    sinks,
                    event_facts,
                    formula_facts,
                    cast_facts,
                    sentinel_facts,
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
            defs.append(
                SymbolDef(
                    name=name,
                    file_path=rel_file,
                    line_number=line,
                    signature=signature,
                    body_start=line,
                    body_end=end_line,
                )
            )
        return defs

    def _extract_function_uses(
        self, lines, sym, callsites, field_uses, field_uses_by_file
    ):
        calls = []
        for offset, line_text in enumerate(lines):
            line_number = sym.body_start + offset
            for call in _CALL_RE.findall(line_text):
                if call in _CONTROL_CALLS:
                    continue
                if line_number == sym.body_start and call == sym.name:
                    continue
                calls.append(call)
                callsites[call].append(
                    CallSite(
                        caller_name=sym.name,
                        caller_file=sym.file_path,
                        caller_line=sym.line_number,
                        callee_name=call,
                        line_number=line_number,
                        line_text=line_text.strip(),
                    )
                )
            for field_name in _FIELD_RE.findall(line_text):
                use = FieldUse(
                    field=field_name,
                    file_path=sym.file_path,
                    function_name=sym.name,
                    line_number=line_number,
                    line_text=line_text.strip(),
                )
                field_uses[field_name].append(use)
                field_uses_by_file[sym.file_path].append(use)
        return list(dict.fromkeys(calls))

    def _symbol_lock_and_protocol_metadata(
        self, sym: SymbolDef, lines: list[str]
    ) -> tuple[list[str], list[LockOrderEdge], list[str]]:
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
                    edges.append(
                        LockOrderEdge(
                            first_lock=prior,
                            second_lock=lock,
                            file_path=sym.file_path,
                            function_name=sym.name,
                            line_number=line_number,
                            line_text=line_text.strip(),
                        )
                    )
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
        list[CopyUse],
        list[GuardFact],
        list[AssignmentFact],
        list[CleanupFact],
        list[SinkFact],
        list[EventFact],
        list[FormulaFact],
        list[CastFact],
        list[SentinelFact],
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
                cleanup_facts.append(
                    CleanupFact(
                        action="exit",
                        kind="exit",
                        resource="return" if "return" in lower else "goto",
                        line_number=line_number,
                        line_text=stripped,
                    )
                )
        return (
            copy_uses,
            guards,
            assignments,
            cleanup_facts,
            sinks,
            event_facts,
            formula_facts,
            cast_facts,
            sentinel_facts,
        )

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
            uses.append(
                CopyUse(
                    api=api_l,
                    line_number=line_number,
                    dst_expr=_short_expr(dst),
                    src_expr=_short_expr(src),
                    size_expr=_short_expr(size),
                    line_text=line,
                )
            )
        return uses

    def _guards_from_line(self, line: str, line_number: int) -> list[GuardFact]:
        guards = []
        for match in _GUARD_COMPARE_RE.finditer(line):
            lhs = _short_expr(match.group("lhs"))
            rhs = _short_expr(match.group("rhs"))
            op = match.group("op")
            tokens = _fact_tokens(f"{lhs} {rhs}")
            interesting = tokens & (
                _COUNT_SIZE_WORDS
                | _RESOURCE_WORDS
                | _POLICY_GUARD_WORDS
                | _PROTOCOL_TOKEN_WORDS
            )
            for token in sorted(interesting):
                guards.append(
                    GuardFact(
                        token=token,
                        lhs=lhs,
                        op=op,
                        rhs=rhs,
                        line_number=line_number,
                        line_text=line,
                    )
                )
        return guards

    def _assignments_from_line(
        self, line: str, line_number: int
    ) -> list[AssignmentFact]:
        facts = []
        for match in _ASSIGN_FACT_RE.finditer(line):
            lhs = _short_expr(match.group("lhs"))
            rhs = _short_expr(match.group("rhs"))
            tokens = tuple(
                sorted(
                    _fact_tokens(f"{lhs} {rhs}")
                    & (
                        _COUNT_SIZE_WORDS
                        | _RESOURCE_WORDS
                        | _PROTOCOL_TOKEN_WORDS
                        | _POLICY_GUARD_WORDS
                    )
                )
            )
            if not tokens and not _ARITH_EXPR_RE.search(rhs):
                continue
            facts.append(
                AssignmentFact(
                    target=lhs,
                    value=rhs,
                    tokens=tokens,
                    line_number=line_number,
                    line_text=line,
                    is_field=("->" in lhs or "." in lhs),
                    is_arithmetic=bool(_ARITH_EXPR_RE.search(rhs)),
                )
            )
        for match in _UPDATE_FACT_RE.finditer(line):
            target = _short_expr(match.group("target"))
            op = match.group("op")
            tokens = tuple(
                sorted(
                    _fact_tokens(target)
                    & (_COUNT_SIZE_WORDS | _RESOURCE_WORDS | _PROTOCOL_TOKEN_WORDS)
                )
            )
            if not tokens:
                continue
            facts.append(
                AssignmentFact(
                    target=target,
                    value=op,
                    tokens=tokens,
                    line_number=line_number,
                    line_text=line,
                    is_field=("->" in target or "." in target),
                    is_arithmetic=False,
                )
            )
        return facts

    def _cleanup_facts_from_line(
        self, line: str, line_number: int
    ) -> list[CleanupFact]:
        facts = []
        for api in _CALL_RE.findall(line):
            api_l = api.lower()
            args = _first_call_args(line, api)
            resource = _short_expr(args[0] if args else "")
            action, kind = self._cleanup_action(api_l)
            if action:
                facts.append(
                    CleanupFact(
                        action=action,
                        kind=kind,
                        resource=resource or api_l,
                        line_number=line_number,
                        line_text=line,
                    )
                )
        for match in _UPDATE_FACT_RE.finditer(line):
            op = match.group("op")
            target = _short_expr(match.group("target"))
            tokens = _fact_tokens(target)
            if not tokens & (
                _COUNT_SIZE_WORDS | {"refcount", "mappings", "pages", "groups"}
            ):
                continue
            facts.append(
                CleanupFact(
                    action="inc" if op in {"++", "+="} else "dec",
                    kind="acquire" if op in {"++", "+="} else "release",
                    resource=target,
                    line_number=line_number,
                    line_text=line,
                )
            )
        return facts

    def _cleanup_action(self, api: str) -> tuple[str, str]:
        if re.search(
            r"(?:alloc|malloc|calloc|get|map|register|list_add|hash_add|insert|link_node|idr_alloc|xa_insert|enable)",
            api,
        ):
            if re.search(
                r"(?:free|unmap|unregister|remove|erase|delete|del|disable)", api
            ):
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
            if (
                "insert" in api
                or "add" in api
                or "link_node" in api
                or "idr_alloc" in api
            ):
                return "insert", "acquire"
            return "alloc", "acquire"
        if re.search(
            r"(?:free|put|unmap|unregister|list_del|hash_del|erase|remove|delete|del|idr_remove|xa_erase|disable)",
            api,
        ):
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
            if api_l not in _POLICY_SINK_APIS and not any(
                token in api_l for token in _POLICY_SINK_APIS
            ):
                continue
            tokens = _fact_tokens(f"{api_l} {line}") & (
                _POLICY_GUARD_WORDS | _RESOURCE_WORDS | _PROTOCOL_TOKEN_WORDS
            )
            token = sorted(tokens)[0] if tokens else api_l
            facts.append(
                SinkFact(
                    api=api_l, token=token, line_number=line_number, line_text=line
                )
            )
        return facts

    def _event_facts_from_line(self, line: str, line_number: int) -> list[EventFact]:
        facts: list[EventFact] = []
        lower = line.lower()
        tokens = _fact_tokens(line)
        resource_tokens = sorted(
            tokens
            & (
                _RESOURCE_WORDS
                | _QUEUE_LIVENESS_WORDS
                | _TRACKER_WORDS
                | _PM_WORDS
                | _SLOT_WORDS
            )
        )

        if (
            re.search(r"\bif\s*\(|\bWARN_ON\b|\bBUG_ON\b|\breturn\s+-", line)
            and resource_tokens
        ):
            for token in resource_tokens[:4]:
                facts.append(EventFact("validation", token, line_number, line, "guard"))

        if tokens & _RESOURCE_WORDS:
            if _ASSIGN_FACT_RE.search(line) and not _NULL_CLEAR_RE.search(line):
                for token in sorted(tokens & _RESOURCE_WORDS)[:4]:
                    facts.append(
                        EventFact(
                            "resource_bind", token, line_number, line, "assignment"
                        )
                    )
            if _NULL_CLEAR_RE.search(line) or re.search(
                r"\b(?:clear|reset|invalidate|unmap|unbind)\w*\s*\(", lower
            ):
                for token in sorted(tokens & _RESOURCE_WORDS)[:4]:
                    facts.append(
                        EventFact("resource_clear", token, line_number, line, "clear")
                    )

        if _ASYNC_SCHEDULE_RE.search(line) and tokens & {
            "fault",
            "irq",
            "interrupt",
            "event",
            "work",
            "worker",
        }:
            token = sorted(
                tokens & {"fault", "irq", "interrupt", "event", "work", "worker"}
            )[0]
            facts.append(
                EventFact("async_schedule", token, line_number, line, "schedule")
            )
        if _ASYNC_CLEAR_RE.search(line) and tokens & {
            "fault",
            "irq",
            "interrupt",
            "event",
            "state",
        }:
            token = sorted(tokens & {"fault", "irq", "interrupt", "event", "state"})[0]
            facts.append(EventFact("async_clear", token, line_number, line, "clear"))
        if _FAULT_CLEAR_RE.search(line):
            facts.append(
                EventFact("fault_clear", "fault", line_number, line, "clear_fault")
            )

        if _SUSPEND_SOURCE_RE.search(line):
            for token in sorted(tokens & (_SUSPEND_WORDS | {"size", "pages", "nr"}))[
                :4
            ]:
                facts.append(
                    EventFact("suspend_resource", token, line_number, line, "suspend")
                )

        if _PM_RUNTIME_API_RE.search(line):
            facts.append(
                EventFact("pm_runtime_get", "pm", line_number, line, "runtime")
            )
        if _PM_SENSITIVE_API_RE.search(line):
            token = (
                "register"
                if re.search(r"\b(?:readl|writel|regmap_|kbase_reg_)", lower)
                else "power"
            )
            facts.append(
                EventFact(
                    "pm_sensitive_action", token, line_number, line, "pm_sensitive"
                )
            )
        if re.search(
            r"\b(?:pm_runtime_put|pm_runtime_put_sync|disable_gpu_power_control|clk_disable|regulator_disable)\w*\s*\(",
            lower,
        ):
            facts.append(
                EventFact("pm_runtime_put", "pm", line_number, line, "runtime")
            )

        if tokens & _TRACKER_WORDS:
            if re.search(
                r"\b(?:rb_erase|list_del|delete|remove|erase|del)\w*\s*\(", lower
            ):
                facts.append(
                    EventFact(
                        "tracker_remove",
                        sorted(tokens & _TRACKER_WORDS)[0],
                        line_number,
                        line,
                        "remove",
                    )
                )
            if _NULL_CLEAR_RE.search(line) or re.search(
                r"\b(?:invalid|clear|reset)\b", lower
            ):
                facts.append(
                    EventFact(
                        "tracker_invalidate",
                        sorted(tokens & _TRACKER_WORDS)[0],
                        line_number,
                        line,
                        "invalidate",
                    )
                )

        if tokens & _SLOT_WORDS:
            if re.search(
                r"\[\s*0\s*\]|\bfirst\b|\bslot0\b|\bslot\s*=\s*0\b|\bkatom\b", lower
            ):
                facts.append(
                    EventFact("slot_first", "slot", line_number, line, "first")
                )
            if re.search(
                r"\[\s*1\s*\]|\bsecond\b|\bslot1\b|\bslot\s*\+\s*1\b|\bnext\b|\bother\b|\bpair",
                lower,
            ):
                facts.append(
                    EventFact("slot_second", "slot", line_number, line, "second")
                )
            if re.search(r"\b(?:return|continue|break|goto)\b", lower) and (
                {"prio", "priority"} & tokens
                or re.search(r"!\s*katom|reset|stop|different", lower)
            ):
                facts.append(
                    EventFact("slot_skip", "slot", line_number, line, "priority_skip")
                )

        if {"protected", "protm"} & tokens:
            if tokens & _WAIT_ACK_TOKENS:
                facts.append(
                    EventFact("protected_wait", "protected", line_number, line, "wait")
                )
            if _PROTECTED_ACTIVE_RE.search(line) or re.search(
                r"\b(?:active|entered|enabled)\b", lower
            ):
                facts.append(
                    EventFact(
                        "protected_verify", "protected", line_number, line, "verify"
                    )
                )
        if "mmu" in tokens and _LOCK_CALL_RE.search(line):
            facts.append(EventFact("mmu_lock", "mmu", line_number, line, "lock"))
        if _ACTIVE_SINGLETON_RE.search(line):
            facts.append(
                EventFact(
                    "active_singleton",
                    "active_protm_grp",
                    line_number,
                    line,
                    "active_singleton",
                )
            )

        return facts

    def _formula_facts_from_line(
        self, line: str, line_number: int
    ) -> list[FormulaFact]:
        facts = []
        for match in _ASSIGN_FACT_RE.finditer(line):
            lhs = _short_expr(match.group("lhs"))
            rhs = _short_expr(match.group("rhs"), limit=160)
            operators = _formula_operators(rhs)
            if not operators:
                continue
            tokens = tuple(
                sorted(
                    _fact_tokens(f"{lhs} {rhs}")
                    & (_COUNT_SIZE_WORDS | _RESOURCE_WORDS | _PROTOCOL_TOKEN_WORDS)
                )
            )
            facts.append(
                FormulaFact(
                    target=lhs,
                    expr=rhs,
                    normalized=_normalise_formula_expr(rhs),
                    tokens=tokens,
                    operators=operators,
                    line_number=line_number,
                    line_text=line,
                )
            )
        return facts

    def _cast_facts_from_line(self, line: str, line_number: int) -> list[CastFact]:
        facts = []
        for match in _STRUCT_CAST_RE.finditer(line):
            src = _short_expr(match.group("src"), limit=160)
            if not _METADATA_SOURCE_RE.search(src):
                continue
            facts.append(
                CastFact(
                    target=match.group("target"),
                    target_type=" ".join(match.group("type").split()),
                    source=src,
                    line_number=line_number,
                    line_text=line,
                )
            )
        if "container_of" in line and _METADATA_SOURCE_RE.search(line):
            args = _first_call_args(line, "container_of")
            if len(args) >= 2:
                target = re.split(r"\s*=\s*", line, maxsplit=1)[0].strip().split()[-1]
                facts.append(
                    CastFact(
                        target=target,
                        target_type=_short_expr(args[1]),
                        source=_short_expr(args[0], limit=160),
                        line_number=line_number,
                        line_text=line,
                    )
                )
        return facts

    def _sentinel_facts_from_line(
        self, line: str, line_number: int
    ) -> list[SentinelFact]:
        facts = []
        tokens = _fact_tokens(line)
        if not tokens & {"phys", "phys_addr", "pfn", "addr", "address", "dma", "pa"}:
            return facts
        for match in _SENTINEL_COMPARE_RE.finditer(line):
            expr = _short_expr(match.group("expr"))
            expr_tokens = _fact_tokens(expr)
            token = sorted(
                (expr_tokens | tokens)
                & {"phys", "phys_addr", "pfn", "addr", "address", "dma", "pa"}
            )[0]
            facts.append(
                SentinelFact(
                    expr=expr,
                    value=match.group("value"),
                    token=token,
                    line_number=line_number,
                    line_text=line,
                )
            )
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
        has_lifecycle_words = _name_has_any(
            sym.name, _LIFECYCLE_WORDS
        ) or _name_has_any(call_text, _LIFECYCLE_WORDS)
        has_callback_words = (
            _name_has_any(sym.name, _CALLBACK_WORDS)
            or _name_has_any(call_text, _CALLBACK_WORDS)
            or _name_has_any(body, _CALLBACK_WORDS)
        )
        has_lock_api = bool(locks)
        has_protocol_words = bool(state_tokens)
        has_notifier_words = _name_has_any(
            sym.name, _NOTIFIER_WORDS
        ) or _notifier_related_text(match_text)
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
                globals_.append(
                    GlobalConstruct(
                        unique_name=f"{rel_file}::{name}",
                        file_path=rel_file,
                        name=name,
                        line_number=start + 1,
                        kind=kind,
                        initializer=text[:3000],
                        referenced_functions=refs,
                    )
                )
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
        sym
        for defs in index.definitions.values()
        for sym in defs
        if sym.file_path == file_path
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
        use
        for uses in index.field_uses.values()
        for use in uses
        if use.file_path == file_path
    ]


def _all_symbols(index: SymbolIndex) -> list[SymbolDef]:
    if index.defs_by_file:
        return [sym for symbols in index.defs_by_file.values() for sym in symbols]
    return [sym for defs in index.definitions.values() for sym in defs]


def _lifecycle_symbol_candidates(index: SymbolIndex) -> list[SymbolDef]:
    if index.lifecycle_symbols or index.meta_by_symbol:
        return list(index.lifecycle_symbols)
    return [
        sym for sym in _all_symbols(index) if _name_has_any(sym.name, _LIFECYCLE_WORDS)
    ]


def _callback_symbol_candidates(index: SymbolIndex) -> list[SymbolDef]:
    if index.callback_symbols or index.meta_by_symbol:
        return list(index.callback_symbols)
    return [
        sym for sym in _all_symbols(index) if _name_has_any(sym.name, _CALLBACK_WORDS)
    ]


def _notifier_symbol_candidates(index: SymbolIndex) -> list[SymbolDef]:
    if index.notifier_related_symbols or index.meta_by_symbol:
        return list(index.notifier_related_symbols)
    return [
        sym for sym in _all_symbols(index) if _name_has_any(sym.name, _NOTIFIER_WORDS)
    ]


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
        is_sink = bool(
            _SINK_KIND_RE.search(match_text) or _SECURITY_API_RE.search(match_text)
        )
        sink_type = _sink_type_for_text(match_text) if is_sink else ""
    return FunctionNode(
        unique_name=_symbol_unique_name(sym),
        file_path=sym.file_path,
        name=sym.name,
        line_number=sym.line_number,
        is_source=is_source,
        is_sink=is_sink,
        calls=calls,
        source_reason=(
            "deterministic source-like entry or external input use" if is_source else ""
        ),
        sink_type=sink_type,
        sink_reason=(
            "deterministic sink-like API/state/lifecycle use" if is_sink else ""
        ),
    )


__all__ = [name for name in globals() if not name.startswith("__")]
