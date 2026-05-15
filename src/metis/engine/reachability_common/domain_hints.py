# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Optional project/domain hints for C/C++ reachability analysis."""

from __future__ import annotations


_GPU_PROFILE = {
    "keywords": (
        "gpu",
        "gpu_ready",
        "gpu_powered",
        "gpu_init",
        "gpu_submit",
        "gpu_remove",
        "gpu_watchdog_fn",
        "gpu_ctx_get",
        "gpu_ctx_put",
        "gpu_ioctl_reset",
        "gpu_check_perm",
        "gpu_debug_dump_context",
        "gpu_region_create",
        "gpu_region_create_alias",
        "gpu_region_destroy_alias",
        "gpu_file_release",
        "gpu_file_poll",
        "gpu_sched_submit",
        "gpu_ctx_destroy",
        "gpu_mmu_insert_pages",
        "gpu_power_off",
        "gpu_fw_load_custom",
        "gpu_mappings",
        "gpu_wr",
        "cpu_wr",
        "ctx",
        "ctx_count",
        "ctx->regions",
        "ctx.lock",
        "region",
        "regions",
        "region_count",
        "region->pages",
        "alias",
        "alias_count",
        "mmu",
        "mmu.lock",
        "mmio",
        "dma",
        "firmware",
        "fw_name",
        "ioctl",
        "sysfs",
        "debugfs",
        "doorbell",
        "irq",
        "watchdog",
    ),
    "notes": (
        "GPU/domain hints are user-selected and should not be assumed for generic code.",
        "State/order: gpu_ready, gpu_powered, firmware, MMIO/DMA, queues, "
        "doorbells, interrupts, and power transitions may be security-sensitive.",
        "Permission: GPU_WR/CPU_WR-style constants and ioctl/debug/sysfs paths may "
        "represent separate permission domains.",
        "Lifecycle/accounting: gpu_mappings, alias_count, region_count, ctx_count, "
        "get/put, map/unmap, create/destroy, and watchdog callbacks may indicate "
        "ownership or teardown bugs.",
        "Memory/resource ownership: region->pages, alias pages, MMU mappings, and "
        "firmware paths are benchmark-specific hints, not generic assumptions.",
    ),
}

_BUILTIN_PROFILES = {"gpu": _GPU_PROFILE}


def normalize_domain_hints(raw_hints=None, raw_profiles=None):
    """Return normalized domain hint data from built-in profiles and user config."""
    keywords: list[str] = []
    notes: list[str] = []

    for profile_name in _iter_strings(raw_profiles):
        profile = _BUILTIN_PROFILES.get(profile_name.strip().lower())
        if profile:
            keywords.extend(profile.get("keywords", ()))
            notes.extend(profile.get("notes", ()))

    _add_raw_hints(raw_hints, keywords, notes)
    return {
        "keywords": tuple(dict.fromkeys(_clean_keyword(k) for k in keywords if k)),
        "notes": tuple(dict.fromkeys(str(note).strip() for note in notes if note)),
    }


def format_domain_hints_for_prompt(hints):
    notes = tuple((hints or {}).get("notes") or ())
    keywords = tuple((hints or {}).get("keywords") or ())
    if not notes and not keywords:
        return ""
    lines = ["User-provided domain hints:"]
    lines.extend(f"- {note}" for note in notes)
    if keywords:
        lines.append("- Relevant domain keywords: " + ", ".join(keywords[:80]))
    return "\n".join(lines)


def _add_raw_hints(raw, keywords, notes):
    if raw is None:
        return
    if isinstance(raw, dict):
        keywords.extend(_iter_strings(raw.get("keywords") or raw.get("terms")))
        notes.extend(_iter_strings(raw.get("notes") or raw.get("prompt_notes")))
        for value in raw.get("profiles") or ():
            profile = _BUILTIN_PROFILES.get(str(value).strip().lower())
            if profile:
                keywords.extend(profile.get("keywords", ()))
                notes.extend(profile.get("notes", ()))
        return
    if isinstance(raw, (list, tuple, set)):
        for item in raw:
            _add_raw_hints(item, keywords, notes)
        return
    keywords.extend(_iter_strings(raw))


def _iter_strings(value):
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (list, tuple, set)):
        return tuple(str(item) for item in value if str(item).strip())
    return (str(value),) if str(value).strip() else ()


def _clean_keyword(value):
    return str(value or "").strip().lower()
