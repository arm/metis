# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import logging
from collections.abc import Iterable
from typing import Any

from llama_index.core.schema import BaseNode
from llama_index.core.schema import IndexNode

logger = logging.getLogger(__name__)


def _project_value(value: Any) -> tuple[Any, int]:
    """Represent NUL visibly without deleting text or merging metadata keys."""
    if isinstance(value, str):
        return value.replace("\x00", "\\u0000"), value.count("\x00")
    if isinstance(value, dict):
        result = {}
        count = 0
        for key, item in value.items():
            safe_key, key_count = _project_value(key)
            safe_item, item_count = _project_value(item)
            if safe_key in result:
                raise ValueError("NUL normalization would merge index metadata keys")
            result[safe_key] = safe_item
            count += key_count + item_count
        return result, count
    if isinstance(value, (list, tuple)):
        items = [_project_value(item) for item in value]
        return type(value)(item for item, _ in items), sum(n for _, n in items)
    return value, 0


def project_index_node[NodeT: BaseNode](node: NodeT) -> NodeT:
    """Make a NUL-safe indexing copy, retaining source data and stable identities."""
    identities = [node.node_id, node.ref_doc_id]
    if isinstance(node, IndexNode):
        identities.append(node.index_id)
    for related in node.relationships.values():
        identities.extend(
            item.node_id
            for item in (related if isinstance(related, list) else [related])
        )
    if any(value is not None and "\x00" in value for value in identities):
        raise ValueError("NUL in index node identity")

    payload, count = _project_value(node.model_dump())
    if not count:
        return node
    # The original embedding describes different text or metadata.
    payload["embedding"] = None
    # LlamaIndex's deserializer restores typed objects attached to IndexNode.
    projected = type(node).from_dict(payload)
    logger.warning(
        "Index NUL normalized before embedding: node_id=%r file_path=%r count=%d",
        node.node_id[:128],
        str(node.metadata.get("file_path", ""))[:512],
        count,
        extra={"event": "index_text_normalized", "nul_count": count},
    )
    return projected


def project_index_nodes(nodes: Iterable[BaseNode]) -> list[BaseNode]:
    """Preflight a whole collection before its caller embeds or replaces anything."""
    return [project_index_node(node) for node in nodes]
