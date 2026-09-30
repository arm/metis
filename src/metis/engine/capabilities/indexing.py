# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import logging
import os
import re
from concurrent.futures import CancelledError
from datetime import UTC
from datetime import datetime
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

import unidiff
from llama_index.core import SimpleDirectoryReader
from llama_index.core.readers.file.base import default_file_metadata_func
from llama_index.core.schema import Document

from metis.engine.diff_utils import extract_content_from_diff
from metis.engine.diff_utils import unquote_git_path
from metis.engine import git_history
from metis.engine.git_history import head_commit
from metis.engine.helpers import prepare_nodes_iter
from metis.engine.repository import EngineRepository
from metis.engine.runtime import EngineConfig
from metis.engine.runtime import EngineState
from metis.exceptions import IndexSyncError
from metis.exceptions import IndexUpdateError
from metis.exceptions import ParsingError

logger = logging.getLogger("metis")


# SimpleDirectoryReader keeps only file_path in the embedded and LLM text of a
# document. update must write the same metadata as index, or the rows differ.
_READER_EXCLUDED_METADATA_KEYS = (
    "file_name",
    "file_type",
    "file_size",
    "creation_date",
    "last_modified_date",
    "last_accessed_date",
)


def _relative_path(file_path: str, codebase_path: str) -> str:
    """Return the path of a file relative to the codebase root, with ``/`` separators."""
    relative = os.path.relpath(
        os.path.abspath(file_path), os.path.abspath(codebase_path)
    )
    return relative.replace(os.sep, "/")


def _document_metadata(file_path: str, codebase_path: str) -> dict[str, Any]:
    """Return the metadata that index and update write for a file.

    ``file_path`` is the absolute path. ``file_name`` is the path relative to the
    codebase root, because a base name does not identify a file when several
    files share it.
    """
    file_path = os.path.abspath(file_path)
    try:
        metadata = default_file_metadata_func(file_path)
    except OSError:
        metadata = {"file_path": file_path}
    metadata["file_name"] = _relative_path(file_path, codebase_path)
    return metadata


def _read_source_text(file_path: str) -> str:
    with open(file_path, "r", encoding="utf-8") as source:
        return source.read()


def _source_path(diff_file: unidiff.PatchedFile) -> str:
    """Return the decoded pre-change path of a patched file."""
    return _path_from_diff(diff_file, source=True)


def _diff_path(diff_file: unidiff.PatchedFile) -> str:
    """Return the decoded post-change path of a patched file."""
    return _path_from_diff(diff_file, source=diff_file.is_removed_file)


def _patch_headers(diff_file: unidiff.PatchedFile) -> list[str]:
    return [line.rstrip("\n") for line in diff_file.patch_info or []]


def _header_paths(headers: list[str]) -> tuple[str, str] | None:
    for line in headers:
        if line.startswith("diff --git "):
            parts = re.findall(r'"(?:\\.|[^"\\])*"|\S+', line[len("diff --git ") :])
            if len(parts) == 2:
                return unquote_git_path(parts[0]), unquote_git_path(parts[1])
    return None


def _path_from_diff(diff_file: unidiff.PatchedFile, *, source: bool) -> str:
    headers = _patch_headers(diff_file)
    marker = "rename from " if source else "rename to "
    copy_marker = "copy from " if source else "copy to "
    for line in headers:
        if line.startswith((marker, copy_marker)):
            return unquote_git_path(line.split(" ", 2)[2])
    raw_path = unquote_git_path(
        diff_file.source_file if source else diff_file.target_file
    )
    header_paths = _header_paths(headers)
    if header_paths is not None:
        left, right = header_paths
        # Both sides of a default diff name the same path after a/ and b/.
        prefixed = (
            left.startswith("a/") and right.startswith("b/") and left[2:] == right[2:]
        )
    else:
        old = unquote_git_path(diff_file.source_file)
        new = unquote_git_path(diff_file.target_file)
        # Without a git header, /dev/null marks the side that has no path.
        prefixed = (old.startswith("a/") or old == "/dev/null") and (
            new.startswith("b/") or new == "/dev/null"
        )
    if prefixed and raw_path.startswith("a/" if source else "b/"):
        return raw_path[2:]
    return raw_path


def _has_header(headers: list[str], prefix: str) -> bool:
    return any(line.startswith(prefix) for line in headers)


def _is_gitlink(diff_file: unidiff.PatchedFile) -> bool:
    if "160000" in (diff_file.source_mode, diff_file.target_mode):
        return True
    # A modified gitlink keeps its mode in the index line, so check the body.
    # A text file that contains this phrase also has other changed lines.
    changed = [
        line.value
        for hunk in diff_file
        for line in hunk
        if line.is_added or line.is_removed
    ]
    return bool(changed) and all(
        value.startswith("Subproject commit ") for value in changed
    )


@dataclass(frozen=True, slots=True)
class SyncResult:
    status: str  # "up_to_date" or "updated"
    base: str
    head: str


class IndexingService:
    def __init__(
        self,
        config: EngineConfig,
        state: EngineState,
        repository: EngineRepository,
        *,
        get_embedding_models: Callable[[], tuple[Any, Any]],
        clear_retriever_cache: Callable[[], None] | None = None,
    ):
        self._config = config
        self._state = state
        self._repository = repository
        self._get_embedding_models = get_embedding_models
        self._clear_retriever_cache = clear_retriever_cache
        # Share publication/mutation ordering, including same-thread callbacks.
        self._mutation_lock = state.retriever_lock
        self._active_mutations = 0
        self._closed = False

    @contextmanager
    def _mutation(self) -> Iterator[None]:
        with self._mutation_lock:
            if self._closed:
                raise RuntimeError("Index capability is closed")
            self._active_mutations += 1
            failure: BaseException | None = None
            try:
                yield
            except BaseException as exc:
                failure = exc
                raise
            finally:
                self._active_mutations -= 1
                # A close requested from this backend call cannot wait for itself.
                if self._closed and not self._active_mutations:
                    try:
                        self._close_backend()
                    except BaseException as exc:
                        if failure is None:
                            raise
                        failure.add_note(f"Index cleanup also failed: {exc}")

    def close(self) -> None:
        with self._mutation_lock:
            if self._closed:
                return
            self._closed = True
            if self._active_mutations:
                raise RuntimeError(
                    "Cannot close the active index from its backend call"
                )
            self._close_backend()

    def _close_backend(self) -> None:
        close = getattr(self._config.vector_backend, "close", None)
        if callable(close):
            close()

    def _docs_extensions(self) -> list[str]:
        return [
            ext.lower()
            for ext in self._config.plugin_config.get("docs", {}).get(
                "supported_extensions", [".md"]
            )
        ]

    def _index_kind(self, path: str, docs_supported_exts: list[str]) -> str | None:
        if os.path.splitext(path)[1].lower() in docs_supported_exts:
            return "docs"
        if self._repository.get_language_name_for_path(path) is not None:
            return "code"
        return None

    def _get_supported_input_files(
        self,
        docs_supported_exts: list[str],
    ) -> list[str]:
        base_path = os.path.abspath(self._config.codebase_path)
        docs_supported = [ext.lower() for ext in docs_supported_exts]
        metisignore_spec = self._repository.load_metisignore()
        selected = []

        for root, _, files in os.walk(base_path):
            for file_name in files:
                full_path = os.path.join(root, file_name)
                if os.path.islink(full_path) and not os.path.exists(full_path):
                    continue
                if self._repository.is_metisignored(full_path, spec=metisignore_spec):
                    continue
                if self._index_kind(full_path, docs_supported) is not None:
                    selected.append(full_path)

        return selected

    def index_codebase(self) -> None:
        pending_before = self._state.pending_nodes
        try:
            self.index_prepare_nodes()
            self.index_finalize_embeddings()
        finally:
            if self._state.pending_nodes is not pending_before:
                self._state.pending_nodes = None

    def count_index_items(self) -> int:
        docs_exts = self._config.plugin_config.get("docs", {}).get(
            "supported_extensions", [".md"]
        )
        return len(self._get_supported_input_files(docs_exts))

    def index_prepare_nodes_iter(self):
        """Prepare nodes for this thread's next finalize call without changing the index."""
        if self._closed:
            raise RuntimeError("Index capability is closed")
        if self._state.pending_nodes is not None:
            raise RuntimeError(
                "Finish the pending index preparation before preparing again"
            )
        self._get_embedding_models()
        docs_supported_exts = self._docs_extensions()

        logger.info(f"Indexing codebase at: {self._config.codebase_path}")
        input_files = self._get_supported_input_files(docs_supported_exts)
        if not input_files:
            self._state.pending_nodes = ([], [])
            return
        reader = SimpleDirectoryReader(
            input_files=input_files,
            filename_as_id=True,
        )
        documents = reader.load_data()
        logger.info(
            f"Loaded {len(documents)} documents from {self._config.codebase_path}"
        )

        doc_splitter = self._repository.get_doc_splitter()
        base_path = os.path.abspath(self._config.codebase_path)
        parent_dir = os.path.dirname(base_path)
        code_docs = []
        doc_docs = []
        for doc in documents:
            file_path = doc.metadata.get("file_path") or doc.id_
            doc.metadata["file_name"] = _relative_path(file_path, base_path)
            new_id = os.path.relpath(doc.id_, parent_dir)
            doc.doc_id = new_id
            doc.id_ = new_id

            kind = self._index_kind(file_path, docs_supported_exts)
            if kind == "docs":
                doc_docs.append(doc)
            elif kind == "code":
                code_docs.append(doc)

        nodes_code, nodes_docs = yield from prepare_nodes_iter(
            code_docs,
            doc_docs,
            self._repository.get_plugin_for_path,
            self._repository.get_splitter_cached,
            doc_splitter,
        )

        self._state.pending_nodes = (nodes_code, nodes_docs)

    def index_prepare_nodes(self):
        for _ in self.index_prepare_nodes_iter():
            pass

    def index_finalize_embeddings(self):
        pending = self._state.pending_nodes
        if pending is None:
            raise RuntimeError("No pending index preparation for this thread")
        self._state.pending_nodes = None
        with self._mutation():
            embed_model_code, embed_model_docs = self._get_embedding_models()
            nodes_code, nodes_docs = pending
            self._config.vector_backend.init()
            reset_index = getattr(self._config.vector_backend, "reset_index", None)
            if callable(reset_index):
                if self._clear_retriever_cache is not None:
                    self._clear_retriever_cache()
                try:
                    reset_index()
                finally:
                    if self._clear_retriever_cache is not None:
                        self._clear_retriever_cache()
            self._config.vector_backend.index_nodes(
                nodes_code,
                nodes_docs,
                embed_model_code=embed_model_code,
                embed_model_docs=embed_model_docs,
                **self._config.usage_runtime.hooks.embed_model_kwargs(),
            )
            self._record_index_state("index", self._resolve_commit())

    def _resolve_commit(self) -> str | None:
        """Return the commit the codebase is at: the explicit one, else git HEAD."""
        return self._config.index_commit or head_commit(self._config.codebase_path)

    def _record_index_state(self, operation: str, commit: str | None) -> None:
        """Record the commit that the index reflects after a successful change.

        A commit that is not known is recorded as ``None``, so a commit recorded
        by an earlier run is never left in place for an index that has changed.
        """
        state = {
            "commit": commit,
            "operation": operation,
            "updated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        }
        set_state = getattr(self._config.vector_backend, "set_index_state", None)
        try:
            if set_state is None:
                raise NotImplementedError
            set_state(state)
        except NotImplementedError:
            logger.warning("This vector backend does not record the index state.")
            return
        if commit is None:
            logger.warning(
                "The recorded index commit is now unknown. Pass --commit, or run "
                "index in a git checkout."
            )

    def get_index_state(self) -> dict | None:
        """Return the recorded index state, or ``None`` when nothing is recorded."""
        get_state = getattr(self._config.vector_backend, "get_index_state", None)
        try:
            return get_state() if get_state is not None else None
        except NotImplementedError:
            return None

    def sync_index(self, *, allow_non_ancestor: bool = False) -> SyncResult:
        """Update the index from the recorded commit to the checked-out commit.

        The diff between the two commits is applied like ``update``, and the new
        commit is recorded when that succeeds. Changed files are read from the
        working tree, so HEAD must be the new commit and tracked files under the
        codebase must be unchanged, before and after the update.
        """
        state = self.get_index_state()
        base = (state or {}).get("commit")
        if not base:
            raise IndexSyncError(
                "No commit is recorded for this index. Run `index` first."
            )
        try:
            base = git_history.normalize_commit(base)
        except ValueError as exc:
            raise IndexSyncError(
                "The recorded commit is not a valid commit id. Run a full `index`."
            ) from exc
        path = self._config.codebase_path
        explicit = self._config.index_commit
        try:
            checkout = git_history.read_head(path)
            if checkout is None:
                raise IndexSyncError(
                    "sync needs the git checkout that contains the codebase. "
                    "Run it inside the checkout, or set GIT_DIR."
                )
            head = explicit or checkout
            # An explicit commit must be checked out even when the index is at it.
            if explicit or base != head:
                self._check_checkout(path, head)
            if base == head:
                return SyncResult("up_to_date", base, head)
            self._check_range(path, base, head, allow_non_ancestor=allow_non_ancestor)
            patch_text = git_history.diff_between(path, base, head)
            with self._mutation():
                self._apply_patch(patch_text)
                try:
                    self._check_checkout(path, head)
                except IndexSyncError as exc:
                    raise IndexSyncError(
                        f"The checkout changed while sync ran: {exc} The index was "
                        f"updated, but the recorded commit is still {base}. "
                        "Run sync again."
                    ) from exc
                self._record_index_state("sync", head)
        except git_history.GitError as exc:
            raise IndexSyncError(
                f"{exc}. Run sync in a git checkout with git installed, "
                "or run a full `index`."
            ) from exc
        return SyncResult("updated", base, head)

    @staticmethod
    def _check_checkout(path: str, head: str) -> None:
        checkout = git_history.read_head(path)
        if checkout != head:
            raise IndexSyncError(
                f"HEAD is {checkout or 'unknown'}, not {head}. sync reads changed "
                f"files from the working tree, so check out {head} first."
            )
        if git_history.has_tracked_changes(path):
            raise IndexSyncError(
                "Tracked files under the codebase have uncommitted changes. "
                "Commit or stash them first."
            )

    @staticmethod
    def _check_range(
        path: str, base: str, head: str, *, allow_non_ancestor: bool
    ) -> None:
        shallow = git_history.is_shallow(path)
        if not git_history.has_commit(path, base):
            if shallow:
                raise IndexSyncError(
                    f"The recorded commit {base} is not in this shallow clone. "
                    "Fetch more history with `git fetch --unshallow`, or run a "
                    "full `index`."
                )
            raise IndexSyncError(
                f"The recorded commit {base} is not in this repository. "
                "Run a full `index`."
            )
        if allow_non_ancestor or git_history.is_ancestor(path, base, head):
            return
        if shallow:
            raise IndexSyncError(
                f"This shallow clone does not show that {base} is an ancestor of "
                f"{head}. Fetch more history with `git fetch --unshallow`, pass "
                "--allow-non-ancestor, or run a full `index`."
            )
        raise IndexSyncError(
            f"The recorded commit {base} is not an ancestor of {head}. History "
            "was rewritten or the index was built from another branch. Run a "
            "full `index`, or pass --allow-non-ancestor to apply the diff "
            "between the two trees."
        )

    def _prepare_nodes(
        self, code_docs: list[Document], doc_docs: list[Document]
    ) -> tuple[list, list]:
        preparation = prepare_nodes_iter(
            code_docs,
            doc_docs,
            self._repository.get_plugin_for_path,
            self._repository.get_splitter_cached,
            self._repository.get_doc_splitter(),
            raise_on_error=True,
        )
        try:
            while True:
                next(preparation)
        except StopIteration as done:
            return done.value

    def update_index(self, patch_text, commit=None):
        """Apply a patch to the index and record the commit it reaches.

        The commit is the one given here or with ``--commit``. Without one, the
        recorded commit becomes unknown. A patch is not always the diff from the
        recorded commit, so after a plain update neither the old commit nor HEAD
        describes the index, and ``sync`` must not start from the old commit.

        A plain update that fails after the patch parses also records an
        unknown commit, because it may have written rows. An update with a
        commit that fails keeps the old record, so ``sync`` applies the range
        again.
        """
        commit = commit or self._config.index_commit
        with self._mutation():
            try:
                self._apply_patch(patch_text)
            except ParsingError:
                raise
            except BaseException:
                if commit is None:
                    self._clear_commit_after_failed_update()
                raise
            self._record_index_state("update", commit)

    def _clear_commit_after_failed_update(self) -> None:
        try:
            self._record_index_state("update", None)
        except Exception:
            # The update error matters more. Report this one and keep going.
            logger.exception("Could not clear the recorded commit after update.")

    def _apply_patch(self, patch_text):
        with self._mutation():
            embed_model_code, embed_model_docs = self._get_embedding_models()
            try:
                patch_set = unidiff.PatchSet.from_string(patch_text)
                logger.info("Parsed the provided patch string successfully.")
            except Exception as e:
                raise ParsingError(f"Error parsing patch string: {e}")
            self._config.vector_backend.init()

            index_code, index_docs = self._config.vector_backend.get_index_handles(
                embed_model_code=embed_model_code,
                embed_model_docs=embed_model_docs,
                **self._config.usage_runtime.hooks.embed_model_kwargs(),
            )

            codebase_name = os.path.basename(
                os.path.abspath(self._config.codebase_path)
            )
            docs_supported_exts = self._docs_extensions()
            metisignore_spec = self._repository.load_metisignore()
            failures: list[str] = []
            for diff_file in patch_set:
                headers = _patch_headers(diff_file)
                if _is_gitlink(diff_file):
                    continue
                is_copy = _has_header(headers, "copy from ") and _has_header(
                    headers, "copy to "
                )
                is_rename = _has_header(headers, "rename from ") and _has_header(
                    headers, "rename to "
                )
                if (
                    not diff_file
                    and not is_copy
                    and not is_rename
                    and not diff_file.is_binary_file
                    and not diff_file.is_added_file
                    and not diff_file.is_removed_file
                ):
                    continue
                diff_path = _diff_path(diff_file)
                doc_id = os.path.join(codebase_name, diff_path)
                kind = self._index_kind(doc_id, docs_supported_exts)

                if is_rename:
                    # A rename is a delete of the old path plus an add of the new one.
                    old_doc_id = os.path.join(codebase_name, _source_path(diff_file))
                    old_kind = self._index_kind(old_doc_id, docs_supported_exts)
                    if old_kind is not None:
                        old_index = index_code if old_kind == "code" else index_docs
                        old_index.delete_ref_doc(old_doc_id, delete_from_docstore=True)

                if kind is None:
                    continue
                target_index = index_code if kind == "code" else index_docs
                file_path = os.path.join(self._config.codebase_path, diff_path)

                if diff_file.is_removed_file or diff_file.is_binary_file:
                    target_index.delete_ref_doc(doc_id, delete_from_docstore=True)
                else:
                    if self._repository.is_metisignored(
                        os.path.abspath(file_path), spec=metisignore_spec
                    ):
                        # Existing rows may predate the ignore rule.
                        target_index.delete_ref_doc(doc_id, delete_from_docstore=True)
                        continue
                    try:
                        file_content = _read_source_text(file_path)
                    except FileNotFoundError:
                        if not (diff_file.is_added_file or is_copy or is_rename):
                            failures.append(f"{diff_path} (file not found)")
                            continue
                        file_content = extract_content_from_diff(diff_file)
                    except (OSError, UnicodeError) as exc:
                        failures.append(f"{diff_path} ({exc})")
                        continue
                    if not file_content:
                        logger.warning("No content available for %s", diff_path)
                        target_index.delete_ref_doc(doc_id, delete_from_docstore=True)
                        continue
                    doc = Document(
                        text=file_content,
                        metadata=_document_metadata(
                            file_path, self._config.codebase_path
                        ),
                        id_=doc_id,
                        excluded_embed_metadata_keys=list(
                            _READER_EXCLUDED_METADATA_KEYS
                        ),
                        excluded_llm_metadata_keys=list(_READER_EXCLUDED_METADATA_KEYS),
                    )

                    try:
                        nodes_code, nodes_docs = self._prepare_nodes(
                            [doc] if kind == "code" else [],
                            [doc] if kind == "docs" else [],
                        )
                    except CancelledError:
                        raise
                    except Exception as exc:
                        failures.append(f"{diff_path} (node preparation: {exc})")
                        continue
                    nodes = nodes_code or nodes_docs
                    if not nodes:
                        logger.warning("No nodes available for %s", diff_path)
                        target_index.delete_ref_doc(doc_id, delete_from_docstore=True)
                        continue
                    target_index.delete_ref_doc(doc_id, delete_from_docstore=True)
                    target_index.insert_nodes(nodes)
                    target_index.docstore.set_document_hash(doc.id_, doc.hash)
            if failures:
                raise IndexUpdateError(failures)
            logger.info("Index update complete based on the provided patch diff.")
