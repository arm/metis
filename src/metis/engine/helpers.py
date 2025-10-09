# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import logging
import os
from rich.progress import (
    Progress,
    SpinnerColumn,
    BarColumn,
    TextColumn,
    TaskProgressColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)

from metis.utils import (
    count_tokens,
    llm_call,
    parse_json_output,
    read_file_content,
)

logger = logging.getLogger("metis")


def query_engine(engine, question):
    try:
        return engine.query(question)
    except Exception as e:
        logger.warning(f"Error querying index: {e}")
        return ""


def validate_review(
    llm_provider,
    llama_query_model,
    file_path,
    snippet,
    combined_context,
    review,
    system_prompt_validation,
):
    prompt_text = (
        f"SNIPPET: {snippet}\nCONTEXT:\n{combined_context}\nREVIEW:\n{review}\n"
    )
    validation_response = llm_call(
        llm_provider,
        system_prompt_validation,
        prompt_text,
        model=llama_query_model,
    )
    parsed_response = parse_json_output(validation_response)
    logger.info(f"Final validation for {file_path}: {parsed_response}")
    return parsed_response


def summarize_changes(llm_provider, file_path, issues, summary_prompt):
    try:
        answer = llm_call(llm_provider, summary_prompt, issues)
        return answer
    except Exception as e:
        logger.error(f"Error summarizing changes for {file_path}: {e}")
        return ""


def retrieve_context(file_path, query_engine_code, query_engine_docs, context_prompt):
    result_code = query_engine(query_engine_code, context_prompt)
    if result_code:
        logger.debug(f"Retrieved context from code index for {file_path}.")

    result_docs = query_engine(query_engine_docs, context_prompt)
    if result_docs:
        logger.debug(f"Retrieved context from documentation index for {file_path}.")

    parts = []
    if result_code:
        parts.append(str(result_code))

    if result_docs:
        parts.append(str(result_docs))

    return "\n".join(parts)


def perform_security_review(
    llm_provider, file_path, snippet, combined_context, system_prompt
):
    prompt_text = (
        f"FILE: {file_path}\nSNIPPET: {snippet}\nCONTEXT:\n{combined_context}\n"
    )
    try:
        answer = llm_call(llm_provider, system_prompt, prompt_text)
        logger.info(f"Received security review response for {file_path}.")
        return answer
    except Exception as e:
        logger.error(f"Error during security review for {file_path}: {e}")
        return ""


def extract_content_from_diff(file_diff):
    content_lines = []
    for hunk in file_diff:
        for line in hunk:
            if line.is_added:
                content_lines.append(line.value)
    return "".join(content_lines)


def process_diff_file(codebase_path, file_diff, max_token_length):
    changed_lines = []
    for hunk in file_diff:
        for line in hunk:
            if line.is_added:
                changed_lines.append("+" + line.value)
            elif line.is_removed:
                changed_lines.append("-" + line.value)
    snippet = "".join(changed_lines)
    original_file_path = os.path.join(codebase_path, file_diff.path)
    original_content = read_file_content(original_file_path)
    if original_content:
        logger.info(f"Fetched original content for {file_diff.path}.")
        total_tokens = count_tokens(original_content) + count_tokens(snippet)
        if total_tokens <= max_token_length:
            snippet = f"ORIGINAL_FILE:\n{original_content}\n\nFILE_CHANGES:\n{snippet}"
        else:
            snippet = f"FILE_CHANGES:\n{snippet}"
    return snippet


def build_nodes_for_indexing(
    code_docs,
    doc_docs,
    get_plugin_for_extension,
    get_splitter_cached,
    doc_splitter,
    verbose,
):
    nodes_code = []
    nodes_docs = []
    if verbose:
        with Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(bar_width=None, complete_style="green", finished_style="green"),
            TaskProgressColumn(),
            TextColumn("[bright_black]elapsed"),
            TimeElapsedColumn(),
            TextColumn("[bright_black]eta"),
            TimeRemainingColumn(),
            transient=True,
            redirect_stdout=True,
            redirect_stderr=True,
        ) as progress:
            task_code = progress.add_task("Parsing code", total=len(code_docs))
            for d in code_docs:
                ext = os.path.splitext(d.id_)[1].lower()
                plugin = get_plugin_for_extension(ext)
                if not plugin:
                    progress.advance(task_code, 1)
                    continue
                try:
                    splitter = get_splitter_cached(plugin)
                    parsed_nodes = splitter.get_nodes_from_documents([d])
                    nodes_code.extend(parsed_nodes)
                except Exception as e:
                    name = (
                        plugin.get_name() if hasattr(plugin, "get_name") else "unknown"
                    )
                    logger.warning(
                        f"Could not parse code with language {name} for file {d.id_} (ext {ext}): {e}"
                    )
                finally:
                    progress.advance(task_code, 1)
            try:
                progress.update(task_code, completed=progress.tasks[task_code].total)
            except Exception:
                pass

            task_docs = progress.add_task("Parsing docs", total=len(doc_docs))
            for d in doc_docs:
                try:
                    nodes_docs.extend(doc_splitter.get_nodes_from_documents([d]))
                finally:
                    progress.advance(task_docs, 1)
            try:
                progress.update(task_docs, completed=progress.tasks[task_docs].total)
            except Exception:
                pass
    else:
        for d in code_docs:
            ext = os.path.splitext(d.id_)[1].lower()
            plugin = get_plugin_for_extension(ext)
            if not plugin:
                continue
            try:
                splitter = get_splitter_cached(plugin)
                parsed_nodes = splitter.get_nodes_from_documents([d])
                nodes_code.extend(parsed_nodes)
            except Exception as e:
                name = plugin.get_name() if hasattr(plugin, "get_name") else "unknown"
                logger.warning(
                    f"Could not parse code with language {name} for file {d.id_} (ext {ext}): {e}"
                )
                continue
        nodes_docs = doc_splitter.get_nodes_from_documents(doc_docs)
    return nodes_code, nodes_docs


def run_with_timer(description, func, *args, **kwargs):
    with Progress(
        TextColumn("[bold cyan]" + description),
        TextColumn("[bright_black]elapsed"),
        TimeElapsedColumn(),
        transient=True,
        redirect_stdout=True,
        redirect_stderr=True,
    ) as progress:
        task_id = progress.add_task(description, total=1)
        result = func(*args, **kwargs)
        try:
            progress.update(task_id, completed=1)
        except Exception:
            pass
        return result
