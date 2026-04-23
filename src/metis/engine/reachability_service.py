from __future__ import annotations

import json
import logging
import os
import threading
import uuid

from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate

from metis.usage import submit_with_current_context
from metis.utils import parse_json_output, read_file_content

from .repository import EngineRepository
from .runtime import EngineConfig

logger = logging.getLogger("metis")


# types

@dataclass
class FunctionNode:
    unique_name: str
    file_path: str
    name: str
    line_number: int
    is_source: bool
    is_sink: bool
    calls: list[str] = field(default_factory=list)
    resolved_calls: list[str] = field(default_factory=list)
    source_reason: str = ""
    sink_type: str = ""
    sink_reason: str = ""

    def to_dict(self) -> dict:
        return {
            "unique_name": self.unique_name,
            "file_path": self.file_path,
            "name": self.name,
            "line_number": self.line_number,
            "is_source": self.is_source,
            "is_sink": self.is_sink,
            "calls": self.calls,
            "resolved_calls": self.resolved_calls,
            "source_reason": self.source_reason,
            "sink_type": self.sink_type,
            "sink_reason": self.sink_reason,
        }
    

@dataclass
class ReachabilityPath:
    source: str
    sink: str
    path: list[str] = field(default_factory=list)
    sink_type: str = ""

@dataclass
class VulnerabilityFinding:
    id: str
    vulnerability_type: str
    severity: str
    confidence: str
    source_function: str
    source_file: str
    source_line: int
    sink_function: str
    sink_file: str
    sink_line: int
    path: list[str] = field(default_factory=list)
    description: str = ""
    root_cause: str = ""
    evidence: str = ""
    analysis_type: str = "reachability"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "vulnerability_type": self.vulnerability_type,
            "severity": self.severity,
            "confidence": self.confidence,
            "source_function": self.source_function,
            "source_file": self.source_file,
            "source_line": self.source_line,
            "sink_function": self.sink_function,
            "sink_file": self.sink_file,
            "sink_line": self.sink_line,
            "path": self.path,
            "description": self.description,
            "root_cause": self.root_cause,
            "evidence": self.evidence,
            "analysis_type": self.analysis_type,
        }

class ReachabilityGraph:
    def __init__(self):
        self.nodes: dict[str, FunctionNode] = {}
        self.name_index: dict[str, list[str]] = {}

    def add_node(self, node):
        self.nodes[node.unique_name] = node
        self.name_index.setdefault(node.name, []).append(node.unique_name)

    def resolve_all_calls(self):
        for node in self.nodes.values():
            resolved = []
            for call_name in node.calls:
                targets = self.name_index.get(call_name, [])
                if len(targets) == 1:
                    resolved.append(targets[0])
                elif len(targets) > 1:
                    same = [t for t in targets if t.startswith(node.file_path + "::")]
                    resolved.extend(same if same else targets)
            node.resolved_calls = list(dict.fromkeys(resolved))

    def get_sources(self):
        return [n for n in self.nodes.values() if n.is_source]
    
    def get_sinks(self):
        return [n for n in self.nodes.values() if n.is_sink]
    
    def get_node(self, name):
        return self.nodes.get(name)
    
    def node_count(self):
        return len(self.nodes)
    
    def edge_count(self):
        return sum(len(n.resolved_calls) for n in self.nodes.values())
    
    def save_jsonl(self, path):
        out = Path(path)

        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", encoding="utf-8") as fh:
            for n in self.nodes.values():
                fh.write(json.dumps(n.to_dict(), ensure_ascii=False) + "\n")


# shared

def _number_lines(content):
    lines = content.splitlines()
    w = len(str(len(lines)))
    return "\n".join(f"{i+1:>{w}}: {line}" for i, line in enumerate(lines))


def _read_function_body(codebase_path, node, max_chars=3000):
    content = read_file_content(os.path.join(codebase_path, node.file_path))
    if not content:
        return ""
    fl = content.splitlines()
    start = max(0, node.line_number - 1)
    end = min(len(fl), start + 80)

    depth, opened = 0, False

    for i in range(start, min(len(fl), start + 300)):
        for ch in fl[i]:
            if ch == "{":
                depth += 1
                opened = True
            elif ch == "}":
                depth -= 1
        if opened and depth <= 0:
            end = i + 1
            break
    
    snippet = "\n".join(f"{start+1+j}: {fl[start+j]}" for j in range(end - start))
    return snippet[:max_chars] + "\n" if len(snippet) > max_chars else snippet


def _build_all_code(codebase_path, nodes, max_chars=3000):
    bodies = []

    for fn in nodes:
        body = _read_function_body(codebase_path, fn, max_chars)
        if body:
            bodies.append(f"Function {fn.unique_name} (line {fn.line_number} in {fn.file_path}):\n{body}")
    return "\n\n".join(bodies)

def _lookup_fn(name, fn_by_name, fn_by_unique, all_fns):
    if name in fn_by_unique:
        return fn_by_unique[name]
    if name in fn_by_name:
        return fn_by_name[name]
    for fn in all_fns:
        if name in fn.name or name in fn.unique_name:
            return fn
    return None


def _severity_title(value, default="Medium"):
    text = str(value or "").strip().lower()
    if not text:
        return default
    return text[:1].upper() + text[1:]


def _chunked(items, size):
    if size <= 0:
        size = 1
    for i in range(0, len(items), size):
        yield items[i : i + size]


def _dedupe_paths(paths):
    seen = set()
    results = []
    for p in paths:
        key = (p.source, p.sink, tuple(p.path))
        if key in seen:
            continue
        seen.add(key)
        results.append(p)
    return results


def _read_line_context(codebase_path, rel_file, line_number, context=2, max_chars=1200):
    content = read_file_content(os.path.join(codebase_path, rel_file))
    if not content:
        return ""
    lines = content.splitlines()
    if not lines:
        return ""
    try:
        line_number = max(1, int(line_number))
    except Exception:
        line_number = 1
    start = max(0, line_number - 1 - context)
    end = min(len(lines), line_number + context)
    snippet = "\n".join(f"{i+1}: {lines[i]}" for i in range(start, end))
    return snippet[:max_chars]


_VULN_TO_CWE = {
    "buffer_overflow": "CWE-120",
    "out_of_bounds": "CWE-787",
    "use_after_free": "CWE-416",
    "double_free": "CWE-415",
    "null_deref": "CWE-476",
    "command_injection": "CWE-78",
    "format_string": "CWE-134",
    "integer_overflow": "CWE-190",
    "path_traversal": "CWE-22",
    "race_condition": "CWE-362",
    "uninitialized_memory": "CWE-457",
    "type_confusion": "CWE-843",
}



# Graph builder


_EXTRACTION_SYSTEM_PROMPT = """\
You are a C and C++ static analysis tool. Analyze the following source file and
extract ALL function definitions with their security relevant metadata.

For each function defined in this file (with body), provide:

1. "name": the function name
2. "line": line number where the function definition starts
3. "calls": list of ALL function and macro names called inside this funciton body
4. "is_source": true if this function directly receives or processes external or untrusted input (e.g. user input, network data, file content, environment variables, etc.) in a way that could lead to vulnerabilities if not handled properly. Otherwise false.
5. "source_reason": if is_source, briefly explain why
6. "is_sink": true if this function performs operation that could be dangerous with attacker controlled input
7. "sink_type": if is_sink, one of: buffer_overflow, use_after_free, double_free, null_deref, command_injection, format_string, integer_overflow, path_traversal, race_condition, uninitialized_memory, type_confusion, out_of_bounds, other
8. "sink_reason": if is_sink, briefly explain why

For source indicators, mark is_source=true when a function:
- reads from stdin, files, network sockets, pipes, IPC, env variables, or other external sources
- processes command line arguments (e.g. main's argv)
- is a callback or handler that is likely invoked with external input (e.g. signal handlers, event handlers, thread entry points, etc.)
- receives data from shared memory or message queues
- is main function or an entry point that receives input from outside the program


For sink indicators, mark is_sink=true when a function:
- calls memcpy, strcpy, sprintf, gets, or similar functions with attacker controlled input
- performs pointer arithmetic without bound checks
- has integer arithmetic that could overflow and influence buffer sizes or indices
- calls system, exec, popen, or similar functions with attacker controlled input or constructed strings
- uses format strings built from variables
- frees memory that may be used afterward or frees the same pointer multiple times
- dereferences pointers without null checks after allocation or lookup
- accesses arrays with indices derived from untrusted input
- opens files with paths derived from untrusted input
- has realloc or malloc with arithmetic on the size argument that could wrap
- casts void pointers to a concrete type without validation


A function CAN be both a source and a sink.
Do NOT include mere declarations or prototypes without bodies.
DO include static, inine, and helper functions.

Return ONLY valid JSON:
{{"functions": [{{"name": ..., "line": ..., "calls": [...], "is_source": ..., "source_reason": ..., "is_sink": ..., "sink_type": ..., "sink_reason": ...}}, ...]}}

If the file has no function definitions, return {{"functions": []}}."""

_EXTRACTION_USER_TEMPLATE = "File: {file_path}\n\nCode:\n{file_content}"


class GraphBuilder:
    def __init__(self, llm_provider, model, usage_runtime, max_tokens=16384):
        self._p = llm_provider
        self._m = model
        self._u = usage_runtime
        self._t = max_tokens

    def build(self, files, codebase_path, *, max_workers=4, progress_callback=None):
        graph = ReachabilityGraph()

        total = len(files)
        errors = []

        if progress_callback:
            progress_callback({"event": "extraction_start", "total": total})

        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futs = {submit_with_current_context(ex, self._extract, f, codebase_path): f for f in files}
            done = 0
            for fut in as_completed(futs):
                fp = futs[fut]
                done += 1
                try:
                    for n in fut.result():
                        graph.add_node(n)
                except Exception as e:
                    errors.append(f"{os.path.basename(fp)}: {e}")
                if progress_callback:
                    progress_callback({"event": "extraction_progress", "completed": done, "total": total, "file": fp})

        graph.resolve_all_calls()

        if progress_callback:
            progress_callback({"event": "extraction_done", "nodes": graph.node_count(),
                               "edges": graph.edge_count(), "sources": len(graph.get_sources()), "sinks": len(graph.get_sinks()), "errors": errors})
            
        return graph
    

    def _extract(self, file_path, codebase_path):
        content = read_file_content(file_path)

        if not content or not content.strip():
            return []
        
        base = os.path.abspath(codebase_path)
        rel = os.path.relpath(file_path, base)
        kw = self._u.hooks.chat_model_kwargs()

        chat = self._p.get_chat_model(model=self._m, max_tokens=self._t, temperature=0.0, **kw)
        prompt = ChatPromptTemplate.from_messages([
            ("system", _EXTRACTION_SYSTEM_PROMPT),
            ("user", _EXTRACTION_USER_TEMPLATE)
        ])

        raw = (prompt | chat | StrOutputParser()).invoke({"file_path": rel, "file_content": _number_lines(content)}).strip()

        parsed = parse_json_output(raw)
        if not isinstance(parsed, dict):
            return []
        fns = parsed.get("functions")
        if not isinstance(fns, list):
            return []
        
        nodes, seen = [], set()

        for e in fns:

            if not isinstance(e, dict):
                continue

            name = str(e.get("name") or "").strip()
            if not name: continue
            u = f"{rel}::{name}"

            if u in seen:
                continue    

            seen.add(u)

            calls = [str(c).strip() for c in (e.get("calls") or []) if str(c).strip()]
            line = 1

            try: line = max(1, int(e.get("line", 1)))
            except: pass
            nodes.append(FunctionNode(
                unique_name=u,
                file_path=rel,
                name=name,
                line_number=line,
                calls=calls,
                is_source=bool(e.get("is_source")),
                source_reason=str(e.get("source_reason") or "").strip(),
                is_sink=bool(e.get("is_sink")),
                sink_type=str(e.get("sink_type") or "").strip(),
                sink_reason=str(e.get("sink_reason") or "").strip(),
            ))
        return nodes
    

# path tracer

class PathTracer:
    def __init__(self, graph, *, max_path_length=25, max_paths_per_source=200):
        self._g = graph
        self._ml = max_path_length
        self._mp = max_paths_per_source

    def find_all_paths(self):
        sources = self._g.get_sources()
        sinks = {n.unique_name for n in self._g.get_sinks()}
        if not sources or not sinks:
            return []
        paths = []
        for s in sources:
            paths.extend(self._bfs(s.unique_name, sinks))
        return paths
    

    def _bfs(self, src, sinks):
        results, q = [], deque([[src]])

        while q and len(results) < self._mp:
            path = q.popleft()
            node = self._g.get_node(path[-1])
            if not node:
                continue

            for c in node.resolved_calls:
                if c in path:
                    continue
                np = path + [c]
                if c in sinks:
                    sn = self._g.get_node(c)
                    results.append(ReachabilityPath(source=src, sink=c, path=list(np), sink_type=sn.sink_type if sn else ""))
                    if len(results) >= self._mp:
                        break
                    if len(np) < self._ml:
                        q.append(np)
                elif len(np) < self._ml:
                    q.append(np)
        return results
    


# reachability confirmer, at this point we should already have a pretty good idea of the vulnerable paths, 
# so we can use the LLM to confirm if they are likely to be true positives or not, and also to provide more context and evidence for each finding. 
# The idea is that this can help prioritize the findings and reduce false positives.


_CONFIRM_SYS = """\

You are a security researcher specializing in C and C++ code analysis. 

You are given reachable call paths from attacker input sources to flagged sinks, with relevant source code.

For EACH path determine if it is a real exploitable vulnerability:

- Does attacker input actually propagate through every hop?
- Are there sanitization or bound checks?
- is the sink truly dangerous as called?


Return ONLY valid JSON:

{{"findings": [{{"path_index": 0, "is_vulnerable": true, "vulnerability_type": "buffer_overflow", "severity": "high", "confidence": "high", "description": "...", "root_cause": "...", "evidence": "..." }}, ...]}}

vulnerability_type should be one of: buffer_overflow, use_after_free, double_free, null_deref, command_injection, format_string, integer_overflow, path_traversal, race_condition, uninitialized_memory, type_confusion, out_of_bounds, other
severity should be one of: low, medium, high, critical
confidence should be one of: low, medium, high

Be conservative."""


_CONFIRM_USR = "{paths_section}\n\n{code_section}"


_FILE_CONFIRM_SYS = """\
You are a security researcher specializing in C and C++ code analysis.

You are reviewing ONE target file from a larger codebase.

You are given:
- reachable call paths from external or attacker-controlled sources
- the relevant code from the target file
- supporting code for upstream/downstream functions on the path

Only report a vulnerability when the primary bug mechanism is actually present in the TARGET FILE code shown.
Do not report generic race, use-after-free, integer-overflow, or path-traversal hypotheses unless the concrete target-file code supports that conclusion.
Be conservative and prefer precision over recall.

For EACH path determine if it is a real exploitable vulnerability in the target file:

- Does attacker input actually propagate through the path into the target file logic?
- Does the target file contain the missing validation, unsafe state transition, unsafe publish/use ordering, or dangerous sink usage?
- Are there checks or lifecycle constraints that make the path non-exploitable?
- Is the root cause in the target file rather than merely elsewhere on the path?

Return ONLY valid JSON:

{{"findings": [{{"path_index": 0, "is_vulnerable": true, "vulnerability_type": "buffer_overflow", "severity": "high", "confidence": "high", "description": "...", "root_cause": "...", "evidence": "..." }}, ...]}}

vulnerability_type should be one of: buffer_overflow, use_after_free, double_free, null_deref, command_injection, format_string, integer_overflow, path_traversal, race_condition, uninitialized_memory, type_confusion, out_of_bounds, other
severity should be one of: low, medium, high, critical
confidence should be one of: low, medium, high

Be conservative."""


_FILE_CONFIRM_USR = """Target file: {target_file}

{paths_section}

== TARGET FILE CODE ==
{target_file_code}

== RELATED PATH CODE ==
{related_code_section}
"""


class VulnerabilityConfirmer:
    def __init__(self, llm_provider, model, usage_runtime, codebase_path, max_tokens=4096):
       self._p = llm_provider
       self._m = model
       self._u = usage_runtime
       self._cb = os.path.abspath(codebase_path)
       self._t = max_tokens

    def confirm_parallel(self, paths, graph, *, max_workers=8, output_path=None, progress_callback=None):
        
        if not paths: return []
        groups = defaultdict(list)

        for p in paths:
            groups[p.sink_type].append(p)
            
        total = len(groups)
        all_f = []
        lock = threading.Lock()
        done = [0]

        if progress_callback:
            progress_callback({"event": "confirmation_start", "total": total})
        fh = None

        if output_path:
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            fh = open(output_path, "w", encoding="utf-8")
        try:
            with ThreadPoolExecutor(max_workers=max_workers) as ex:
                futs = {submit_with_current_context(ex, self._group, sn, gp, graph): sn for sn, gp in groups.items()}

                for fut in as_completed(futs):
                    sn = futs[fut]

                    try:
                        findings = fut.result()
                        with lock:
                            all_f.extend(findings)
                            if fh:
                                for f in findings:
                                    fh.write(json.dumps(f.to_dict(), ensure_ascii=False) + "\n")
                                    fh.flush()
                    except Exception as e:
                        logger.warning(f"Error confirming paths for sink type {sn}: {e}")
                    with lock:
                        done[0]+=1
                    if progress_callback:
                        progress_callback({"event": "confirmation_progress", "completed": done[0], "total": total, "sink": sn})
        finally:
            if fh:
                fh.close()
        if progress_callback:
            progress_callback({"event": "confirmation_done", "confirmed": len(all_f)})
        return all_f
   
    def _group(self, sink_type, paths, graph):
        batch = paths[:8]
        needed = {}

        for p in batch:
            for u in p.path:
                n = graph.get_node(u)
                if n:
                    needed[u] = n
        ps = ["== CANDIDATE PATHS =="]
        
        for i, p in enumerate(batch):
            sn, sk = graph.get_node(p.source), graph.get_node(p.sink)
            ps.append(f"\nPath {i}:\n Chain: {' -> '.join(p.path)}")
            if sn:
                ps.append(f" Source: {sn.unique_name} (line {sn.line_number}) - {sn.source_reason}")

            if sk:
                ps.append(f" Sink: {sk.unique_name} (line {sk.line_number}) [{sk.sink_type}] - {sk.sink_reason}")

        cs = ["== SOURCE CODE =="]
        for u, n in needed.items():
            b = _read_function_body(self._cb, n)
            if b: cs.append(f"\n--- {u} (line {n.line_number}) ---\n{b}")
        kw = self._u.hooks.chat_model_kwargs()
        chat = self._p.get_chat_model(model=self._m, max_tokens=self._t, temperature=0.1, **kw)
        
        prompt = ChatPromptTemplate.from_messages([
            ("system", _CONFIRM_SYS),
            ("user", _CONFIRM_USR)
        ])
        
        raw = (prompt | chat | StrOutputParser()).invoke({"paths_section": "\n".join(ps), "code_section": "\n".join(cs)}).strip()
        parsed = parse_json_output(raw)

        if not isinstance(parsed, dict):
            return []
        fl = parsed.get("findings")

        if not isinstance(fl, list):
            return []   
        
        results = []

        for e in fl:
            if not isinstance(e, dict) or not e.get("is_vulnerable"):
                continue

            idx = int(e.get("path_index", -1))

            if idx < 0 or idx >= len(batch): continue

            rp = batch[idx]
            sn = graph.get_node(rp.source)
            sk = graph.get_node(rp.sink)

            results.append(VulnerabilityFinding(
                id=uuid.uuid4().hex[:16], vulnerability_type=str(e.get("vulnerability_type") or rp.sink_type or "other"),
                severity = str(e.get("severity") or "medium"), confidence=str(e.get("confidence") or "medium"),
                source_function=rp.source, source_file=sn.file_path if sn else "", source_line=sn.line_number if sn else 0,
                sink_function=rp.sink, sink_file=sk.file_path if sk else "", sink_line=sk.line_number if sk else 0,
                path=list(rp.path), description=str(e.get("description") or ""), root_cause=str(e.get("root_cause") or ""),
                evidence=str(e.get("evidence") or ""), analysis_type="reachability"))
        
        return results

    def confirm_for_file(self, target_file, paths, graph, *, max_workers=4, progress_callback=None):
        target_file = str(target_file)
        paths = _dedupe_paths(paths)
        if not paths:
            return []

        batches = list(_chunked(paths, 8))
        total = len(batches)
        all_findings = []
        done = 0

        if progress_callback:
            progress_callback({"event": "file_confirmation_start", "file": target_file, "total": total})

        with ThreadPoolExecutor(max_workers=max(1, min(max_workers, total))) as ex:
            futs = {
                submit_with_current_context(ex, self._confirm_file_batch, target_file, batch, graph): idx
                for idx, batch in enumerate(batches)
            }

            for fut in as_completed(futs):
                done += 1
                try:
                    all_findings.extend(fut.result())
                except Exception as e:
                    logger.warning(f"Error confirming file-focused paths for {target_file}: {e}")
                if progress_callback:
                    progress_callback({"event": "file_confirmation_progress", "file": target_file, "completed": done, "total": total})

        if progress_callback:
            progress_callback({"event": "file_confirmation_done", "file": target_file, "confirmed": len(all_findings)})
        return all_findings

    def _confirm_file_batch(self, target_file, batch, graph):
        needed = {}
        target_nodes = {}
        related_nodes = {}

        for p in batch:
            for u in p.path:
                n = graph.get_node(u)
                if not n:
                    continue
                needed[u] = n
                if n.file_path == target_file:
                    target_nodes[u] = n
                else:
                    related_nodes[u] = n

        ps = ["== CANDIDATE PATHS =="]

        for i, p in enumerate(batch):
            sn, sk = graph.get_node(p.source), graph.get_node(p.sink)
            ps.append(f"\nPath {i}:\n Chain: {' -> '.join(p.path)}")
            if sn:
                ps.append(f" Source: {sn.unique_name} (line {sn.line_number}) - {sn.source_reason}")
            if sk:
                ps.append(f" Sink: {sk.unique_name} (line {sk.line_number}) [{sk.sink_type}] - {sk.sink_reason}")

        target_code = ["-- Functions from target file implicated by the reachable paths --"]
        for u, n in target_nodes.items():
            body = _read_function_body(self._cb, n, 5000)
            if body:
                target_code.append(f"\n--- {u} (line {n.line_number}) ---\n{body}")

        related_code = ["-- Supporting code from the rest of the reachable paths --"]
        for u, n in related_nodes.items():
            body = _read_function_body(self._cb, n, 2500)
            if body:
                related_code.append(f"\n--- {u} (line {n.line_number}) ---\n{body}")

        kw = self._u.hooks.chat_model_kwargs()
        chat = self._p.get_chat_model(model=self._m, max_tokens=self._t, temperature=0.1, **kw)

        prompt = ChatPromptTemplate.from_messages([
            ("system", _FILE_CONFIRM_SYS),
            ("user", _FILE_CONFIRM_USR)
        ])

        raw = (prompt | chat | StrOutputParser()).invoke(
            {
                "target_file": target_file,
                "paths_section": "\n".join(ps),
                "target_file_code": "\n".join(target_code),
                "related_code_section": "\n".join(related_code),
            }
        ).strip()

        parsed = parse_json_output(raw)
        if not isinstance(parsed, dict):
            return []

        fl = parsed.get("findings")
        if not isinstance(fl, list):
            return []

        results = []

        for e in fl:
            if not isinstance(e, dict) or not e.get("is_vulnerable"):
                continue

            idx = int(e.get("path_index", -1))
            if idx < 0 or idx >= len(batch):
                continue

            rp = batch[idx]
            sn = graph.get_node(rp.source)
            sk = graph.get_node(rp.sink)

            if sk and sk.file_path != target_file:
                continue

            results.append(
                VulnerabilityFinding(
                    id=uuid.uuid4().hex[:16],
                    vulnerability_type=str(e.get("vulnerability_type") or rp.sink_type or "other"),
                    severity=str(e.get("severity") or "medium"),
                    confidence=str(e.get("confidence") or "medium"),
                    source_function=rp.source,
                    source_file=sn.file_path if sn else "",
                    source_line=sn.line_number if sn else 0,
                    sink_function=rp.sink,
                    sink_file=sk.file_path if sk else "",
                    sink_line=sk.line_number if sk else 0,
                    path=list(rp.path),
                    description=str(e.get("description") or ""),
                    root_cause=str(e.get("root_cause") or ""),
                    evidence=str(e.get("evidence") or ""),
                    analysis_type="reachability",
                )
            )

        return results
   


# supplementary analyzer

_RESOURCE_KW = frozenset({"free", "malloc", "calloc", "realloc", "close", "destroy", "release", "delete", "munmap", "unref"})
_AUTH_KW = frozenset({"auth", "login", "access", "permit", "allow", "deny", "credential", "password", "key", "secret", "token", "check", "verify"})


# first pass, infra funciton

_INTRA_ANALYSIS_SYS = """\
You are a security analyst specializing in C and C++ code.

Examine each function bellow for bugs WITHIN the funciton itself.

Look for:
- Buffer overflows (e.g. unchecked memcpy, strcpy, sprintf, gets, etc.)
- Use after free or double free (e.g. free called multiple times on the same pointer, or pointer used after being freed)
- Null dereferences (e.g. pointer dereferenced without null check after allocation or lookup)
- Command injection (e.g. system, exec, popen called with attacker controlled input or
constructed strings)
- Format string vulnerabilities (e.g. format strings built from variables)
- Integer overflows (e.g. arithmetic on size or index variables that could wrap)
- Path traversal (e.g. file open with paths derived from untrusted input)
- Race conditions (e.g. access to shared resources without proper synchronization)
- Uninitialized memory usage (e.g. use of variables that may not have been initialized)
- Type confusion (e.g. casting void pointers to concrete types without validation)
- Authentication and access control issues (e.g. functions with names or contexts suggesting they handle auth or access control but have suspicious patterns)
- Other common C/C++ bugs (e.g. off-by-one errors, incorrect use of APIs, etc.)


Return ONLY valid JSON:
{{"findings": [{{"vulnerability_type": "buffer_overflow", "severity": "high", "confidence": "high", "function_name": "...", "line": int, "description": "...", "root_cause": "...", "evidence": "..." }}]}}

Return {{"findings": []}} if no issues found. Be thorough."""


_INTRA_USR = "File: {file_path}\n\n{functions_code}"



# lifecycle analyzer


_LIFE_SYS = """\

You are a security analyst specializing in C and C++ code.

Specifically you are analyzinf codebase for USE AFTER FREE, DANGLING POINTER AND LIFETIME BUGS
spanning MULTIPLE functions.

Below are ALL functions. Analyze their INTERACTIONS:

1. USE AFTER FREE AND DANGLING POINTERS: Look for pointers that are freed in one function but still used in another function that could be reachable from it. Consider indirect calls and function pointers as well.
2. LIFETIME ISSUES: Look for resources (memory, file descriptors, locks, etc.) that are acquired in one function and released in another, and check if there are any paths where the resource could be used after being released or not released at all.

Return ONLY valid JSON:
{{"findings": [{{"vulnerability_type": "use_after_free", "severity": "high", "confidence": "high", "source_function": "...", "source_line": int, "sink_function": "...", "sink_line": int, "description": "...", "root_cause": "...", "evidence": "..." }}]}}

Return {{"findings": []}} if no issues found. Be thorough."""


_LIFE_USR = "{all_functions_code}"


# Resource ownership and pointer safety analyzer


_OWN_SYS = """\

You are a security analyst specializing in C and C++ code. 

You are analyzing resource ownership, pointer safety, and potential memory management issues in the following functions and their interactions.

Examine all functions below for:

1. Double free, double close across functions: Look for resources (memory, file descriptors, etc.) that are released multiple times across different functions that could be reachable from each other.
2. Use after realloc or stale pointers: Look for pointers that are realloced in one function but still used in another function that could be reachable from it without proper handling.
3. Callback and event handler safety: Look for functions that are likely to be used as callbacks or event handlers and check if they properly handle resources and pointers considering they could be invoked in various contexts.
4. Refcount imbalances: Look for patterns suggesting reference counting of resources and check for potential imbalances (e.g. missing increments or decrements) across functions.

Return only valid JSON:
{{"findings": [{{"vulnerability_type": "double_free", "severity": "high", "confidence": "high", "source_function": "...", "source_line": int, "sink_function": "...", "sink_line": int, "description": "...", "root_cause": "...", "evidence": "..." }}]}}

Return {{"findings": []}} if no issues found. Be thorough."""

_OWN_USR = "{all_functions_code}"

# semantic and data correctness

_SEM_SYS = """\

You are a security analyst specializing in C and C++ code. 

You are analytically examining the following functions and their interactions for potential semantic bugs and data correctness issues that could lead to security vulnerabilities.

Examine all funcitons below for:

1. Boolean coercion of rich returns: Look for functions that return rich status or error codes but are used in a boolean context, which could lead to incorrect assumptions about success or failure.
2. Type confusion and void pointer misuse: Look for patterns of void pointer usage and check if there are any potential type confusion issues or unsafe casts across functions.
3. Wrong enum or constant usage: Look for functions that take enums or constants as arguments and check if there are any suspicious patterns of usage that could indicate incorrect assumptions or logic errors.
4. Wrong struct field passed: Look for functions that take struct pointers as arguments and check if there are any suspicious patterns of field access or passing that could indicate incorrect assumptions or logic errors.
5. length off by one in metadata or code: Look for patterns of length or size handling that could indicate off-by-one errors, such as loops iterating one too many times, buffer sizes that are not properly accounted for, or metadata that does not match the actual data structure.
6. array index bounds confusion: Look for patterns of array indexing that could indicate confusion about bounds, such as using the wrong variable for the size, mixing up indices, or not properly checking bounds before access.
7. integer overflow leading to data corruption: Look for patterns of integer arithmetic that could lead to overflow and subsequent data corruption, such as calculating buffer sizes, indices, or offsets without proper checks.
8. uninitialized data leading to logic errors: Look for patterns of variable usage that could indicate uninitialized data being used in a way that affects program logic, such as conditionals, loops, or function arguments.

return only valid JSON:
{{"findings": [{{"vulnerability_type": "boolean_coercion", "severity": "medium", "confidence": "medium", "source_function": "...", "source_line": int, "sink_function": "...", "sink_line": int, "description": "...", "root_cause": "...", "evidence": "..." }}]}}

Return {{"findings": []}} if no issues found. Be thorough."""


_SEM_USR = "{all_functions_code}"





class SupplementaryAnalyzer:
    def __init__(self, llm_provider, audit_model, strong_model, usage_runtime, codebase_path,
                 audit_max_tokens=8192, strong_max_tokens=16384):
        self._p = llm_provider
        self._am=audit_model
        self._sm=strong_model
        self._u = usage_runtime
        self._cb = os.path.abspath(codebase_path)
        self._at = audit_max_tokens
        self._st = strong_max_tokens

    def analyze(self, graph, *, max_workers=8, progress_callback=None):
        findings = []

        findings.extend(self._pass_infra(graph, max_workers, progress_callback))
        findings.extend(self._pass_lifecycle(graph, progress_callback))
        findings.extend(self._pass_ownership(graph, progress_callback))
        findings.extend(self._pass_semantic(graph, progress_callback))

        if progress_callback:
            by_type = defaultdict(int)
            for f in findings:
                by_type[f.analysis_type] += 1
            progress_callback({"event": "supplementary_done", **dict(by_type), "total": len(findings)})
        return findings
    
    # intra function analysis

    def _pass_infra(self, graph, max_workers, cb):
        targets = self._select_intra_targets(graph)
        if not targets: return []

        groups = defaultdict(list)

        for t in targets:
            groups[t.file_path].append(t)

        if cb:
            cb({"event": "intra_audit_start", "files": len(groups), "functions": len(targets)})
        
        results = []

        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futs = {submit_with_current_context(ex, self._audit_file, fp, fns): fp for fp, fns in groups.items()}
            done = 0

            for fut in as_completed(futs):
                fp = futs[fut]
                done += 1
                try:
                    results.extend(fut.result())
                except Exception as e:
                    logger.warning(f"Intra audit fail. Error auditing file {fp}: {e}")
                if cb:
                        cb({"event": "intra_audit_progress", "completed": done, "total": len(groups), "file": fp})
        return results


    def _select_intra_targets(self, graph):
        seen = set()
        targets = []

        for n in graph.nodes.values():
            nl = n.name.lower()
            cl = [c.lower() for c in n.calls]
            ac = nl + " " + " ".join(cl)

            if n.is_sink or n.is_source or any(k in ac for k in _RESOURCE_KW) or any(k in ac for k in _AUTH_KW) or "goto" in ac:
                if n.unique_name not in seen:
                    seen.add(n.unique_name)
                    targets.append(n)
        return targets
    

    def _audit_file(self, file_path, functions):
        bodies = []

        for fn in functions:
            b = _read_function_body(self._cb, fn, 4096)
            if b: bodies.append(f"--- {fn.unique_name} (line {fn.line_number}) ---\n{b}")
        if not bodies:
            return []
        
        kw = self._u.hooks.chat_model_kwargs()
        chat = self._p.get_chat_model(model=self._am, max_tokens=self._at, temperature=0.1, **kw)
        prompt = ChatPromptTemplate.from_messages([
            ("system", _INTRA_ANALYSIS_SYS),
            ("user", _INTRA_USR)
        ])
        raw = (prompt | chat | StrOutputParser()).invoke({"file_path": file_path, "functions_code": "\n\n".join(bodies)}).strip()
        return self._parse_intra(raw, functions)
    

    def _parse_intra(self, raw, functions):
        parsed = parse_json_output(raw)
        if not isinstance(parsed, dict):
            return []
        
        fl = parsed.get("findings")
        if not isinstance(fl, list):
            return []
        
        lk = {fn.unique_name: fn for fn in functions}
        results = []

        for e in fl:
            if not isinstance(e, dict):
                continue
            fn = _lookup_fn(str(e.get("function_name") or ""), lk, {f.unique_name: f for f in functions}, functions)

            if not fn: fn = functions[0]
            line = fn.line_number

            try:
                line = max(1, int(e.get("line", line)))
            except:
                pass

            results.append(VulnerabilityFinding(
                id=uuid.uuid4().hex[:16], vulnerability_type=str(e.get("vulnerability_type") or "other"), severity=str(e.get("severity") or "medium"), confidence=str(e.get("confidence") or "medium"),
                source_function=fn.unique_name, source_file=fn.file_path, source_line=line, sink_function=fn.unique_name, sink_file=fn.file_path, sink_line=line,
                description=str(e.get("description") or ""), root_cause=str(e.get("root_cause") or ""), evidence=str(e.get("evidence") or ""), analysis_type="intra_function"))
        return results
    


    # lifecycle analysis

    def _pass_lifecycle(self, graph, cb):
        fns = list(graph.nodes.values())
        if not fns: return []

        if cb:
            cb({"event": "lifecycle_audit_start", "functions": len(fns)})
        
        code = _build_all_code(self._cb, fns)

        if not code:
            return []
        
        kw = self._u.hooks.chat_model_kwargs()

        chat = self._p.get_chat_model(model=self._am, max_tokens=self._at, temperature=0.1, **kw)
        prompt = ChatPromptTemplate.from_messages([
            ("system", _LIFE_SYS),
            ("user", _LIFE_USR)
        ])

        raw = (prompt | chat | StrOutputParser()).invoke({"all_functions_code": code})
        results = self._parse_cross(raw, fns, "lifecycle", "free_function", "use_function")

        if cb:
            cb({"event": "lifecycle_audit_done", "findings": len(results)})

        return results
    

    # ownership and pointer safety analysis

    def _pass_ownership(self, graph, cb):

        fns = list(graph.nodes.values())
        if not fns: return []

        if cb:
            cb({"event": "ownership_audit_start", "functions": len(fns)})
        
        code = _build_all_code(self._cb, fns)

        if not code:
            return []
        
        kw = self._u.hooks.chat_model_kwargs()

        chat = self._p.get_chat_model(model=self._am, max_tokens=self._at, temperature=0.1, **kw)
        prompt = ChatPromptTemplate.from_messages([
            ("system", _OWN_SYS),
            ("user", _OWN_USR)
        ])

        raw = (prompt | chat | StrOutputParser()).invoke({"all_functions_code": code})
        results = self._parse_cross(raw, fns, "ownership", "release_function", "use_function")

        if cb:
            cb({"event": "ownership_audit_done", "findings": len(results)})

        return results
    
    # semantic and data correctness analysis

    def _pass_semantic(self, graph, cb):
        fns = list(graph.nodes.values())
        if not fns: return []

        if cb:
            cb({"event": "semantic_audit_start", "functions": len(fns)})
        
        code = _build_all_code(self._cb, fns)

        if not code:
            return []
        
        kw = self._u.hooks.chat_model_kwargs()

        chat = self._p.get_chat_model(model=self._am, max_tokens=self._at, temperature=0.1, **kw)
        prompt = ChatPromptTemplate.from_messages([
            ("system", _SEM_SYS),
            ("user", _SEM_USR)
        ])

        raw = (prompt | chat | StrOutputParser()).invoke({"all_functions_code": code})
        results = self._parse_semantic(raw, fns)

        if cb:
            cb({"event": "semantic_audit_done", "findings": len(results)})

        return results
    


    # shared parsers

    def _parse_cross(self, raw, all_fns, analysis_type, key_a, key_b):

        parsed = parse_json_output(raw)
        if not isinstance(parsed, dict):
            return []
        
        fl = parsed.get("findings")

        if not isinstance(fl, list):
            return []
        
        bn = {fn.name: fn for fn in all_fns}
        bu = {fn.unique_name: fn for fn in all_fns}
        results = []

        for e in fl:
            if not isinstance(e, dict):
                continue

            fa = _lookup_fn(str(e.get(key_a) or ""), bn, bu, all_fns)
            fb = _lookup_fn(str(e.get(key_b) or ""), bn, bu, all_fns)

            if not fa or not fb:
                continue

            results.append(VulnerabilityFinding(
                id=uuid.uuid4().hex[:16], vulnerability_type=str(e.get("vulnerability_type") or "other"), severity=str(e.get("severity") or "medium"), confidence=str(e.get("confidence") or "medium"),
                source_function=fa.unique_name, source_file=fa.file_path, source_line=fa.line_number, sink_function=fb.unique_name, sink_file=fb.file_path, sink_line=fb.line_number,
                description=str(e.get("description") or ""), root_cause=str(e.get("root_cause") or ""), evidence=str(e.get("evidence") or ""), analysis_type=analysis_type))
        return results
    

    def _parse_semantic(self, raw, all_fns):
        parsed = parse_json_output(raw)

        if not isinstance(parsed, dict):
            return []
        
        fl = parsed.get("findings")
        if not isinstance(fl, list):
            return []
        
        bn = {fn.name: fn for fn in all_fns}
        bu = {fn.unique_name: fn for fn in all_fns}
        results = []

        for e in fl:
            if not isinstance(e, dict):
                continue

            fn = _lookup_fn(str(e.get("function_name") or ""), bn, bu, all_fns)
            rf = _lookup_fn(str(e.get("related_function") or ""), bn, bu, all_fns)

            if not fn:
                continue

            src_fn = rf or fn
            results.append(VulnerabilityFinding(
                id=uuid.uuid4().hex[:16], vulnerability_type=str(e.get("vulnerability_type") or "other"), severity=str(e.get("severity") or "medium"), confidence=str(e.get("confidence") or "medium"),
                source_function=src_fn.unique_name, source_file=src_fn.file_path, source_line=src_fn.line_number, sink_function=fn.unique_name, sink_file=fn.file_path, sink_line=fn.line_number,
                description=str(e.get("description") or ""), root_cause=str(e.get("root_cause") or ""), evidence=str(e.get("evidence") or ""), analysis_type="semantic"))
        return results
    


# deduplicator


class Deduplicator:
    @staticmethod
    def deduplicate(findings, *, max_per_sink=3):
        if not findings:
            return [], 0, 0
        
        groups = defaultdict(list)
        for f in findings:
            groups[(f.sink_function, f.vulnerability_type)].append(f)

        selected = []

        for g in groups.values():
            selected.extend(_select_diverse(g, max_per_sink))
        
        return selected, len(findings), len(findings) - len(selected)
    

def _select_diverse(findings, limit):
    if len(findings)<=limit:
        return list(findings)
    
    sev = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}

    fs = sorted(findings, key=lambda f: (sev.get(f.severity, 5), len(f.path)))
    sel, cov = [], set()

    for f in fs:
        if len(sel)>=limit:
            break
        if not sel or len(set(f.path) - cov) > 0:
            sel.append(f)
            cov.update(f.path)

    if len(sel)<limit:
        ids = {id(f) for f in sel}
        for f in fs:
            if id(f) not in ids: sel.append(f)
            if len(sel) >= limit: break
    
    return sel
        

# service

_C_CPP_EXTS = frozenset({".c", ".h", ".cc", ".cpp", ".hpp", ".hh", ".hxx", ".cxx"})
DEFAULT_OUTPUT_DIR = "metis_reachability_results"

class ReachabilityService:
    def __init__(self, config, repository, llm_provider, usage_runtime):
        self._config = config
        self._repository = repository
        self._llm_provider = llm_provider
        self._usage_runtime = usage_runtime
        self._graph_cache: dict[tuple, tuple[ReachabilityGraph, list[ReachabilityPath]]] = {}
        self._file_review_cache: dict[tuple, dict] = {}
        self._cache_lock = threading.Lock()

    def get_c_cpp_files(self):
        return [f for f in self._repository.get_code_files() if os.path.splitext(f)[1].lower() in _C_CPP_EXTS]
    
    def build_graph(self, files, *, extraction_model="gpt-4.1-mini", max_workers=8, progress_callback=None):
        return GraphBuilder(self._llm_provider, extraction_model, self._usage_runtime).build(
            files, self._config.codebase_path, max_workers=max_workers, progress_callback=progress_callback
        )
    
    def trace_paths(self, graph, *, max_path_length=25):
        return PathTracer(graph, max_path_length=max_path_length).find_all_paths()
    
    def run_supplementary_analysis(self, graph, *, audit_model="gpt-4.1-mini", strong_model=None,
                    max_workers=8, progress_callback=None):
        sm = strong_model or self._config.llama_query_model
        return SupplementaryAnalyzer(
            self._llm_provider, audit_model, sm, self._usage_runtime, self._config.codebase_path
        ).analyze(graph, max_workers=max_workers, progress_callback=progress_callback)
    
    def confirm_paths(self, paths, graph, *, confirmation_model=None, max_workers=8,
                      output_path=None, progress_callback=None):
        cm = confirmation_model or self._config.llama_query_model
        return VulnerabilityConfirmer(self._llm_provider, cm, self._usage_runtime, self._config.codebase_path).confirm_parallel(
            paths, graph, max_workers=max_workers, output_path=output_path, progress_callback=progress_callback)

    def confirm_paths_for_file(
        self,
        target_file,
        paths,
        graph,
        *,
        confirmation_model=None,
        max_workers=8,
        progress_callback=None,
    ):
        cm = confirmation_model or self._config.llama_query_model
        return VulnerabilityConfirmer(
            self._llm_provider,
            cm,
            self._usage_runtime,
            self._config.codebase_path,
        ).confirm_for_file(
            target_file,
            paths,
            graph,
            max_workers=max_workers,
            progress_callback=progress_callback,
        )

    def _graph_cache_key(self, *, extraction_model, max_workers, max_paths, max_path_length):
        return (
            str(extraction_model or ""),
            int(max_workers),
            int(max_paths),
            int(max_path_length),
        )

    def _file_review_cache_key(
        self,
        *,
        target_file,
        extraction_model,
        confirmation_model,
        max_workers,
        max_paths,
        max_paths_per_sink,
        max_path_length,
    ):
        return (
            str(target_file),
            str(extraction_model or ""),
            str(confirmation_model or self._config.llama_query_model or ""),
            int(max_workers),
            int(max_paths),
            int(max_paths_per_sink),
            int(max_path_length),
        )

    def _ensure_graph_and_paths(
        self,
        *,
        extraction_model="gpt-4.1-mini",
        max_workers=8,
        max_paths=0,
        max_path_length=25,
        progress_callback=None,
    ):
        key = self._graph_cache_key(
            extraction_model=extraction_model,
            max_workers=max_workers,
            max_paths=max_paths,
            max_path_length=max_path_length,
        )
        with self._cache_lock:
            cached = self._graph_cache.get(key)
        if cached is not None:
            return cached

        files = self.get_c_cpp_files()
        if not files:
            graph = ReachabilityGraph()
            paths = []
        else:
            graph = self.build_graph(
                files,
                extraction_model=extraction_model,
                max_workers=max_workers,
                progress_callback=progress_callback,
            )
            if graph.node_count() == 0:
                paths = []
            else:
                paths = self.trace_paths(graph, max_path_length=max_path_length)
                if max_paths > 0:
                    paths = paths[:max_paths]
                paths = _dedupe_paths(paths)

        cached = (graph, paths)
        with self._cache_lock:
            self._graph_cache[key] = cached
        return cached

    def _normalize_target_file(self, file_path):
        base_path = os.path.abspath(self._config.codebase_path)
        abs_target = (
            file_path if os.path.isabs(file_path) else os.path.join(base_path, file_path)
        )
        abs_target = os.path.abspath(abs_target)
        relative_target = os.path.relpath(abs_target, base_path)
        return abs_target, relative_target

    def _paths_for_target_file(self, graph, paths, target_file):
        results = []
        for p in paths:
            sink = graph.get_node(p.sink)
            if sink and sink.file_path == target_file:
                results.append(p)
        return _dedupe_paths(results)

    def review_codebase(
        self,
        *,
        extraction_model="gpt-4.1-mini",
        confirmation_model=None,
        max_workers=8,
        max_paths=0,
        max_paths_per_sink=3,
        max_path_length=25,
        progress_callback=None,
    ):
        graph, paths = self._ensure_graph_and_paths(
            extraction_model=extraction_model,
            max_workers=max_workers,
            max_paths=max_paths,
            max_path_length=max_path_length,
            progress_callback=progress_callback,
        )

        if graph.node_count() == 0 or not paths:
            return []

        files = sorted({graph.get_node(p.sink).file_path for p in paths if graph.get_node(p.sink)})
        results = []

        if progress_callback:
            progress_callback({"event": "file_review_start", "files": len(files)})

        completed = 0
        for target_file in files:
            review = self.review_single_file_from_codebase(
                target_file,
                extraction_model=extraction_model,
                confirmation_model=confirmation_model,
                max_workers=max_workers,
                max_paths=max_paths,
                max_paths_per_sink=max_paths_per_sink,
                max_path_length=max_path_length,
                progress_callback=progress_callback,
            )
            completed += 1
            if review and review.get("reviews"):
                results.append(review)
            if progress_callback:
                progress_callback(
                    {
                        "event": "file_review_progress",
                        "completed": completed,
                        "total": len(files),
                        "file": target_file,
                    }
                )

        if progress_callback:
            progress_callback({"event": "file_review_done", "files": len(results)})

        return results

    def review_single_file_from_codebase(
        self,
        file_path,
        *,
        extraction_model="gpt-4.1-mini",
        confirmation_model=None,
        max_workers=8,
        max_paths=0,
        max_paths_per_sink=3,
        max_path_length=25,
        progress_callback=None,
    ):
        abs_target, relative_target = self._normalize_target_file(file_path)
        cache_key = self._file_review_cache_key(
            target_file=relative_target,
            extraction_model=extraction_model,
            confirmation_model=confirmation_model,
            max_workers=max_workers,
            max_paths=max_paths,
            max_paths_per_sink=max_paths_per_sink,
            max_path_length=max_path_length,
        )

        with self._cache_lock:
            cached = self._file_review_cache.get(cache_key)
        if cached is not None:
            return dict(cached)

        graph, paths = self._ensure_graph_and_paths(
            extraction_model=extraction_model,
            max_workers=max_workers,
            max_paths=max_paths,
            max_path_length=max_path_length,
            progress_callback=progress_callback,
        )

        if graph.node_count() == 0 or not paths:
            review = {
                "file": relative_target,
                "file_path": abs_target,
                "reviews": [],
            }
            with self._cache_lock:
                self._file_review_cache[cache_key] = review
            return dict(review)

        target_paths = self._paths_for_target_file(graph, paths, relative_target)
        if not target_paths:
            review = {
                "file": relative_target,
                "file_path": abs_target,
                "reviews": [],
            }
            with self._cache_lock:
                self._file_review_cache[cache_key] = review
            return dict(review)

        file_findings = self.confirm_paths_for_file(
            relative_target,
            target_paths,
            graph,
            confirmation_model=confirmation_model,
            max_workers=max_workers,
            progress_callback=progress_callback,
        )

        deduped, _total, _removed = Deduplicator.deduplicate(
            file_findings,
            max_per_sink=max_paths_per_sink,
        )

        grouped = self._group_findings_as_reviews(deduped)
        review = None
        for item in grouped:
            if item.get("file") == relative_target:
                review = item
                break

        if review is None:
            review = {
                "file": relative_target,
                "file_path": abs_target,
                "reviews": [],
            }

        with self._cache_lock:
            self._file_review_cache[cache_key] = review
        return dict(review)

    def _group_findings_as_reviews(self, findings):
        grouped = defaultdict(list)
        base_path = os.path.abspath(self._config.codebase_path)

        for finding in findings:
            rel_file = finding.sink_file or finding.source_file
            if not rel_file:
                continue
            abs_file = rel_file if os.path.isabs(rel_file) else os.path.join(base_path, rel_file)
            grouped[(rel_file, os.path.abspath(abs_file))].append(self._finding_to_review(finding))

        results = []
        for (rel_file, abs_file), reviews in grouped.items():
            results.append(
                {
                    "file": rel_file,
                    "file_path": abs_file,
                    "reviews": reviews,
                }
            )
        return results

    def _finding_to_review(self, finding):
        line_number = int(finding.sink_line or finding.source_line or 1)
        issue = (
            str(finding.description).strip()
            if str(finding.description or "").strip()
            else f"{finding.vulnerability_type.replace('_', ' ')} in {finding.sink_function}"
        )

        reasoning_parts = []
        if str(finding.evidence or "").strip():
            reasoning_parts.append(str(finding.evidence).strip())
        if finding.path:
            reasoning_parts.append(f"Reachability path: {' -> '.join(finding.path)}")
        if str(finding.root_cause or "").strip():
            reasoning_parts.append(f"Root cause: {str(finding.root_cause).strip()}")

        code_snippet = ""
        target_file = finding.sink_file or finding.source_file
        if target_file:
            code_snippet = _read_line_context(
                self._config.codebase_path,
                target_file,
                line_number,
                context=2,
            )

        return {
            "issue": issue,
            "line_number": line_number,
            "code_snippet": code_snippet,
            "cwe": _VULN_TO_CWE.get(str(finding.vulnerability_type or "").strip()),
            "severity": _severity_title(finding.severity, "Medium"),
            "confidence": _severity_title(finding.confidence, "Medium"),
            "reasoning": "\n".join(reasoning_parts),
            "mitigation": str(finding.root_cause or "").strip(),
        }

    @staticmethod
    def deduplicate_and_write(findings, output_path, *, max_paths_per_sink=3):
        deduped, total, removed = Deduplicator.deduplicate(findings, max_per_sink=max_paths_per_sink)
        _write_jsonl(output_path, deduped)
        return deduped, total, removed
    

def _write_jsonl(path, findings):
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        for f in findings: fh.write(json.dumps(f.to_dict(), ensure_ascii=False) + "\n")