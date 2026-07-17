#!/usr/bin/env python3
"""Generate and apply safe cross-instance GhidraMCP comparison plans."""

import argparse
import json
import os
import re
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path


managed_dir = Path()
plan_version = 0
retention = 0
engine_arguments = []


class CompareError(RuntimeError):
    pass


def request(port, method, path, params=None, body=None, timeout=130):
    query = ""
    if params:
        query = "?" + urllib.parse.urlencode(
            {key: value for key, value in params.items() if value is not None}
        )
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body, separators=(",", ":")).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}{query}",
        data=data,
        headers=headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            text = response.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError) as exc:
        raise CompareError(f"{method} {path} failed on MCP port {port}: {exc}") from exc
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return text
    if isinstance(value, dict) and set(value) == {"data"}:
        return value["data"]
    if isinstance(value, dict) and value.get("error"):
        raise CompareError(f"{method} {path} failed on MCP port {port}: {value['error']}")
    return value


def require_endpoints(port, endpoints):
    schema = request(port, "GET", "/mcp/schema", timeout=30)
    serialized = json.dumps(schema) if not isinstance(schema, str) else schema
    missing = [endpoint for endpoint in endpoints if endpoint not in serialized]
    if missing:
        raise CompareError(
            f"MCP port {port} is missing required endpoints: {', '.join(missing)}"
        )


def instance_info(port):
    info = request(port, "GET", "/mcp/instance_info", timeout=5)
    if isinstance(info, dict) and isinstance(info.get("data"), dict):
        info = info["data"]
    if not isinstance(info, dict):
        raise CompareError(f"MCP port {port} returned invalid instance metadata")
    return info


def line_list(value):
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        for key in ("items", "results", "data"):
            if isinstance(value.get(key), list):
                return value[key]
        return []
    if not isinstance(value, str):
        return []
    stripped = value.strip()
    if not stripped or stripped.lower().startswith("no "):
        return []
    return [line for line in stripped.splitlines() if line.strip()]


def paged_lines(port, path, extra=None, page_size=1000):
    rows = []
    offset = 0
    while True:
        params = {"offset": offset, "limit": page_size}
        if extra:
            params.update(extra)
        page = line_list(request(port, "GET", path, params=params))
        rows.extend(page)
        if len(page) < page_size:
            break
        offset += len(page)
    return rows


def function_hashes(port):
    rows = []
    offset = 0
    while True:
        page = request(
            port,
            "GET",
            "/get_bulk_function_hashes",
            params={"offset": offset, "limit": 500, "filter": ""},
        )
        if not isinstance(page, dict) or not isinstance(page.get("functions"), list):
            raise CompareError(f"MCP port {port} returned invalid bulk function hashes")
        rows.extend(page["functions"])
        returned = int(page.get("returned", len(page["functions"])))
        total = int(page.get("total_matching", len(rows)))
        if returned == 0 or len(rows) >= total:
            break
        offset += returned
    return rows


def parse_type_rows(rows):
    parsed = []
    for row in rows:
        if not isinstance(row, str):
            continue
        parts = [part.strip() for part in row.split("|")]
        if len(parts) < 4:
            continue
        size_match = re.match(r"(\d+|variable)\s+bytes", parts[2])
        parsed.append(
            {
                "name": parts[0],
                "category": parts[1],
                "size": int(size_match.group(1)) if size_match and size_match.group(1).isdigit() else None,
                "path": parts[3],
            }
        )
    return parsed


def all_types(port, category=""):
    return parse_type_rows(
        paged_lines(port, "/list_data_types", {"category": category})
    )


def parse_struct_layout(text, fallback):
    if not isinstance(text, str) or "Data type is not a structure" in text or "Structure not found" in text:
        return None
    name_match = re.search(r"^Structure:\s*(.+)$", text, re.MULTILINE)
    size_match = re.search(r"^Size:\s*(\d+)\s+bytes$", text, re.MULTILINE)
    if not name_match or not size_match:
        return None
    fields = []
    in_layout = False
    for line in text.splitlines():
        if line.strip() == "-------|------|------|-----":
            in_layout = True
            continue
        if not in_layout or not line.strip():
            continue
        parts = [part.strip() for part in line.split("|")]
        if len(parts) != 4 or not parts[0].isdigit() or not parts[1].isdigit():
            continue
        fields.append(
            {
                "offset": int(parts[0]),
                "size": int(parts[1]),
                "type": parts[2],
                "name": parts[3] if parts[3] != "(unnamed)" else f"field_{int(parts[0]):x}",
            }
        )
    return {
        **fallback,
        "name": name_match.group(1).strip(),
        "size": int(size_match.group(1)),
        "fields": fields,
    }


def parse_enum_values(text, fallback):
    if not isinstance(text, str) or "Data type is not an enumeration" in text or "Enumeration not found" in text:
        return None
    name_match = re.search(r"^Enumeration:\s*(.+)$", text, re.MULTILINE)
    size_match = re.search(r"^Size:\s*(\d+)\s+bytes$", text, re.MULTILINE)
    if not name_match or not size_match:
        return None
    values = {}
    in_values = False
    for line in text.splitlines():
        if line.strip() == "-----|------":
            in_values = True
            continue
        if not in_values or not line.strip() or "|" not in line:
            continue
        name, value = [part.strip() for part in line.split("|", 1)]
        decimal = value.split()[0]
        try:
            values[name] = int(decimal, 10)
        except ValueError:
            continue
    return {
        **fallback,
        "name": name_match.group(1).strip(),
        "size": int(size_match.group(1)),
        "values": values,
    }


def typed_inventory(port, kind):
    candidates = all_types(port, kind)
    by_key = {}
    for candidate in candidates:
        if kind == "struct":
            detail = parse_struct_layout(
                request(port, "GET", "/get_struct_layout", {"struct_name": candidate["name"]}),
                candidate,
            )
        else:
            detail = parse_enum_values(
                request(port, "GET", "/get_enum_values", {"enum_name": candidate["name"]}),
                candidate,
            )
        if detail:
            by_key[(detail["path"], detail["name"])] = detail
    return list(by_key.values())


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def relevant_documentation(doc):
    keys = (
        "function_name",
        "return_type",
        "calling_convention",
        "plate_comment",
        "parameters",
        "comments",
        "labels",
    )
    return {key: doc.get(key) for key in keys}


def autogenerated(name):
    return bool(re.match(r"^(FUN|LAB|DAT|UNK|SUB|EXT|OFF|switchD)_[0-9a-fA-F]+$", name or ""))


def undefined_type(name):
    return not name or name.lower().startswith("undefined")


def generic_parameter(name):
    return not name or name.startswith("param_") or name in {"this", "this_"}


def default_calling_convention(name):
    return not name or name in {"unknown", "default", "__unknown"}


def documentation_delta(source, target):
    payload = {"target_address": target["source_address"]}
    conflicts = []
    changed = []

    source_name = source.get("function_name", "")
    target_name = target.get("function_name", "")
    if source_name and not autogenerated(source_name):
        if autogenerated(target_name):
            payload["function_name"] = source_name
            changed.append("function_name")
        elif source_name != target_name:
            conflicts.append("function_name")

    source_return = source.get("return_type", "")
    target_return = target.get("return_type", "")
    if not undefined_type(source_return):
        if undefined_type(target_return):
            payload["return_type"] = source_return
            changed.append("return_type")
        elif source_return != target_return:
            conflicts.append("return_type")

    source_cc = source.get("calling_convention", "")
    target_cc = target.get("calling_convention", "")
    if not default_calling_convention(source_cc):
        if default_calling_convention(target_cc):
            payload["calling_convention"] = source_cc
            changed.append("calling_convention")
        elif source_cc != target_cc:
            conflicts.append("calling_convention")

    source_plate = source.get("plate_comment")
    target_plate = target.get("plate_comment")
    if source_plate:
        if not target_plate:
            payload["plate_comment"] = source_plate
            changed.append("plate_comment")
        elif source_plate != target_plate:
            conflicts.append("plate_comment")

    source_params = {int(item.get("ordinal", -1)): item for item in source.get("parameters", [])}
    target_params = {int(item.get("ordinal", -1)): item for item in target.get("parameters", [])}
    merged_params = []
    for ordinal, source_param in sorted(source_params.items()):
        target_param = target_params.get(ordinal)
        if not target_param:
            conflicts.append(f"parameter[{ordinal}]")
            continue
        merged = dict(target_param)
        param_changed = False
        source_param_name = source_param.get("name", "")
        target_param_name = target_param.get("name", "")
        if not generic_parameter(source_param_name):
            if generic_parameter(target_param_name):
                merged["name"] = source_param_name
                param_changed = True
            elif source_param_name != target_param_name:
                conflicts.append(f"parameter[{ordinal}].name")
        source_param_type = source_param.get("type", "")
        target_param_type = target_param.get("type", "")
        if not undefined_type(source_param_type):
            if undefined_type(target_param_type):
                merged["type"] = source_param_type
                param_changed = True
            elif source_param_type != target_param_type:
                conflicts.append(f"parameter[{ordinal}].type")
        if param_changed:
            merged_params.append(merged)
    if merged_params:
        payload["parameters"] = merged_params
        changed.append("parameters")

    target_comments = {
        int(item.get("relative_offset", -1)): item for item in target.get("comments", [])
    }
    comments = []
    for item in source.get("comments", []):
        offset = int(item.get("relative_offset", -1))
        current = target_comments.get(offset, {})
        merged = {"relative_offset": offset}
        item_changed = False
        for key in ("eol_comment", "pre_comment"):
            source_value = item.get(key)
            target_value = current.get(key)
            if source_value:
                if not target_value:
                    merged[key] = source_value
                    item_changed = True
                elif source_value != target_value:
                    conflicts.append(f"comments[{offset}].{key}")
        if item_changed:
            comments.append(merged)
    if comments:
        payload["comments"] = comments
        changed.append("comments")

    target_labels = {
        int(item.get("relative_offset", -1)): item.get("name")
        for item in target.get("labels", [])
    }
    labels = []
    for item in source.get("labels", []):
        offset = int(item.get("relative_offset", -1))
        name = item.get("name")
        current = target_labels.get(offset)
        if not current:
            labels.append({"relative_offset": offset, "name": name})
        elif current != name:
            conflicts.append(f"labels[{offset}]")
    if labels:
        payload["labels"] = labels
        changed.append("labels")

    return payload if changed else None, sorted(set(conflicts)), changed


def type_name_counts(types):
    return Counter(item["name"] for item in types)


def type_signature(item, kind):
    if kind == "struct":
        return canonical({"size": item["size"], "fields": item["fields"]})
    return canonical({"size": item["size"], "values": item["values"]})


def base_type(type_name):
    value = re.sub(r"\[[^]]*\]", "", type_name).replace("*", " ").strip()
    value = re.sub(r"\b(const|volatile|struct|enum|signed|unsigned)\b", "", value)
    value = re.sub(r"\s+", " ", value).strip()
    return value


def build_type_operations(source_types, target_types, target_all_types, kind):
    source_counts = type_name_counts(source_types)
    target_counts = type_name_counts(target_types)
    target_all_names = {item["name"] for item in target_all_types}
    target_by_name = {item["name"]: item for item in target_types if target_counts[item["name"]] == 1}
    operations = []
    conflicts = []
    pending = {}

    for item in source_types:
        name = item["name"]
        if source_counts[name] != 1:
            conflicts.append({"kind": kind, "name": name, "reason": "duplicate source name"})
            continue
        if target_counts[name] > 1:
            conflicts.append({"kind": kind, "name": name, "reason": "duplicate target name"})
            continue
        existing = target_by_name.get(name)
        if existing:
            if type_signature(item, kind) != type_signature(existing, kind):
                conflicts.append({"kind": kind, "name": name, "reason": "different target definition"})
            continue
        if name in target_all_names:
            conflicts.append({"kind": kind, "name": name, "reason": "target has a different type with the same name"})
            continue
        pending[name] = item

    if kind == "enum":
        for name in sorted(pending):
            item = pending[name]
            operations.append({"kind": "enum", "name": name, "definition": item})
        return operations, conflicts

    resolved = set(target_all_names)
    primitive_names = {
        "void", "char", "byte", "short", "int", "long", "long long", "float", "double",
        "bool", "uint", "ushort", "ulong", "undefined", "undefined1", "undefined2",
        "undefined4", "undefined8", "pointer", "wchar_t",
    }
    resolved.update(primitive_names)
    while pending:
        progressed = False
        for name in sorted(list(pending)):
            item = pending[name]
            dependencies = {
                base_type(field["type"])
                for field in item["fields"]
                if base_type(field["type"])
            }
            if name in dependencies or not item["fields"]:
                continue
            if dependencies <= resolved:
                operations.append({"kind": "struct", "name": name, "definition": item})
                resolved.add(name)
                del pending[name]
                progressed = True
        if not progressed:
            break
    for name in sorted(pending):
        conflicts.append({"kind": "struct", "name": name, "reason": "cyclic, empty, or unresolved field dependency"})
    return operations, conflicts


def inventory(port):
    functions = function_hashes(port)
    all_data_types = all_types(port)
    structs = typed_inventory(port, "struct")
    enums = typed_inventory(port, "enum")
    metrics = {
        "functions": len(functions),
        "custom_functions": sum(bool(item.get("has_custom_name")) for item in functions),
        "unresolved_functions": sum(not bool(item.get("has_custom_name")) for item in functions),
        "data_types": len(all_data_types),
        "structs": len(structs),
        "enums": len(enums),
        "data_items": len(paged_lines(port, "/list_data_items")),
        "globals": len(paged_lines(port, "/list_globals")),
        "classes": len(paged_lines(port, "/list_classes")),
        "namespaces": len(paged_lines(port, "/list_namespaces")),
        "imports": len(paged_lines(port, "/list_imports")),
        "exports": len(paged_lines(port, "/list_exports")),
    }
    return {
        "functions": functions,
        "all_data_types": all_data_types,
        "structs": structs,
        "enums": enums,
        "metrics": metrics,
    }


def plan_path(source_project, target_project):
    def slug(value):
        cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-.")
        return cleaned or "project"

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    directory = managed_dir / "compare-plans"
    directory.mkdir(parents=True, exist_ok=True)
    return directory / f"{stamp}-{slug(source_project)}-to-{slug(target_project)}.json"


def prune_plans(keep):
    plans = sorted((managed_dir / "compare-plans").glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    for path in plans[keep:]:
        path.unlink()


def generate():
    source_project, source_port, source_pid, target_project, target_port, target_pid = engine_arguments
    source_port, source_pid, target_port, target_pid = map(
        int, (source_port, source_pid, target_port, target_pid)
    )
    source_required = (
        "/get_bulk_function_hashes", "/get_function_documentation", "/list_data_types",
        "/get_struct_layout", "/get_enum_values",
    )
    target_required = source_required + (
        "/apply_function_documentation", "/create_struct", "/resize_struct", "/create_enum",
        "/create_data_type_category", "/move_data_type_to_category",
    )
    require_endpoints(source_port, source_required)
    require_endpoints(target_port, target_required)
    print(f"Collecting source inventory from {source_project} on MCP port {source_port}...")
    source = inventory(source_port)
    print(f"Collecting target inventory from {target_project} on MCP port {target_port}...")
    target = inventory(target_port)

    source_groups = defaultdict(list)
    target_groups = defaultdict(list)
    for item in source["functions"]:
        source_groups[(item.get("hash"), int(item.get("instruction_count", -1)))].append(item)
    for item in target["functions"]:
        target_groups[(item.get("hash"), int(item.get("instruction_count", -1)))].append(item)
    exact_pairs = []
    ambiguous = 0
    for key in sorted(set(source_groups) & set(target_groups), key=str):
        if key[0] and len(source_groups[key]) == len(target_groups[key]) == 1:
            exact_pairs.append((source_groups[key][0], target_groups[key][0]))
        else:
            ambiguous += 1

    operations = []
    conflicts = []
    print(f"Inspecting documentation for {len(exact_pairs)} unique exact function matches...")
    for index, (source_function, target_function) in enumerate(exact_pairs, 1):
        if index % 50 == 0:
            print(f"  inspected {index}/{len(exact_pairs)} matches")
        source_doc = request(
            source_port, "GET", "/get_function_documentation", {"address": source_function["address"]}
        )
        target_doc = request(
            target_port, "GET", "/get_function_documentation", {"address": target_function["address"]}
        )
        if not isinstance(source_doc, dict) or not isinstance(target_doc, dict):
            conflicts.append({"kind": "function", "name": source_function.get("name"), "reason": "invalid documentation export"})
            continue
        payload, doc_conflicts, changed = documentation_delta(source_doc, target_doc)
        for field in doc_conflicts:
            conflicts.append({"kind": "function", "name": source_function.get("name"), "field": field, "reason": "different target value"})
        if payload:
            operations.append(
                {
                    "kind": "function_documentation",
                    "source_address": source_function["address"],
                    "target_address": target_function["address"],
                    "hash": source_function["hash"],
                    "instruction_count": source_function["instruction_count"],
                    "fields": changed,
                    "payload": payload,
                    "target_guard": relevant_documentation(target_doc),
                }
            )

    enum_ops, enum_conflicts = build_type_operations(
        source["enums"], target["enums"], target["all_data_types"], "enum"
    )
    future_target_types = target["all_data_types"] + [
        {"name": operation["name"]} for operation in enum_ops
    ]
    struct_ops, struct_conflicts = build_type_operations(
        source["structs"], target["structs"], future_target_types, "struct"
    )
    operations = enum_ops + struct_ops + operations
    conflicts.extend(enum_conflicts + struct_conflicts)

    created_at = datetime.now(timezone.utc).isoformat()
    plan = {
        "schema": "ghidra-manager-compare-plan",
        "version": plan_version,
        "created_at": created_at,
        "policy": {
            "direction": "source-to-target",
            "matching": "unique-normalized-hash-and-instruction-count",
            "conflicts": "fill-gaps-only",
            "save_target": False,
        },
        "source": {"project": source_project, "port": source_port, "pid": source_pid},
        "target": {"project": target_project, "port": target_port, "pid": target_pid},
        "summary": {
            "source": source["metrics"],
            "target": target["metrics"],
            "exact_function_matches": len(exact_pairs),
            "ambiguous_hash_groups": ambiguous,
            "operations": len(operations),
            "conflicts": len(conflicts),
        },
        "operations": operations,
        "conflicts": conflicts,
    }
    path = plan_path(source_project, target_project)
    temporary = path.with_suffix(".json.next")
    temporary.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n")
    os.chmod(temporary, stat.S_IRUSR | stat.S_IWUSR)
    temporary.replace(path)
    prune_plans(retention)

    print()
    print(f"Comparison: {source_project} -> {target_project}")
    print(f"{'Metric':<24} {'Source':>10} {'Target':>10} {'Delta':>10}")
    print(f"{'-' * 24} {'-' * 10} {'-' * 10} {'-' * 10}")
    for key in (
        "functions", "custom_functions", "unresolved_functions", "structs", "enums",
        "data_types", "data_items", "globals", "classes", "namespaces", "imports", "exports",
    ):
        left = source["metrics"][key]
        right = target["metrics"][key]
        print(f"{key.replace('_', ' '):<24} {left:>10} {right:>10} {right - left:>+10}")
    print()
    print(f"Unique exact function matches: {len(exact_pairs)}")
    print(f"Ambiguous hash groups skipped: {ambiguous}")
    print(f"Proposed operations: {len(operations)}")
    print(f"Conflicts and deferred items: {len(conflicts)}")
    print(f"Plan saved: {path}")
    print("No changes were applied. Review the plan, then apply it with:")
    print(f"  ghidra-manager compare --apply {path}")


def mutation_failed(value):
    if isinstance(value, dict):
        if value.get("success") is False or value.get("status") == "error" or value.get("error"):
            return True
        return False
    lowered = str(value).lower()
    return any(token in lowered for token in ("error", "failed", "unknown field type", "not found"))


def post_checked(port, path, body):
    value = request(port, "POST", path, body=body)
    if mutation_failed(value):
        raise CompareError(f"{path} rejected the operation: {value}")
    return value


def apply_plan():
    path = Path(engine_arguments[0]).expanduser().resolve()
    try:
        plan = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise CompareError(f"Cannot read compare plan {path}: {exc}") from exc
    if plan.get("schema") != "ghidra-manager-compare-plan" or plan.get("version") != plan_version:
        raise CompareError(f"Unsupported compare plan schema or version: {path}")
    target = plan.get("target", {})
    port = int(target.get("port", 0))
    expected_pid = int(target.get("pid", 0))
    expected_project = target.get("project")
    info = instance_info(port)
    if int(info.get("pid", 0)) != expected_pid or info.get("project") != expected_project:
        raise CompareError(
            "Target instance identity changed since comparison; rerun compare before applying"
        )
    required = {
        "/apply_function_documentation", "/get_function_documentation",
        "/create_struct", "/resize_struct", "/create_enum",
        "/create_data_type_category", "/move_data_type_to_category",
    }
    require_endpoints(port, sorted(required))

    print(f"Preflighting {len(plan.get('operations', []))} operations for {expected_project}...")
    current_types = all_types(port)
    current_type_names = Counter(item["name"] for item in current_types)
    for operation in plan.get("operations", []):
        kind = operation.get("kind")
        if kind in {"struct", "enum"}:
            if current_type_names[operation["name"]] != 0:
                raise CompareError(
                    f"Target type state changed for {operation['name']}; rerun compare before applying"
                )
            current_type_names[operation["name"]] += 1
        elif kind == "function_documentation":
            current = request(
                port, "GET", "/get_function_documentation", {"address": operation["target_address"]}
            )
            if not isinstance(current, dict) or relevant_documentation(current) != operation["target_guard"]:
                raise CompareError(
                    f"Target documentation changed at {operation['target_address']}; rerun compare before applying"
                )
            if current.get("hash") != operation["hash"]:
                raise CompareError(
                    f"Target function hash changed at {operation['target_address']}; rerun compare"
                )
        else:
            raise CompareError(f"Unsupported operation kind in plan: {kind}")

    applied = 0
    try:
        for operation in plan.get("operations", []):
            kind = operation["kind"]
            if kind == "enum":
                definition = operation["definition"]
                post_checked(
                    port,
                    "/create_enum",
                    {"name": operation["name"], "values": definition["values"], "size": definition["size"]},
                )
                category = str(Path(definition["path"]).parent)
                if category not in {".", "/"}:
                    post_checked(port, "/create_data_type_category", {"category_path": category})
                    post_checked(
                        port, "/move_data_type_to_category",
                        {"type_name": operation["name"], "category_path": category},
                    )
            elif kind == "struct":
                definition = operation["definition"]
                fields = [
                    {"name": field["name"], "type": field["type"], "offset": field["offset"]}
                    for field in definition["fields"]
                ]
                post_checked(port, "/create_struct", {"name": operation["name"], "fields": fields})
                post_checked(
                    port, "/resize_struct", {"name": operation["name"], "new_size": definition["size"], "force": False}
                )
                category = str(Path(definition["path"]).parent)
                if category not in {".", "/"}:
                    post_checked(port, "/create_data_type_category", {"category_path": category})
                    post_checked(
                        port, "/move_data_type_to_category",
                        {"type_name": operation["name"], "category_path": category},
                    )
            else:
                value = request(port, "POST", "/apply_function_documentation", body=operation["payload"])
                if not isinstance(value, dict) or value.get("success") is not True:
                    raise CompareError(f"Function documentation apply failed: {value}")
            applied += 1
            print(f"  applied {applied}/{len(plan['operations'])}: {kind} {operation.get('name', operation.get('target_address'))}")
    except CompareError:
        print(
            f"Apply stopped after {applied} operations. Earlier changes remain unsaved in Ghidra; "
            "undo them or close without saving before retrying.",
            file=sys.stderr,
        )
        raise

    print()
    print(f"Applied {applied} operations to {expected_project}.")
    print("The target program is not saved. Review the changes in Ghidra, then save or undo them.")


def main(argv: list[str] | None = None) -> int:
    global managed_dir, plan_version, retention, engine_arguments

    parser = argparse.ArgumentParser(
        description="Generate or apply a safe cross-instance GhidraMCP comparison plan."
    )
    parser.add_argument("mode", choices=("generate", "apply"))
    parser.add_argument("managed_dir", type=Path)
    parser.add_argument("plan_version", type=int)
    parser.add_argument("retention", type=int)
    parser.add_argument("arguments", nargs="*")
    args = parser.parse_args(argv)

    expected_arguments = 6 if args.mode == "generate" else 1
    if len(args.arguments) != expected_arguments:
        parser.error(
            f"{args.mode} requires {expected_arguments} engine argument"
            f"{'s' if expected_arguments != 1 else ''}"
        )

    managed_dir = args.managed_dir
    plan_version = args.plan_version
    retention = args.retention
    engine_arguments = args.arguments

    try:
        if args.mode == "generate":
            generate()
        else:
            apply_plan()
    except CompareError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
