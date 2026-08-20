#!/usr/bin/env python3
"""
ZAB Wireshark Dissector Test Runner & Fixture Extractor.

Modes:
  - Execution mode: Discovers per-request-type manifests under tests/fixtures/<type>/manifest.json,
    runs tshark with zab.lua, and verifies dissected output against golden text baselines.
  - Extract mode: Slices packet captures using tshark into target fixture pcapng files.
"""

import argparse
import difflib
import json
import os
import shutil
import subprocess
import sys
import tempfile

def find_tshark():
    """Find tshark binary path."""
    tshark_path = shutil.which("tshark")
    if not tshark_path:
        print("ERROR: tshark binary not found in PATH.", file=sys.stderr)
        print("Ensure tshark is installed or run via Nix devShell/app.", file=sys.stderr)
        sys.exit(1)
    return tshark_path

def run_tshark(tshark_bin, capture_path, lua_script_path, port):
    """Run tshark against a capture file and return stdout (JSON) or raises RuntimeError."""
    cmd = [
        tshark_bin,
        "-n",
        "-r", capture_path,
        "-X", f"lua_script:{lua_script_path}",
        "-X", f"lua_script1:port={port}",
        "-Yzab",
        "-T", "json"
    ]
    env = dict(os.environ, HOME=tempfile.gettempdir())
    res = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if res.returncode != 0:
        raise RuntimeError(f"tshark exited with code {res.returncode}:\n{res.stderr}")
    return res.stdout

def extract_zab_fields_from_json(json_str):
    """Parse tshark JSON output and return canonical string representation."""
    if not json_str or not json_str.strip():
        return ""

    try:
        packets = json.loads(json_str)
    except json.JSONDecodeError as e:
        raise ValueError(f"Failed to parse tshark JSON output: {e}")

    lines = []
    for idx, packet in enumerate(packets, start=1):
        layers = packet.get("_source", {}).get("layers", {})
        zab_layer = layers.get("zab")
        if not zab_layer:
            continue

        field_list = []
        
        def walk(obj):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if isinstance(v, (dict, list)):
                        walk(v)
                    elif k.startswith("zab."):
                        field_list.append((k, str(v)))
            elif isinstance(obj, list):
                for item in obj:
                    walk(item)

        walk(zab_layer)
        field_list.sort(key=lambda x: (x[0], x[1]))

        if lines:
            lines.append("")  # Blank line separator between packets

        lines.append(f"=== Packet {idx} ===")
        for k, v in field_list:
            lines.append(f"{k}\t{v}")

    return "\n".join(lines) + ("\n" if lines else "")

def handle_extract(args, tshark_bin, lua_script_path):
    """Execute extract subcommand to slice packets into fixture pcapng file."""
    input_path = os.path.abspath(args.input)
    out_path = os.path.abspath(args.out)
    port = args.port or 2181

    if not os.path.exists(input_path):
        print(f"ERROR: Source capture file not found at {input_path}", file=sys.stderr)
        sys.exit(1)

    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    cmd = [
        tshark_bin,
        "-r", input_path,
        "-2",
        "-X", f"lua_script:{lua_script_path}",
        "-X", f"lua_script1:port={port}"
    ]
    
    display_filter = args.filter or ""
    if args.range:
        range_filter = f"frame.number >= {args.range.split('-')[0]} && frame.number <= {args.range.split('-')[-1]}"
        display_filter = f"({display_filter}) && ({range_filter})" if display_filter else range_filter

    if display_filter:
        cmd.extend(["-Y", display_filter])

    cmd.extend(["-w", out_path])

    if args.verbose:
        print(f"Running extract command: {' '.join(cmd)}")

    env = dict(os.environ, HOME=tempfile.gettempdir())
    res = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if res.returncode != 0:
        print(f"ERROR: Extraction failed:\n{res.stderr}", file=sys.stderr)
        sys.exit(1)

    print(f"Extracted fixture saved to: {out_path}")
    sys.exit(0)

def find_repo_root():
    """Determine repository root."""
    cwd = os.getcwd()
    if os.path.exists(os.path.join(cwd, "tests", "fixtures")):
        return cwd
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if os.path.basename(script_dir) == "tests":
        return os.path.abspath(os.path.join(script_dir, ".."))
    return script_dir

def main():
    parser = argparse.ArgumentParser(description="ZAB Dissector Test Runner & Fixture Extractor")
    subparsers = parser.add_subparsers(dest="subcommand", help="Subcommand to execute")

    # Extract subcommand
    extract_parser = subparsers.add_parser("extract", help="Extract packet subset from pcap file into fixture pcapng")
    extract_parser.add_argument("-i", "--input", required=True, help="Input capture file path")
    extract_parser.add_argument("-o", "--out", required=True, help="Destination fixture file path")
    extract_parser.add_argument("-f", "--filter", help="tshark display filter string (e.g. 'zab.opcode == 1')")
    extract_parser.add_argument("-r", "--range", help="Frame number range (e.g. '1-10')")
    extract_parser.add_argument("-p", "--port", type=int, default=2181, help="ZAB TCP port (default: 2181)")
    extract_parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose log output")

    # Main runner arguments
    parser.add_argument("-t", "--type", help="Filter execution to specific request/response opcode directory (e.g. 'create')")
    parser.add_argument("-u", "--update", action="store_true", help="Update expected golden output text files")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose log output")

    args = parser.parse_args()
    tshark_bin = find_tshark()
    repo_root = find_repo_root()
    lua_script_path = os.path.join(repo_root, "zab.lua")

    if args.subcommand == "extract":
        handle_extract(args, tshark_bin, lua_script_path)

    repo_root = find_repo_root()
    fixtures_dir = os.path.join(repo_root, "tests", "fixtures")
    lua_script_path = os.path.join(repo_root, "zab.lua")

    if not os.path.exists(fixtures_dir):
        print(f"ERROR: Fixtures directory not found at {fixtures_dir}", file=sys.stderr)
        sys.exit(1)

    if not os.path.exists(lua_script_path):
        print(f"ERROR: Dissector script not found at {lua_script_path}", file=sys.stderr)
        sys.exit(1)

    # Discover request type directories
    type_dirs = []
    if args.type:
        target_dir = os.path.join(fixtures_dir, args.type)
        if not os.path.exists(target_dir):
            print(f"ERROR: Request type directory not found at {target_dir}", file=sys.stderr)
            sys.exit(1)
        type_dirs.append(args.type)
    else:
        for entry in os.listdir(fixtures_dir):
            entry_path = os.path.join(fixtures_dir, entry)
            if os.path.isdir(entry_path) and os.path.exists(os.path.join(entry_path, "manifest.json")):
                type_dirs.append(entry)
        type_dirs.sort()

    if not type_dirs:
        print("No request type manifests found under tests/fixtures/.")
        sys.exit(0)

    passed = 0
    failed = 0
    updated = 0
    total = 0

    for req_type in type_dirs:
        type_dir = os.path.join(fixtures_dir, req_type)
        manifest_path = os.path.join(type_dir, "manifest.json")

        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest_data = json.load(f)

        port = manifest_data.get("port", 2181)
        instances = manifest_data.get("instances", [])

        for inst in instances:
            if not inst.get("enabled", True):
                if args.verbose:
                    print(f"[SKIP] {req_type}/{inst.get('file')} (disabled)")
                continue

            total += 1
            inst_file = inst["file"]
            inst_path = os.path.join(type_dir, inst_file)
            basename = os.path.splitext(inst_file)[0]
            golden_path = os.path.join(type_dir, f"{basename}.txt")

            if not os.path.exists(inst_path):
                print(f"[FAIL] {req_type}/{inst_file} - Capture instance file missing: {inst_path}")
                failed += 1
                continue

            try:
                raw_json = run_tshark(tshark_bin, inst_path, lua_script_path, port)
                actual_text = extract_zab_fields_from_json(raw_json)
            except Exception as e:
                print(f"[FAIL] {req_type}/{inst_file} - Execution error:\n  {e}")
                failed += 1
                continue

            if args.update:
                with open(golden_path, "w", encoding="utf-8") as f:
                    f.write(actual_text)
                print(f"[UPDATED] {req_type}/{inst_file} -> {os.path.relpath(golden_path, repo_root)}")
                updated += 1
                continue

            if not os.path.exists(golden_path):
                print(f"[FAIL] {req_type}/{inst_file} - Expected golden file missing: {os.path.relpath(golden_path, repo_root)}")
                print(f"  Run with --update to generate golden baseline files.")
                failed += 1
                continue

            with open(golden_path, "r", encoding="utf-8") as f:
                expected_text = f.read()

            if actual_text == expected_text:
                print(f"[PASS] {req_type}/{inst_file}")
                passed += 1
            else:
                print(f"[FAIL] {req_type}/{inst_file}")
                diff = difflib.unified_diff(
                    expected_text.splitlines(keepends=True),
                    actual_text.splitlines(keepends=True),
                    fromfile=f"{req_type}/expected_{basename}.txt",
                    tofile=f"{req_type}/actual_{basename}.txt"
                )
                sys.stdout.writelines(diff)
                failed += 1

    print("\n--- Test Summary ---")
    if args.update:
        print(f"Updated {updated} golden file(s). Total evaluated: {total}.")
        sys.exit(0)
    else:
        print(f"Total: {total} | Passed: {passed} | Failed: {failed}")
        if failed > 0:
            sys.exit(1)
        sys.exit(0)

if __name__ == "__main__":
    main()
