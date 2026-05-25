from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from backend.helper.agent.sub_agent.auditor import AuditorAgent
from backend.helper.agent.sub_agent.payload import PayloadAgent
from backend.helper.agent.sub_agent.probe import TargetProbeAgent
from backend.helper.agent.sub_agent.scanner import WebScannerAgent
from backend.helper.pipeline import NovaPipeline
from backend.helper.settings import ARTIFACT_DIR, REPORT_DIR, load_runtime_settings
from backend.helper.utils import normalize_url, read_json, write_json


DEFAULT_PROBE_PATH = ARTIFACT_DIR / "TargetProbe_agent.json"
DEFAULT_WEBSAN_PATH = ARTIFACT_DIR / "Webscan_agent.json"
DEFAULT_AUDIT_PATH = ARTIFACT_DIR / "Auditor_agent.json"


def _path(value: str | None, default: Path) -> Path:
    return Path(value) if value else default


def _emit(data: dict[str, Any], out_path: Path, print_json: bool) -> None:
    write_json(out_path, data)
    print(f"Saved: {out_path}")
    if print_json:
        print(json.dumps(data, indent=2, ensure_ascii=False))


def run_probe(args: argparse.Namespace) -> dict[str, Any]:
    target = normalize_url(args.url)
    data = TargetProbeAgent(load_runtime_settings()).probe(target)
    _emit(data, _path(args.out, DEFAULT_PROBE_PATH), args.print_json)
    return data


def run_scan(args: argparse.Namespace) -> dict[str, Any]:
    target = normalize_url(args.url)
    settings = load_runtime_settings()
    probe = read_json(Path(args.probe)) if args.probe else {}
    scan_target = probe.get("final_url") or target
    if probe and not probe.get("scan_allowed", True):
        data = {
            "agent": "Webscanner Agent",
            "target": scan_target,
            "reachable": False,
            "status_code": probe.get("status_code"),
            "final_url": scan_target,
            "headers": {},
            "title": "",
            "links": [],
            "forms": [],
            "cookies": [],
            "technologies": [],
            "input_points": [],
            "pages": [],
            "events": [],
            "errors": [{"url": scan_target, "error": "TargetProbe 判定最终地址不在允许扫描边界内。"}],
            "scope": {},
            "auth": probe.get("auth", {}),
        }
    else:
        data = WebScannerAgent(settings).scan(scan_target)
    if probe:
        data["target_probe"] = probe
    _emit(data, _path(args.out, DEFAULT_WEBSAN_PATH), args.print_json)
    return data


def run_audit(args: argparse.Namespace) -> dict[str, Any]:
    webscan = read_json(Path(args.input))
    data = AuditorAgent(load_runtime_settings()).audit(webscan)
    _emit(data, _path(args.out, DEFAULT_AUDIT_PATH), args.print_json)
    return data


def run_report(args: argparse.Namespace) -> dict[str, Any]:
    audit = read_json(Path(args.input))
    webscan = read_json(Path(args.webscan))
    probe = read_json(Path(args.probe)) if args.probe else webscan.get("target_probe", {})
    report, json_path, markdown_path = PayloadAgent().build_report(
        audit.get("target", webscan.get("target", "")),
        webscan,
        audit,
        REPORT_DIR,
        target_probe=probe,
    )
    print(f"JSON report: {json_path}")
    print(f"Markdown report: {markdown_path}")
    if args.print_json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    return report


def run_pipeline(args: argparse.Namespace) -> None:
    NovaPipeline(verbose=args.verbose).run(args.url)


def run_scoped(args: argparse.Namespace) -> None:
    target = normalize_url(args.url)
    settings = load_runtime_settings()

    print(f"[Scoped] Target: {target}")
    print("[Scoped] Running target probe...")
    probe = TargetProbeAgent(settings).probe(target)
    write_json(DEFAULT_PROBE_PATH, probe)
    print(f"Saved: {DEFAULT_PROBE_PATH}")
    if args.until == "probe":
        return

    print("[Scoped] Running scanner...")
    scan_target = probe.get("final_url") or target
    if not probe.get("scan_allowed", True):
        webscan = {
            "agent": "Webscanner Agent",
            "target": scan_target,
            "reachable": False,
            "status_code": probe.get("status_code"),
            "final_url": scan_target,
            "headers": {},
            "title": "",
            "links": [],
            "forms": [],
            "cookies": [],
            "technologies": [],
            "input_points": [],
            "pages": [],
            "events": [],
            "errors": [{"url": scan_target, "error": "TargetProbe 判定最终地址不在允许扫描边界内。"}],
            "scope": {},
            "auth": probe.get("auth", {}),
        }
    else:
        webscan = WebScannerAgent(settings).scan(scan_target)
    webscan["target_probe"] = probe
    write_json(DEFAULT_WEBSAN_PATH, webscan)
    print(f"Saved: {DEFAULT_WEBSAN_PATH}")
    if args.until == "scan":
        return

    print("[Scoped] Running auditor...")
    audit = AuditorAgent(settings).audit(webscan)
    write_json(DEFAULT_AUDIT_PATH, audit)
    print(f"Saved: {DEFAULT_AUDIT_PATH}")
    if args.until == "audit":
        return

    print("[Scoped] Building report...")
    report, json_path, markdown_path = PayloadAgent().build_report(
        target,
        webscan,
        audit,
        REPORT_DIR,
        target_probe=probe,
    )
    print(f"JSON report: {json_path}")
    print(f"Markdown report: {markdown_path}")
    if args.print_json:
        print(json.dumps(report, indent=2, ensure_ascii=False))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m backend.helper.agent",
        description="Local manual runner for NOVA agents and scoped pipeline runs.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    probe = subparsers.add_parser("probe", help="Run TargetProbe Agent against a URL.")
    probe.add_argument("--url", required=True)
    probe.add_argument("--out", help=f"Output JSON path. Default: {DEFAULT_PROBE_PATH}")
    probe.add_argument("--print-json", action="store_true")
    probe.set_defaults(func=run_probe)

    scan = subparsers.add_parser("scan", help="Run Webscanner Agent against a URL.")
    scan.add_argument("--url", required=True)
    scan.add_argument("--probe", help=f"Probe JSON path. Default: {DEFAULT_PROBE_PATH}")
    scan.add_argument("--out", help=f"Output JSON path. Default: {DEFAULT_WEBSAN_PATH}")
    scan.add_argument("--print-json", action="store_true")
    scan.set_defaults(func=run_scan)

    audit = subparsers.add_parser("audit", help="Run Auditor Agent against scanner JSON.")
    audit.add_argument("--input", default=str(DEFAULT_WEBSAN_PATH))
    audit.add_argument("--out", help=f"Output JSON path. Default: {DEFAULT_AUDIT_PATH}")
    audit.add_argument("--print-json", action="store_true")
    audit.set_defaults(func=run_audit)

    report = subparsers.add_parser("report", help="Build the final scan report.")
    report.add_argument("--input", default=str(DEFAULT_AUDIT_PATH))
    report.add_argument("--webscan", default=str(DEFAULT_WEBSAN_PATH))
    report.add_argument("--probe", default=str(DEFAULT_PROBE_PATH))
    report.add_argument("--print-json", action="store_true")
    report.set_defaults(func=run_report)

    pipeline = subparsers.add_parser("pipeline", help="Run the full NOVA pipeline.")
    pipeline.add_argument("--url", required=True)
    pipeline.add_argument("--verbose", action="store_true")
    pipeline.set_defaults(func=run_pipeline)

    scoped = subparsers.add_parser("scoped", help="Run from URL through a selected stage.")
    scoped.add_argument("--url", required=True)
    scoped.add_argument(
        "--until",
        choices=["probe", "scan", "audit", "report"],
        default="report",
        help="Stop after this stage.",
    )
    scoped.add_argument("--print-json", action="store_true")
    scoped.set_defaults(func=run_scoped)

    return parser


def main() -> None:
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
