from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from backend.helper.agent.sub_agent.auditor import AuditorAgent
from backend.helper.agent.sub_agent.payload import PayloadAgent
from backend.helper.agent.sub_agent.probe import TargetProbeAgent
from backend.helper.agent.sub_agent.scanner import WebScannerAgent
from backend.helper.auth import basic_auth_header, parse_header_line
from backend.helper.settings import ARTIFACT_DIR, REPORT_DIR, RuntimeSettings, load_runtime_settings
from backend.helper.utils import normalize_url, write_json
from backend.helper.vuln_types import category_label


try:
    from rich import box
    from rich.console import Console
    from rich.table import Table
except ImportError:
    box = None
    Console = None


ASCII_BANNER = r"""
███╗   ██╗ ██████╗ ██╗   ██╗ █████╗
████╗  ██║██╔═══██╗██║   ██║██╔══██╗
██╔██╗ ██║██║   ██║██║   ██║███████║
██║╚██╗██║██║   ██║╚██╗ ██╔╝██╔══██║
██║ ╚████║╚██████╔╝ ╚████╔╝ ██║  ██║
╚═╝  ╚═══╝ ╚═════╝   ╚═══╝  ╚═╝  ╚═╝
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="NOVA",
        description="NOVA AI assisted web security audit assistant.",
    )
    parser.add_argument("--url", required=True, help="Target URL to scan.")
    parser.add_argument("--verbose", action="store_true", help="Show extra runtime details.")
    parser.add_argument("--cookie", help="Authenticated Cookie header value, for example 'SESSION=abc'.")
    parser.add_argument(
        "--header",
        action="append",
        default=[],
        help="Custom authenticated header. Repeatable. Format: 'Name: value'.",
    )
    parser.add_argument("--basic-user", help="HTTP Basic Auth username.")
    parser.add_argument("--basic-pass", help="HTTP Basic Auth password.")
    return parser


def configure_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")


def settings_from_args(args: argparse.Namespace) -> RuntimeSettings:
    settings = load_runtime_settings()
    auth_headers = dict(settings.auth_headers)
    if args.cookie:
        auth_headers["Cookie"] = args.cookie
    for header_line in args.header:
        name, value = parse_header_line(header_line)
        auth_headers[name] = value
    auth_headers.update(basic_auth_header(args.basic_user, args.basic_pass))
    return RuntimeSettings(
        llm_baseurl=settings.llm_baseurl,
        llm_apikey=settings.llm_apikey,
        llm_model=settings.llm_model,
        llm_provider=settings.llm_provider,
        request_timeout=settings.request_timeout,
        max_links=settings.max_links,
        max_pages=settings.max_pages,
        max_depth=settings.max_depth,
        rate_limit=settings.rate_limit,
        active_scan=settings.active_scan,
        active_request_timeout=settings.active_request_timeout,
        max_active_inputs=settings.max_active_inputs,
        focus_target_path=settings.focus_target_path,
        llm_analysis=settings.llm_analysis,
        llm_on_local_targets=settings.llm_on_local_targets,
        llm_payload_advisor=settings.llm_payload_advisor,
        llm_payload_max_per_param=settings.llm_payload_max_per_param,
        llm_payload_report_only=settings.llm_payload_report_only,
        report_confirmed_only=settings.report_confirmed_only,
        allowed_hosts=settings.allowed_hosts,
        exclude_paths=settings.exclude_paths,
        auth_headers=auth_headers,
    )


def print_plain_report(report: dict[str, Any], json_path: Path, markdown_path: Path) -> None:
    summary = report["summary"]
    print("")
    print("扫描概览")
    print(f"目标地址：{summary['target']}")
    print(f"最终地址：{summary.get('final_url') or 'N/A'}")
    print(f"状态码：{summary.get('status_code') or 'N/A'}")
    print(f"是否需要认证：{'是' if summary.get('auth_required') else '否'}")
    print(f"风险等级：{summary['risk_level']}")
    print(f"发现数量：{summary['total_findings']}")
    print(f"确认漏洞：{summary.get('confirmed', 0)}")
    print(f"疑似漏洞：{summary.get('suspected', 0)}")
    print(f"候选 Payload：允许 {summary.get('llm_payload_allowed', 0)}，过滤 {summary.get('llm_payload_blocked', 0)}")
    if summary.get("finding_types"):
        type_text = "；".join(f"{item.get('label')} {item.get('count')} 项" for item in summary["finding_types"])
        print(f"漏洞类型：{type_text}")
    print("")
    print("发现项：")
    if not report["findings"]:
        print("未发现明显风险。")
    for finding in report["findings"]:
        payloads = ", ".join(finding.get("payloads", [])) or "N/A"
        print(f"[{finding['severity']}] {finding['title']}")
        print(f"  状态：{finding.get('status', 'N/A')}")
        print(f"  漏洞类型：{finding.get('category_label') or category_label(finding.get('category'))}")
        print(f"  置信度：{finding['confidence']}")
        print(f"  证据：{finding.get('evidence', 'N/A')}")
        print(f"  已执行 Payload：{payloads}")
    print("")
    print(f"JSON 报告：{json_path}")
    print(f"Markdown 报告：{markdown_path}")


def print_rich_report(
    console: Any,
    report: dict[str, Any],
    json_path: Path,
    markdown_path: Path,
    artifacts: list[tuple[str, Path]],
) -> None:
    summary = report["summary"]
    summary_table = Table(title="扫描概览", show_header=True, header_style="bold cyan", box=box.ASCII)
    summary_table.add_column("字段", style="cyan", no_wrap=True)
    summary_table.add_column("值")
    summary_table.add_row("目标地址", str(summary["target"]))
    summary_table.add_row("最终地址", str(summary.get("final_url") or "N/A"))
    summary_table.add_row("状态码", str(summary.get("status_code") or "N/A"))
    summary_table.add_row("是否需要认证", "是" if summary.get("auth_required") else "否")
    summary_table.add_row("风险等级", str(summary["risk_level"]))
    summary_table.add_row("发现数量", str(summary["total_findings"]))
    summary_table.add_row("确认漏洞", str(summary.get("confirmed", 0)))
    summary_table.add_row("疑似漏洞", str(summary.get("suspected", 0)))
    if summary.get("finding_types"):
        type_text = "；".join(f"{item.get('label')} {item.get('count')} 项" for item in summary["finding_types"])
        summary_table.add_row("漏洞类型", type_text)
    summary_table.add_row(
        "候选 Payload",
        f"允许 {summary.get('llm_payload_allowed', 0)} / 过滤 {summary.get('llm_payload_blocked', 0)}",
    )
    console.print(summary_table)

    findings_table = Table(title="发现项", show_header=True, header_style="bold magenta", box=box.ASCII)
    findings_table.add_column("严重性", no_wrap=True)
    findings_table.add_column("状态", no_wrap=True)
    findings_table.add_column("漏洞类型", overflow="fold")
    findings_table.add_column("标题", overflow="fold")
    findings_table.add_column("置信度", no_wrap=True)
    findings_table.add_column("已执行 Payload", overflow="fold")

    if report["findings"]:
        for finding in report["findings"]:
            findings_table.add_row(
                finding["severity"],
                finding.get("status", "N/A"),
                finding.get("category_label") or category_label(finding.get("category")),
                finding["title"],
                finding["confidence"],
                ", ".join(finding.get("payloads", [])) or "N/A",
            )
    else:
        findings_table.add_row("Info", "N/A", "N/A", "未发现明显风险。", "High", "N/A")
    console.print(findings_table)

    output_table = Table(title="输出文件", show_header=True, header_style="bold green", box=box.ASCII)
    output_table.add_column("文件", style="green", no_wrap=True)
    output_table.add_column("路径")
    for name, path in artifacts:
        output_table.add_row(name, str(path))
    output_table.add_row("JSON 报告", str(json_path))
    output_table.add_row("Markdown 报告", str(markdown_path))
    console.print(output_table)


def run_probe(target: str, settings: RuntimeSettings) -> tuple[dict, Path]:
    probe = TargetProbeAgent(settings).probe(target)
    probe_path = ARTIFACT_DIR / "TargetProbe_agent.json"
    write_json(probe_path, probe)
    return probe, probe_path


def run_webscan(target: str, settings: RuntimeSettings, probe: dict | None = None) -> tuple[dict, Path]:
    scan_target = (probe or {}).get("final_url") or target
    if probe and not probe.get("scan_allowed", True):
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
    webscan["target_probe"] = probe or {}
    webscan_path = ARTIFACT_DIR / "Webscan_agent.json"
    write_json(webscan_path, webscan)
    return webscan, webscan_path


def run_audit(webscan: dict, settings: RuntimeSettings) -> tuple[dict, Path]:
    audit = AuditorAgent(settings).audit(webscan)
    audit_path = ARTIFACT_DIR / "Auditor_agent.json"
    write_json(audit_path, audit)
    return audit, audit_path


def write_report(target: str, probe: dict, webscan: dict, audit: dict) -> tuple[dict, Path, Path]:
    return PayloadAgent().build_report(target, webscan, audit, REPORT_DIR, target_probe=probe)


def run_scan(args: argparse.Namespace) -> tuple[dict, Path, Path, list[tuple[str, Path]]]:
    target = normalize_url(args.url)
    settings = settings_from_args(args)
    artifacts: list[tuple[str, Path]] = []

    probe, probe_path = run_probe(target, settings)
    artifacts.append(("TargetProbe Agent", probe_path))

    webscan, webscan_path = run_webscan(target, settings, probe)
    artifacts.append(("Webscanner Agent", webscan_path))

    audit, audit_path = run_audit(webscan, settings)
    artifacts.append(("Auditor Agent", audit_path))

    report, json_path, markdown_path = write_report(target, probe, webscan, audit)
    return report, json_path, markdown_path, artifacts


def run_plain(args: argparse.Namespace) -> int:
    print(ASCII_BANNER)
    print("NOVA - AI 辅助的 Web 安全审计助手")
    print("")
    print("[1/4] TargetProbe Agent 正在探测目标...")
    print("[2/4] Webscanner Agent 正在爬取目标...")
    print("[3/4] Auditor Agent 正在检查风险、验证本地规则并生成候选 Payload...")
    print("[4/4] 正在写入扫描报告...")
    report, json_path, markdown_path, _ = run_scan(args)
    print_plain_report(report, json_path, markdown_path)
    return 0


def run_rich(args: argparse.Namespace) -> int:
    console = Console(width=110)
    console.print(f"[bold cyan]{ASCII_BANNER}[/bold cyan]")

    target = normalize_url(args.url)
    settings = settings_from_args(args)
    artifacts: list[tuple[str, Path]] = []

    console.print("[cyan][1/4][/cyan] TargetProbe Agent 正在探测目标")
    probe, probe_path = run_probe(target, settings)
    artifacts.append(("TargetProbe Agent", probe_path))

    console.print("[cyan][2/4][/cyan] Webscanner Agent 正在爬取目标")
    webscan, webscan_path = run_webscan(target, settings, probe)
    artifacts.append(("Webscanner Agent", webscan_path))

    console.print("[cyan][3/4][/cyan] Auditor Agent 正在检查风险、本地验证并生成候选 Payload")
    audit, audit_path = run_audit(webscan, settings)
    artifacts.append(("Auditor Agent", audit_path))

    console.print("[cyan][4/4][/cyan] 正在写入扫描报告")
    report, json_path, markdown_path = write_report(target, probe, webscan, audit)

    print_rich_report(console, report, json_path, markdown_path, artifacts)
    return 0


def main() -> int:
    configure_stdio()
    args = build_parser().parse_args()
    try:
        if Console is None:
            return run_plain(args)
        return run_rich(args)
    except Exception as exc:
        if Console is not None:
            Console(stderr=True).print(f"[bold red]NOVA 运行失败：[/bold red] {exc}")
        else:
            print(f"NOVA 运行失败：{exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
