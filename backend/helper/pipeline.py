from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from backend.helper.agent.sub_agent.auditor import AuditorAgent
from backend.helper.agent.sub_agent.payload import PayloadAgent
from backend.helper.agent.sub_agent.probe import TargetProbeAgent
from backend.helper.agent.sub_agent.scanner import WebScannerAgent
from backend.helper.settings import ARTIFACT_DIR, REPORT_DIR, load_runtime_settings
from backend.helper.utils import normalize_url, write_json


@dataclass
class PipelineResult:
    artifact_dir: Path
    json_report: Path
    markdown_report: Path
    report: dict


class NovaPipeline:
    def __init__(self, verbose: bool = False) -> None:
        self.verbose = verbose
        self.settings = load_runtime_settings()

    def _log(self, message: str) -> None:
        print(message)

    def run(self, target_url: str) -> PipelineResult:
        self._log("[NOVA] AI 辅助的 Web 安全审计助手")
        self._log("")

        self._log("[1/4] 探测目标...")
        target_url = normalize_url(target_url)
        probe = TargetProbeAgent(self.settings).probe(target_url)
        probe_path = ARTIFACT_DIR / "TargetProbe_agent.json"
        write_json(probe_path, probe)
        self._log(f"已保存：{probe_path}")

        self._log("[2/4] 运行 Webscanner Agent...")
        scan_target = probe.get("final_url") or target_url
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
            webscan = WebScannerAgent(self.settings).scan(scan_target)
        webscan["target_probe"] = probe
        webscan_path = ARTIFACT_DIR / "Webscan_agent.json"
        write_json(webscan_path, webscan)
        self._log(f"已保存：{webscan_path}")

        self._log("[3/4] 运行 Auditor Agent，本地验证并生成 LLM 候选 Payload...")
        audit = AuditorAgent(self.settings).audit(webscan)
        audit_path = ARTIFACT_DIR / "Auditor_agent.json"
        write_json(audit_path, audit)
        self._log(f"已保存：{audit_path}")

        self._log("[4/4] 生成扫描报告...")
        report, json_path, markdown_path = PayloadAgent().build_report(
            target_url,
            webscan,
            audit,
            REPORT_DIR,
            target_probe=probe,
        )
        self._print_findings(report)
        self._log("")
        self._log(f"JSON 报告：{json_path}")
        self._log(f"Markdown 报告：{markdown_path}")

        return PipelineResult(
            artifact_dir=ARTIFACT_DIR,
            json_report=json_path,
            markdown_report=markdown_path,
            report=report,
        )

    def _print_findings(self, report: dict) -> None:
        findings = report.get("findings", [])
        self._log("")
        self._log("发现项：")
        if not findings:
            self._log("未发现明显风险。")
            return

        for item in findings:
            payloads = ", ".join(item.get("payloads", [])) or "N/A"
            self._log(f"[{item['severity']}] {item['title']}")
            self._log(f"  URL：{item.get('url', 'N/A')}")
            self._log(f"  证据：{item.get('evidence', 'N/A')}")
            self._log(f"  已执行 Payload：{payloads}")
