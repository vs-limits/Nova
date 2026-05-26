from __future__ import annotations

from collections import Counter, defaultdict
import os
from pathlib import Path
from typing import Any

from backend.helper.utils import ensure_dir, write_json
from backend.helper.vuln_types import category_group, category_label, category_sort_key


class PayloadAgent:
    def enrich(self, audit: dict) -> dict:
        return audit

    def build_report(
        self,
        target_url: str,
        webscan: dict,
        payload_result: dict,
        report_dir: Path,
        target_probe: dict | None = None,
    ) -> tuple[dict, Path, Path]:
        ensure_dir(report_dir)
        target_probe = target_probe or webscan.get("target_probe", {})
        raw_findings = payload_result.get("findings", [])
        report_confirmed_only = self._env_bool("NOVA_REPORT_CONFIRMED_ONLY", True)
        findings_for_report = (
            [item for item in raw_findings if item.get("status") == "确认漏洞"]
            if report_confirmed_only
            else raw_findings
        )
        findings = [
            self._with_category_metadata(item)
            for item in sorted(
                findings_for_report,
                key=lambda item: self._severity_score(item.get("severity", "Info")),
                reverse=True,
            )
        ]
        finding_type_summary = self._finding_type_summary(findings)
        raw_llm_advice = payload_result.get("llm_payload_advice", [])
        llm_advice = raw_llm_advice
        if report_confirmed_only and not findings:
            llm_advice = []
        llm_summary = payload_result.get("llm_payload_summary", {})
        report = {
            "agent": "Auditor Agent",
            "summary": {
                "target": target_url,
                "final_url": target_probe.get("final_url") or webscan.get("final_url"),
                "generated_at": payload_result.get("audited_at"),
                "status_code": webscan.get("status_code") or target_probe.get("status_code"),
                "title": webscan.get("title"),
                "total_findings": len(findings),
                "raw_total_findings": len(raw_findings),
                "report_confirmed_only": report_confirmed_only,
                "risk_level": self._risk_level(findings),
                "auth_required": bool(target_probe.get("auth_required")),
                "auth_type_guess": target_probe.get("auth_type_guess", "none"),
                "confirmed": len([item for item in raw_findings if item.get("status") == "确认漏洞"]),
                "suspected": len([item for item in raw_findings if item.get("status") == "疑似漏洞"]),
                "llm_payload_allowed": len([item for item in llm_advice if item.get("allowed")]),
                "llm_payload_blocked": len([item for item in llm_advice if not item.get("allowed")]),
                "finding_types": finding_type_summary,
            },
            "target_probe": target_probe,
            "findings": findings,
            "finding_types": finding_type_summary,
            "llm_payload_advice": llm_advice,
            "llm_payload_summary": llm_summary,
            "artifacts": {
                "target_probe": ".Nova/TargetProbe_agent.json",
                "webscan": ".Nova/Webscan_agent.json",
                "audit": ".Nova/Auditor_agent.json",
            },
        }

        json_path = report_dir / "scan_report.json"
        markdown_path = report_dir / "scan_report.md"
        write_json(json_path, report)
        markdown_path.write_text(self._markdown(report), encoding="utf-8-sig")

        legacy_json_path = report_dir / "payload_report.json"
        legacy_markdown_path = report_dir / "payload_report.md"
        write_json(legacy_json_path, report)
        legacy_markdown_path.write_text(self._markdown(report), encoding="utf-8-sig")
        return report, json_path, markdown_path

    def _severity_score(self, severity: str) -> int:
        return {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}.get(severity, 0)

    def _env_bool(self, name: str, default: bool) -> bool:
        value = os.getenv(name)
        if value is None:
            return default
        return value.strip().lower() in {"1", "true", "yes", "on"}

    def _risk_level(self, findings: list[dict]) -> str:
        if any(item.get("severity") == "Critical" for item in findings):
            return "Critical"
        if any(item.get("severity") == "High" for item in findings):
            return "High"
        if any(item.get("severity") == "Medium" for item in findings):
            return "Medium"
        if findings:
            return "Low"
        return "Info"

    def _with_category_metadata(self, finding: dict) -> dict:
        item = dict(finding)
        category = str(item.get("category") or "unknown")
        item.setdefault("category_label", category_label(category))
        item.setdefault("category_group", category_group(category))
        return item

    def _finding_type_summary(self, findings: list[dict]) -> list[dict[str, Any]]:
        counts: dict[str, int] = {}
        severities: dict[str, str] = {}
        for finding in findings:
            category = str(finding.get("category") or "unknown")
            counts[category] = counts.get(category, 0) + 1
            current = severities.get(category, "Info")
            if self._severity_score(str(finding.get("severity", "Info"))) > self._severity_score(current):
                severities[category] = str(finding.get("severity", "Info"))

        return [
            {
                "category": category,
                "label": category_label(category),
                "group": category_group(category),
                "count": counts[category],
                "max_severity": severities.get(category, "Info"),
            }
            for category in sorted(counts, key=category_sort_key)
        ]

    def _group_findings_by_type(self, findings: list[dict]) -> dict[str, list[dict]]:
        grouped: dict[str, list[dict]] = defaultdict(list)
        for finding in findings:
            grouped[str(finding.get("category") or "unknown")].append(finding)
        return dict(sorted(grouped.items(), key=lambda item: category_sort_key(item[0])))

    def _finding_type_section(self, report: dict) -> list[str]:
        finding_types = report.get("finding_types", [])
        lines = ["## 漏洞类型汇总", ""]
        if not finding_types:
            lines.extend(["本次报告没有需要展示的漏洞类型。", ""])
            return lines

        for item in finding_types:
            lines.append(
                f"- {item.get('label')}：{item.get('count')} 项，最高严重性 {item.get('max_severity')}，分组 {item.get('group')}"
            )
        lines.append("")
        return lines

    def _markdown(self, report: dict) -> str:
        summary = report["summary"]
        probe = report.get("target_probe", {})
        auth = probe.get("auth", {})
        lines = [
            "# NOVA 扫描报告",
            "",
            f"- 目标地址：{summary['target']}",
            f"- 最终地址：{summary.get('final_url') or 'N/A'}",
            f"- 生成时间：{summary.get('generated_at') or 'N/A'}",
            f"- 页面标题：{summary.get('title') or 'N/A'}",
            f"- 状态码：{summary.get('status_code') or 'N/A'}",
            f"- 风险等级：{summary['risk_level']}",
            f"- 展示发现数量：{summary['total_findings']}",
            f"- 确认漏洞：{summary.get('confirmed', 0)}",
            f"- 疑似漏洞：{summary.get('suspected', 0)}",
            f"- 报告过滤：{'仅展示确认漏洞' if summary.get('report_confirmed_only') else '展示全部发现'}",
            "",
            "## 目标探测结果",
            "",
            f"- 是否可达：{'是' if probe.get('reachable') else '否'}",
            f"- DNS 地址：{', '.join(probe.get('dns', {}).get('addresses', [])) or 'N/A'}",
            f"- TLS 可用：{self._format_bool(probe.get('tls', {}).get('valid'))}",
            f"- 是否在扫描边界内：{'是' if probe.get('in_scope') else '否'}",
            f"- 是否需要认证：{'是' if probe.get('auth_required') else '否'}",
            f"- 认证类型判断：{probe.get('auth_type_guess', 'none')}",
            f"- 已配置认证头：{', '.join(auth.get('header_names', [])) or '无'}",
            f"- 跳转次数：{len(probe.get('redirect_chain', []))}",
            f"- 探测错误：{'; '.join(probe.get('probe_errors', [])) or '无'}",
            "",
        ]

        lines.extend(self._finding_type_section(report))
        lines.extend(["## 发现项", ""])

        if not report["findings"]:
            lines.extend(["未发现明显风险。", ""])
        else:
            for category, typed_findings in self._group_findings_by_type(report["findings"]).items():
                lines.extend([f"### {category_label(category)}", ""])
                for finding in typed_findings:
                    lines.extend(
                        [
                            f"#### [{finding['severity']}] {finding['title']}",
                            "",
                            f"- 编号：{finding['id']}",
                            f"- 状态：{finding.get('status', 'N/A')}",
                            f"- 漏洞类型：{finding.get('category_label') or category_label(finding.get('category'))}",
                            f"- 类型标识：{finding.get('category', 'N/A')}",
                            f"- 类型分组：{finding.get('category_group') or category_group(finding.get('category'))}",
                            f"- 置信度：{finding['confidence']}",
                            f"- URL：{finding.get('url', 'N/A')}",
                            f"- 证据：{finding.get('evidence', 'N/A')}",
                            f"- 漏洞细化：{self._format_details(finding.get('details') or finding.get('request_response', {}).get('sqli_details', {}))}",
                            f"- 已执行 payload：{', '.join(finding.get('payloads', [])) or 'N/A'}",
                            f"- 请求/响应摘要：{self._format_evidence(finding.get('request_response', {}))}",
                            f"- 修复建议：{finding.get('recommendation', 'N/A')}",
                            f"- LLM 分析：{finding.get('llm_analysis', 'N/A') or 'N/A'}",
                            "",
                        ]
                    )

        lines.extend(self._candidate_payload_section(report))
        return "\n".join(lines) + "\n"

    def _format_details(self, details: dict[str, Any]) -> str:
        if not details:
            return "N/A"
        parts = []
        if details.get("dbms_guess"):
            parts.append(f"数据库类型={details.get('dbms_guess')}")
        if details.get("injection_context"):
            parts.append(f"注入上下文={details.get('injection_context')}")
        if details.get("column_count"):
            parts.append(f"列数={details.get('column_count')}")
        if details.get("visible_columns"):
            parts.append(f"回显列={', '.join(str(item) for item in details.get('visible_columns', []))}")
        if details.get("comment_suffix"):
            parts.append(f"注释后缀={details.get('comment_suffix')}")
        if details.get("payload_pattern"):
            parts.append(f"推荐模式={details.get('payload_pattern')}")
        if details.get("techniques"):
            parts.append(f"验证技术={', '.join(details.get('techniques', []))}")
        if details.get("verification_method"):
            parts.append(f"验证方式={details.get('verification_method')}")
        if details.get("source"):
            parts.append(f"DOM source={details.get('source')}")
        if details.get("sink"):
            parts.append(f"DOM sink={details.get('sink')}")
        if details.get("target_param"):
            parts.append(f"参数={details.get('target_param')}")
        if details.get("candidate_payload"):
            parts.append(f"候选 payload={details.get('candidate_payload')}")
        return "；".join(parts) if parts else "N/A"

    def _candidate_payload_section(self, report: dict) -> list[str]:
        advice = report.get("llm_payload_advice", [])
        summary = report.get("llm_payload_summary", {})
        lines = [
            "## 候选 Payload",
            "",
            "说明：本节 payload 由 LLM 和/或 NOVA 本地上下文模板生成，并经过本地 Safety Filter。第一版仅写入报告，不自动请求目标，也不参与漏洞确认。",
            "特别说明：SQL 盲注必须比较 true/false 成对响应差异；单条 payload 返回 `exists` 不能证明注入成功。",
            "",
        ]

        if not summary.get("enabled") or summary.get("status") not in {"ok", "local_only"}:
            lines.extend([f"候选 Payload 未启用或不可用：{summary.get('message') or '无可用信息'}", ""])
            return lines

        allowed = [item for item in advice if item.get("allowed")]
        blocked = [item for item in advice if not item.get("allowed")]
        lines.extend(
            [
                f"- 生成数量：{summary.get('generated', len(advice))}",
                f"- 允许展示：{summary.get('allowed', len(allowed))}",
                f"- 已过滤：{summary.get('blocked', len(blocked))}",
                f"- 本地候选：{summary.get('local_candidates', 'N/A')}",
                f"- LLM 候选：{summary.get('llm_candidates', 'N/A')}",
                f"- 报告模式：{'仅报告，不执行' if summary.get('report_only', True) else '可执行'}",
                f"- 生成状态：{summary.get('message') or 'N/A'}",
                "",
            ]
        )

        if allowed:
            grouped: dict[str, list[dict]] = defaultdict(list)
            for item in allowed:
                key = item.get("input_point") or item.get("target_param") or "未标注输入点"
                grouped[key].append(item)
            for input_point, items in grouped.items():
                lines.extend([f"### 输入点：{input_point}", ""])
                pair_groups: dict[str, list[dict]] = defaultdict(list)
                singles: list[dict] = []
                for item in items:
                    if item.get("pair_id"):
                        pair_groups[item["pair_id"]].append(item)
                    else:
                        singles.append(item)

                for pair_id, pair_items in pair_groups.items():
                    pair_items = sorted(pair_items, key=lambda item: item.get("pair_role") != "true")
                    first = pair_items[0]
                    lines.extend(
                        [
                            f"- 类型：{category_label(first.get('category'))}（{first.get('category', 'unknown')}）成对候选（{pair_id}）",
                            f"- 参数：{first.get('target_param') or 'N/A'}",
                            f"- 来源：{first.get('source', 'llm')}",
                        ]
                    )
                    for item in pair_items:
                        label = "true 条件" if item.get("pair_role") == "true" else "false 条件"
                        lines.append(f"- {label} payload：`{item.get('payload', '')}`")
                        lines.append(f"- {label} 预期信号：{item.get('expected_signal') or 'N/A'}")
                    lines.extend(
                        [
                            f"- 用途：{first.get('purpose') or 'N/A'}",
                            f"- 过滤结果：{first.get('filter_reason')}",
                            "",
                        ]
                    )

                for item in singles:
                    lines.extend(
                        [
                            f"- 类型：{category_label(item.get('category'))}（{item.get('category', 'unknown')}）",
                            f"- 参数：{item.get('target_param') or 'N/A'}",
                            f"- 来源：{item.get('source', 'llm')}",
                            f"- 候选 payload：`{item.get('payload', '')}`",
                            f"- 用途：{item.get('purpose') or 'N/A'}",
                            f"- 预期信号：{item.get('expected_signal') or 'N/A'}",
                            f"- 过滤结果：{item.get('filter_reason')}",
                            "",
                        ]
                    )
        else:
            lines.extend(["没有通过 Safety Filter 的候选 payload。", ""])

        if blocked:
            reason_counts = Counter(item.get("filter_reason") or "未知原因" for item in blocked)
            lines.extend(["### 已过滤 Payload 统计", ""])
            for reason, count in reason_counts.items():
                lines.append(f"- {reason}：{count}")
            lines.append("")
            lines.append("已过滤 payload 只展示摘要，不作为可直接复现步骤：")
            for item in blocked[:10]:
                lines.append(
                    f"- 类型：{category_label(item.get('category'))}（{item.get('category', 'unknown')}）；参数：{item.get('target_param') or 'N/A'}；摘要：`{item.get('payload')}`；原因：{item.get('filter_reason')}"
                )
            lines.append("")
        return lines

    def _format_bool(self, value: object) -> str:
        if value is True:
            return "是"
        if value is False:
            return "否"
        return "未检测"

    def _format_evidence(self, evidence: dict[str, Any]) -> str:
        if not evidence:
            return "N/A"
        if "baseline" in evidence:
            parts = []
            for name in ("baseline", "true_case", "false_case"):
                item = evidence.get(name, {})
                parts.append(
                    f"{name}: status={item.get('status_code')}, length={item.get('body_length')}, {item.get('matched', '')}".strip()
                )
            return " | ".join(parts)
        if "error_probe" in evidence or "followup" in evidence:
            parts = []
            error_probe = evidence.get("error_probe", {})
            if error_probe:
                parts.append(
                    f"error_probe: status={error_probe.get('status_code')}, length={error_probe.get('body_length')}, {error_probe.get('matched', '')}".strip()
                )
            followup = evidence.get("followup", {})
            if followup:
                if followup.get("column_count"):
                    parts.append(f"column_count={followup.get('column_count')}")
                union_probe = followup.get("union_probe", {})
                if union_probe:
                    markers = ", ".join(union_probe.get("reflected_markers", [])) or "none"
                    parts.append(f"union_reflected={markers}")
            return " | ".join(parts) if parts else "N/A"
        return (
            f"status={evidence.get('status_code', 'N/A')}, "
            f"length={evidence.get('body_length', 'N/A')}, "
            f"matched={evidence.get('matched', 'N/A')}"
        )
