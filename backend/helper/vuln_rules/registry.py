from __future__ import annotations

from urllib.parse import urlparse

from backend.helper.evidence.finding import FindingFactory
from backend.helper.evidence.http import HttpClient
from backend.helper.evidence.matchers import prefer_xss_checks
from backend.helper.settings import RuntimeSettings
from backend.helper.vuln_rules.base import RuleContext
from backend.helper.vuln_rules.rules import (
    ActiveProbeFailureRule,
    ActiveProbeLimitRule,
    CommandInjectionRule,
    CookieFlagsRule,
    CryptoPassiveRule,
    CspWeaknessRule,
    CsrfTokenRule,
    DomXssRule,
    DvwaCaptchaBypassRule,
    DvwaCommandInjectionFormRule,
    DvwaCspBypassRule,
    DvwaJavascriptRule,
    FileInclusionRule,
    FileUploadRule,
    HeaderDisclosureRule,
    JavaScriptAnalysisRule,
    OpenRedirectRule,
    PassiveDisclosureRule,
    PendingInputRule,
    ReflectedXssRule,
    SecurityHeadersRule,
    SsrfCandidateRule,
    SqliRule,
    StoredXssRule,
    WeakSessionRule,
    WeakSessionGenerateRule,
)


class RuleRegistry:
    def __init__(
        self,
        passive_rules: list | None = None,
        page_rules: list | None = None,
        form_rules: list | None = None,
        input_rules: list | None = None,
    ) -> None:
        self.passive_rules = passive_rules or [
            SecurityHeadersRule(),
            HeaderDisclosureRule(),
            CspWeaknessRule(),
            CookieFlagsRule(),
            WeakSessionRule(),
            CryptoPassiveRule(),
            PassiveDisclosureRule(),
        ]
        self.page_rules = page_rules or [
            DvwaCaptchaBypassRule(),
            DvwaCspBypassRule(),
            DvwaJavascriptRule(),
            JavaScriptAnalysisRule(),
        ]
        self.form_rules = form_rules or [
            DvwaCommandInjectionFormRule(),
            CsrfTokenRule(),
            WeakSessionGenerateRule(),
            StoredXssRule(),
            FileUploadRule(),
        ]
        self.input_rules = input_rules or [
            DomXssRule(),
            OpenRedirectRule(),
            SsrfCandidateRule(),
            SqliRule(),
            FileInclusionRule(),
            CommandInjectionRule(),
            ReflectedXssRule(),
            PendingInputRule(),
        ]
        self.limit_rule = ActiveProbeLimitRule()
        self.failure_rule = ActiveProbeFailureRule()

    @classmethod
    def default_rules(cls) -> "RuleRegistry":
        return cls()

    def run(
        self,
        webscan: dict,
        settings: RuntimeSettings,
        finding_factory: FindingFactory,
        http_client: HttpClient,
    ) -> list[dict]:
        target = webscan.get("target", "")
        headers = {key.lower(): value for key, value in webscan.get("headers", {}).items()}
        base_context = RuleContext(
            settings=settings,
            webscan=webscan,
            finding_factory=finding_factory,
            http_client=http_client,
            target=target,
            headers=headers,
        )
        findings: list[dict] = []
        for rule in self.passive_rules:
            findings.extend(rule.evaluate(base_context))

        findings.extend(self._run_page_rules(webscan, settings, finding_factory, http_client, target, headers))
        findings.extend(self._run_form_rules(webscan, settings, finding_factory, http_client, target, headers))
        findings.extend(self._run_input_rules(webscan, settings, finding_factory, http_client, target, headers))
        return findings

    def _run_page_rules(
        self,
        webscan: dict,
        settings: RuntimeSettings,
        finding_factory: FindingFactory,
        http_client: HttpClient,
        target: str,
        headers: dict[str, str],
    ) -> list[dict]:
        findings: list[dict] = []
        pages = webscan.get("pages", []) or [webscan]
        if not any(page.get("forms") for page in pages) and webscan.get("forms"):
            pages = [webscan]
        for page in pages:
            if not self._page_in_focused_target_path(settings, target, page):
                continue
            context = RuleContext(
                settings=settings,
                webscan=webscan,
                finding_factory=finding_factory,
                http_client=http_client,
                target=target,
                headers=headers,
                page=page,
            )
            for rule in self.page_rules:
                findings.extend(rule.evaluate(context))
        return findings

    def _run_form_rules(
        self,
        webscan: dict,
        settings: RuntimeSettings,
        finding_factory: FindingFactory,
        http_client: HttpClient,
        target: str,
        headers: dict[str, str],
    ) -> list[dict]:
        findings: list[dict] = []
        pages = webscan.get("pages", []) or [webscan]
        if not any(page.get("forms") for page in pages) and webscan.get("forms"):
            pages = [webscan]
        for page in pages:
            for form in page.get("forms", []):
                if form.get("active_testable") is False:
                    continue
                context = RuleContext(
                    settings=settings,
                    webscan=webscan,
                    finding_factory=finding_factory,
                    http_client=http_client,
                    target=target,
                    headers=headers,
                    page=page,
                    form=form,
                )
                for rule in self.form_rules:
                    findings.extend(rule.evaluate(context))
        return findings

    def _run_input_rules(
        self,
        webscan: dict,
        settings: RuntimeSettings,
        finding_factory: FindingFactory,
        http_client: HttpClient,
        target: str,
        headers: dict[str, str],
    ) -> list[dict]:
        findings: list[dict] = []
        pages = webscan.get("pages", []) or [webscan]
        seen: set[tuple[str, str]] = set()
        active_inputs = 0
        for page in pages:
            for input_point in page.get("input_points", []):
                if input_point.get("method", "GET").upper() != "GET":
                    continue
                name = input_point.get("name", "")
                url = input_point.get("url", "")
                if not name or not url:
                    continue
                key = (url, name)
                if key in seen:
                    continue
                seen.add(key)

                if not input_point.get("active_testable", True):
                    continue
                active_inputs += 1
                context = RuleContext(
                    settings=settings,
                    webscan=webscan,
                    finding_factory=finding_factory,
                    http_client=http_client,
                    target=target,
                    headers=headers,
                    page=page,
                    input_point=input_point,
                )
                if active_inputs > settings.max_active_inputs:
                    findings.append(self.limit_rule.limit_finding(context, url))
                    return findings

                for rule in self._ordered_input_rules(page, input_point):
                    result = rule.evaluate(context)
                    if result:
                        findings.extend(result)
                        break
                    if context.probe_failed:
                        findings.append(self.failure_rule.failure_finding(context, url, name))
                        break
        return findings

    def _ordered_input_rules(self, page: dict, input_point: dict) -> list:
        by_class = {rule.__class__.__name__: rule for rule in self.input_rules}
        dom = by_class["DomXssRule"]
        reflected = by_class["ReflectedXssRule"]
        redirect = by_class["OpenRedirectRule"]
        ssrf = by_class["SsrfCandidateRule"]
        sqli = by_class["SqliRule"]
        lfi = by_class["FileInclusionRule"]
        command = by_class["CommandInjectionRule"]
        pending = by_class["PendingInputRule"]
        if prefer_xss_checks(page, input_point):
            return [dom, reflected, redirect, ssrf, sqli, lfi, command, pending]
        return [dom, redirect, ssrf, sqli, lfi, command, reflected, pending]

    def _page_in_focused_target_path(self, settings: RuntimeSettings, target: str, page: dict) -> bool:
        if not settings.focus_target_path:
            return True
        if page.get("active_testable") is False and page.get("active_scope_reason") == "outside_target_path":
            return False

        target_path = urlparse(target).path or "/"
        if target_path == "/":
            return True
        page_url = str(page.get("final_url") or page.get("url") or "")
        if not page_url:
            return True
        page_path = urlparse(page_url).path or "/"
        normalized_target = target_path.rstrip("/")
        return page_path == normalized_target or page_path.startswith(f"{normalized_target}/")
