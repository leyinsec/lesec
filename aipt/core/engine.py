import asyncio
import time
import logging
from datetime import datetime
from typing import Optional, List, Set
from urllib.parse import urlparse

from .config import Config
from .models import ScanResult, Vulnerability
from .async_engine import AsyncHTTPClient, AsyncCrawler
from .ai_detector import MLAnomalyDetector
from .auth_manager import AuthManager
from .report_generator import ReportGenerator
from ..scanners.vulnerability_scanner import VulnerabilityScanner
from ..scanners.js_auditor import JSAuditor


class ScanEngine:
    def __init__(self, config: Config):
        self.config = config
        self.result = ScanResult()
        self.logger = self._setup_logging()
        self.client: Optional[AsyncHTTPClient] = None
        self.crawler: Optional[AsyncCrawler] = None
        self.ai_detector: Optional[MLAnomalyDetector] = None
        self.auth_manager: Optional[AuthManager] = None
        self.vuln_scanner: Optional[VulnerabilityScanner] = None
        self.js_auditor: Optional[JSAuditor] = None
        self.report_generator = ReportGenerator(config.report)

    def _setup_logging(self) -> logging.Logger:
        logger = logging.getLogger("aipt")
        logger.setLevel(getattr(logging, self.config.logging.level.upper(), logging.INFO))

        if self.config.logging.console_output:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        if self.config.logging.file:
            from logging.handlers import RotatingFileHandler
            file_handler = RotatingFileHandler(
                self.config.logging.file,
                maxBytes=self.config.logging.max_size,
                backupCount=self.config.logging.backup_count
            )
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

        return logger

    async def scan(self, target_url: str) -> ScanResult:
        self.result = ScanResult(target=target_url)
        self.result.start_time = datetime.now()

        self.logger.info(f"Starting AI-Enhanced Penetration Test on {target_url}")
        self.logger.info("=" * 60)

        async with AsyncHTTPClient(self.config) as client:
            self.client = client
            self.crawler = AsyncCrawler(client, self.config)
            self.ai_detector = MLAnomalyDetector(self.config.ai)
            self.auth_manager = AuthManager(self.config.auth, client)
            self.vuln_scanner = VulnerabilityScanner(client, self.config, self.ai_detector)
            self.js_auditor = JSAuditor(client, self.config.js_audit)

            if self.config.auth.enabled:
                auth_success = await self.auth_manager.authenticate()
                if not auth_success:
                    self.logger.warning("Authentication failed, continuing without auth")

            try:
                await self._crawl_phase(target_url)
                await self._scan_phase()
                await self._js_audit_phase()
                await self._ai_analysis_phase()

            except Exception as e:
                self.logger.error(f"Scan error: {e}")
                self.result.errors.append(str(e))

        self.result.end_time = datetime.now()
        self.result.duration = (self.result.end_time - self.result.start_time).total_seconds()

        self.vuln_scanner.deduplicate_vulnerabilities()
        self.result.vulnerabilities = self.vuln_scanner.vulnerabilities

        self.logger.info("=" * 60)
        self.logger.info(f"Scan completed in {self.result.duration:.2f} seconds")
        self.logger.info(f"URLs discovered: {self.result.urls_discovered}")
        self.logger.info(f"Forms discovered: {self.result.forms_discovered}")
        self.logger.info(f"Vulnerabilities found: {len(self.result.vulnerabilities)}")

        for severity, count in self.result.severity_summary.items():
            if count > 0:
                self.logger.info(f"  {severity}: {count}")

        return self.result

    async def _crawl_phase(self, target_url: str) -> None:
        self.logger.info("Phase 1: Web Crawling")

        urls, forms, endpoints = await self.crawler.crawl(
            target_url,
            max_depth=self.config.scan.max_depth
        )

        self.result.urls_discovered = len(urls)
        self.result.forms_discovered = len(forms)
        self.result.endpoints_discovered = len(endpoints)
        self.result.forms = forms
        self.result.endpoints = endpoints

        self.logger.info(f"Discovered {len(urls)} URLs, {len(forms)} forms, {len(endpoints)} endpoints")

    async def _scan_phase(self) -> None:
        self.logger.info("Phase 2: Vulnerability Scanning")

        urls = self.crawler.discovered_urls
        forms = self.result.forms
        endpoints = self.result.endpoints

        vulnerabilities = await self.vuln_scanner.scan_all(urls, forms, endpoints)
        self.logger.info(f"Found {len(vulnerabilities)} vulnerabilities")

    async def _js_audit_phase(self) -> None:
        if not self.config.js_audit.enabled:
            return

        self.logger.info("Phase 3: JavaScript Security Audit")

        js_urls = set()
        for url in list(self.crawler.discovered_urls)[:self.config.js_audit.max_files]:
            try:
                response = await self.client.get(url)
                if response.is_success and 'text/html' in response.headers.get('Content-Type', ''):
                    discovered_js = await self.js_auditor.discover_js_files(response.text, url)
                    js_urls.update(discovered_js)
            except Exception as e:
                self.logger.debug(f"JS discovery error for {url}: {e}")

        if js_urls:
            js_findings = await self.js_auditor.audit(js_urls)
            self.result.js_files_analyzed = len(self.js_auditor.js_files)
            self.result.js_files = self.js_auditor.js_files

            for finding in js_findings:
                self.result.vulnerabilities.append(finding)

            self.logger.info(f"JS audit found {len(js_findings)} issues")
        else:
            self.logger.info("No JavaScript files found for analysis")

    async def _ai_analysis_phase(self) -> None:
        if not self.config.ai.enabled:
            return

        self.logger.info("Phase 4: AI-Powered Analysis")

        behavioral_findings = self.ai_detector.behavioral_analysis(
            [resp for resp in self.crawler.discovered_urls]
        )

        for finding in behavioral_findings:
            vuln = Vulnerability(
                type=VulnType.BUSINESS_LOGIC,
                severity=Severity(finding['severity']),
                title=finding['type'],
                description=finding['description'],
                ai_detected=True,
                ai_confidence=finding['confidence'],
                tags=["ai-detected", "behavioral"]
            )
            self.result.vulnerabilities.append(vuln)

        self.logger.info(f"AI analysis complete")

    def generate_reports(self) -> dict:
        self.logger.info("Generating reports")
        return self.report_generator.generate(self.result)

    async def run_full_scan(self, target_url: str) -> ScanResult:
        result = await self.scan(target_url)
        reports = self.generate_reports()

        self.logger.info("Reports generated:")
        for fmt, path in reports.items():
            self.logger.info(f"  {fmt.upper()}: {path}")

        return result
