import asyncio
import re
import json
import hashlib
from typing import List, Dict, Optional, Set, Tuple, Any
from urllib.parse import urljoin, urlparse
from collections import defaultdict
import logging

from ..core.config import JSAuditConfig
from ..core.models import Vulnerability, Severity, VulnType, Evidence, JSFile
from ..core.async_engine import AsyncHTTPClient


class JSPatternMatcher:
    def __init__(self):
        self.patterns = self._compile_patterns()

    def _compile_patterns(self) -> Dict[str, Dict[str, Any]]:
        return {
            'eval_usage': {
                'pattern': re.compile(r'\beval\s*\(', re.IGNORECASE),
                'severity': Severity.HIGH,
                'description': 'Use of eval() allows arbitrary code execution',
                'cwe': 'CWE-95',
                'remediation': 'Avoid eval(). Use JSON.parse() for JSON data or safer alternatives.'
            },
            'function_constructor': {
                'pattern': re.compile(r'new\s+Function\s*\(', re.IGNORECASE),
                'severity': Severity.HIGH,
                'description': 'Function constructor usage similar to eval()',
                'cwe': 'CWE-95',
                'remediation': 'Avoid new Function(). Use static function definitions.'
            },
            'settimeout_string': {
                'pattern': re.compile(r'setTimeout\s*\(\s*["\']', re.IGNORECASE),
                'severity': Severity.HIGH,
                'description': 'setTimeout with string argument executes code dynamically',
                'cwe': 'CWE-95',
                'remediation': 'Use function references instead of strings in setTimeout/setInterval.'
            },
            'setinterval_string': {
                'pattern': re.compile(r'setInterval\s*\(\s*["\']', re.IGNORECASE),
                'severity': Severity.HIGH,
                'description': 'setInterval with string argument executes code dynamically',
                'cwe': 'CWE-95',
                'remediation': 'Use function references instead of strings in setInterval.'
            },
            'innerHTML_assignment': {
                'pattern': re.compile(r'\.innerHTML\s*=', re.IGNORECASE),
                'severity': Severity.HIGH,
                'description': 'Direct innerHTML assignment is a potential XSS vector',
                'cwe': 'CWE-79',
                'remediation': 'Use textContent or sanitize HTML before assignment.'
            },
            'outerHTML_assignment': {
                'pattern': re.compile(r'\.outerHTML\s*=', re.IGNORECASE),
                'severity': Severity.HIGH,
                'description': 'outerHTML assignment can lead to XSS',
                'cwe': 'CWE-79',
                'remediation': 'Avoid outerHTML with user input. Use safer DOM manipulation.'
            },
            'document_write': {
                'pattern': re.compile(r'document\.write\s*\(', re.IGNORECASE),
                'severity': Severity.HIGH,
                'description': 'document.write() is a dangerous XSS vector',
                'cwe': 'CWE-79',
                'remediation': 'Use DOM manipulation methods instead of document.write().'
            },
            'document_writeln': {
                'pattern': re.compile(r'document\.writeln\s*\(', re.IGNORECASE),
                'severity': Severity.HIGH,
                'description': 'document.writeln() is a dangerous XSS vector',
                'cwe': 'CWE-79',
                'remediation': 'Use DOM manipulation methods instead of document.writeln().'
            },
            'dangerous_protocols': {
                'pattern': re.compile(r'(javascript:|data:|vbscript:|mhtml:)', re.IGNORECASE),
                'severity': Severity.HIGH,
                'description': 'Dangerous URL protocol detected',
                'cwe': 'CWE-79',
                'remediation': 'Validate and sanitize URLs. Block dangerous protocols.'
            },
            'dom_xss_sinks': {
                'pattern': re.compile(r'(?:location|location\.href|document\.URL|document\.documentURI|document\.referrer|window\.name|history\.pushState|history\.replaceState)\s*(?:\.|\[)', re.IGNORECASE),
                'severity': Severity.HIGH,
                'description': 'DOM XSS sink detected - user input flows to dangerous sink',
                'cwe': 'CWE-79',
                'remediation': 'Validate and sanitize data before passing to DOM sinks.'
            },
            'jquery_html': {
                'pattern': re.compile(r'\$\s*\([^)]*\)\.html\s*\(', re.IGNORECASE),
                'severity': Severity.HIGH,
                'description': 'jQuery .html() with potential user input',
                'cwe': 'CWE-79',
                'remediation': 'Use .text() instead of .html() when possible. Sanitize input.'
            },
            'jquery_append': {
                'pattern': re.compile(r'\$\s*\([^)]*\)\.(?:append|prepend|after|before)\s*\(', re.IGNORECASE),
                'severity': Severity.MEDIUM,
                'description': 'jQuery DOM insertion with potential user input',
                'cwe': 'CWE-79',
                'remediation': 'Sanitize content before DOM insertion.'
            },
            'hardcoded_secrets': {
                'pattern': re.compile(r'(?:api[_-]?key|secret[_-]?key|password|passwd|token|auth[_-]?token|access[_-]?token|bearer)\s*[:=]\s*["\'][^"\']{8,}["\']', re.IGNORECASE),
                'severity': Severity.CRITICAL,
                'description': 'Potential hardcoded sensitive information',
                'cwe': 'CWE-798',
                'remediation': 'Use environment variables or secure key management services.'
            },
            'aws_credentials': {
                'pattern': re.compile(r'(?:AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16})', re.IGNORECASE),
                'severity': Severity.CRITICAL,
                'description': 'AWS Access Key ID detected',
                'cwe': 'CWE-798',
                'remediation': 'Use IAM roles or AWS Secrets Manager. Never hardcode credentials.'
            },
            'private_key': {
                'pattern': re.compile(r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----'),
                'severity': Severity.CRITICAL,
                'description': 'Private key found in source code',
                'cwe': 'CWE-798',
                'remediation': 'Store private keys in secure vaults, never in source code.'
            },
            'weak_crypto': {
                'pattern': re.compile(r'\b(md5|sha1|des|rc4|ecb)\s*\(', re.IGNORECASE),
                'severity': Severity.HIGH,
                'description': 'Weak cryptographic algorithm detected',
                'cwe': 'CWE-327',
                'remediation': 'Use strong algorithms: SHA-256+, AES-GCM, ChaCha20-Poly1305.'
            },
            'insecure_random': {
                'pattern': re.compile(r'\bMath\.random\s*\(', re.IGNORECASE),
                'severity': Severity.MEDIUM,
                'description': 'Math.random() is not cryptographically secure',
                'cwe': 'CWE-338',
                'remediation': 'Use crypto.getRandomValues() for security-sensitive operations.'
            },
            'localstorage_sensitive': {
                'pattern': re.compile(r'localStorage\.(?:set|get)Item\s*\(\s*["\'][^"\']*(?:token|key|auth|user|pass|secret)', re.IGNORECASE),
                'severity': Severity.MEDIUM,
                'description': 'Sensitive data stored in localStorage',
                'cwe': 'CWE-312',
                'remediation': 'Avoid storing sensitive data in localStorage. Use httpOnly cookies.'
            },
            'sessionstorage_sensitive': {
                'pattern': re.compile(r'sessionStorage\.(?:set|get)Item\s*\(\s*["\'][^"\']*(?:token|key|auth|user|pass|secret)', re.IGNORECASE),
                'severity': Severity.MEDIUM,
                'description': 'Sensitive data stored in sessionStorage',
                'cwe': 'CWE-312',
                'remediation': 'Avoid storing sensitive data in sessionStorage.'
            },
            'postmessage_no_origin': {
                'pattern': re.compile(r'postMessage\s*\([^,]+\)', re.IGNORECASE),
                'severity': Severity.HIGH,
                'description': 'postMessage without origin validation',
                'cwe': 'CWE-346',
                'remediation': 'Always specify targetOrigin in postMessage(). Validate origin on receive.'
            },
            'postmessage_wildcard': {
                'pattern': re.compile(r'postMessage\s*\([^,]+,\s*["\']\*["\']\s*\)', re.IGNORECASE),
                'severity': Severity.HIGH,
                'description': 'postMessage with wildcard origin',
                'cwe': 'CWE-346',
                'remediation': 'Never use "*" as targetOrigin. Specify exact allowed origins.'
            },
            'cookie_no_secure': {
                'pattern': re.compile(r'document\.cookie\s*=\s*[^;]+(?!;\s*secure)', re.IGNORECASE),
                'severity': Severity.MEDIUM,
                'description': 'Cookie set without Secure flag',
                'cwe': 'CWE-614',
                'remediation': 'Always set Secure and HttpOnly flags for sensitive cookies.'
            },
            'cookie_no_httponly': {
                'pattern': re.compile(r'document\.cookie\s*=\s*[^;]+(?!;\s*HttpOnly)', re.IGNORECASE),
                'severity': Severity.MEDIUM,
                'description': 'Cookie set without HttpOnly flag',
                'cwe': 'CWE-1004',
                'remediation': 'Set HttpOnly flag to prevent JavaScript access to cookies.'
            },
            'dynamic_import': {
                'pattern': re.compile(r'import\s*\(', re.IGNORECASE),
                'severity': Severity.LOW,
                'description': 'Dynamic import detected - verify source URLs',
                'cwe': 'CWE-829',
                'remediation': 'Validate URLs before dynamic imports.'
            },
            'webpack_sourcemap': {
                'pattern': re.compile(r'//#\s*sourceMappingURL\s*=\s*([^\s]+)', re.IGNORECASE),
                'severity': Severity.LOW,
                'description': 'Source map reference found',
                'cwe': None,
                'remediation': 'Remove source maps from production builds.'
            },
            'debugger_statements': {
                'pattern': re.compile(r'\bdebugger\s*;'),
                'severity': Severity.LOW,
                'description': 'Debugger statement found',
                'cwe': 'CWE-489',
                'remediation': 'Remove debugger statements from production code.'
            },
            'console_statements': {
                'pattern': re.compile(r'console\.(?:log|debug|info|warn|error|table)\s*\('),
                'severity': Severity.LOW,
                'description': 'Console statement may leak information',
                'cwe': 'CWE-489',
                'remediation': 'Remove console statements from production code.'
            },
            'prototype_pollution': {
                'pattern': re.compile(r'(?:__proto__|constructor\.prototype)\s*=', re.IGNORECASE),
                'severity': Severity.HIGH,
                'description': 'Potential prototype pollution vulnerability',
                'cwe': 'CWE-1321',
                'remediation': 'Use Object.freeze(), Object.create(null), or validation libraries.'
            },
            'regex_dos': {
                'pattern': re.compile(r'/(?:[a-zA-Z0-9_]+/){5,}|\([^)]*\+\+?\)|\([^)]*\*\+?\)'),
                'severity': Severity.MEDIUM,
                'description': 'Complex regex pattern - potential ReDoS vulnerability',
                'cwe': 'CWE-1333',
                'remediation': 'Use regex validators. Avoid nested quantifiers with overlapping matches.'
            },
            'xml_external_entity': {
                'pattern': re.compile(r'DOMParser\s*\(\)|parseFromString', re.IGNORECASE),
                'severity': Severity.MEDIUM,
                'description': 'XML parsing without explicit XXE protection',
                'cwe': 'CWE-611',
                'remediation': 'Disable external entities in XML parsers.'
            },
            'jsonp_usage': {
                'pattern': re.compile(r'callback\s*=|jsonp|\.ajax\s*\([^)]*dataType\s*:\s*["\']jsonp["\']', re.IGNORECASE),
                'severity': Severity.MEDIUM,
                'description': 'JSONP usage detected - potential XSS risk',
                'cwe': 'CWE-79',
                'remediation': 'Use CORS instead of JSONP for cross-origin requests.'
            },
            'webrtc_leak': {
                'pattern': re.compile(r'RTCPeerConnection|getUserMedia|webkitRTCPeerConnection', re.IGNORECASE),
                'severity': Severity.LOW,
                'description': 'WebRTC may leak internal IP addresses',
                'cwe': 'CWE-200',
                'remediation': 'Use privacy-aware ICE server configuration.'
            },
        }

    def analyze(self, content: str, source: str = 'inline') -> List[Vulnerability]:
        findings = []
        lines = content.split('\n')

        for pattern_name, pattern_info in self.patterns.items():
            for i, line in enumerate(lines, 1):
                matches = pattern_info['pattern'].findall(line)
                if matches:
                    evidence = matches[0] if isinstance(matches[0], str) else str(matches[0])
                    vuln = Vulnerability(
                        type=VulnType.JS_VULNERABILITY,
                        severity=pattern_info['severity'],
                        title=f"JS: {pattern_name.replace('_', ' ').title()}",
                        description=pattern_info['description'],
                        url=source,
                        evidence=Evidence(
                            matched_pattern=evidence,
                            context=f"Line {i}: {line.strip()[:200]}"
                        ),
                        cwe_id=pattern_info.get('cwe'),
                        remediation=pattern_info.get('remediation', 'Review and fix the identified issue.'),
                        tags=["javascript", pattern_name]
                    )
                    findings.append(vuln)

        return findings


class SecretScanner:
    def __init__(self):
        self.secret_patterns = [
            (r'(?:password|passwd|pwd)\s*[:=]\s*["\'][^"\']{4,}["\']', Severity.CRITICAL, 'Hardcoded password'),
            (r'(?:bearer|basic|token)\s+[a-zA-Z0-9\-_\.]+', Severity.HIGH, 'Hardcoded authorization token'),
            (r'sk_live_[a-zA-Z0-9]{24,}', Severity.CRITICAL, 'Stripe live secret key'),
            (r'sk_test_[a-zA-Z0-9]{24,}', Severity.HIGH, 'Stripe test secret key'),
            (r'pk_live_[a-zA-Z0-9]{24,}', Severity.HIGH, 'Stripe live publishable key'),
            (r'rk_live_[a-zA-Z0-9]{24,}', Severity.CRITICAL, 'Stripe restricted key'),
            (r'https?://[^/]+\.s3\.amazonaws\.com', Severity.MEDIUM, 'AWS S3 bucket reference'),
            (r'https?://[^/]+\.blob\.core\.windows\.net', Severity.MEDIUM, 'Azure Blob Storage reference'),
            (r'ghp_[a-zA-Z0-9]{36}', Severity.CRITICAL, 'GitHub personal access token'),
            (r'gho_[a-zA-Z0-9]{36}', Severity.CRITICAL, 'GitHub OAuth token'),
            (r'ghu_[a-zA-Z0-9]{36}', Severity.CRITICAL, 'GitHub user-to-server token'),
            (r'ghs_[a-zA-Z0-9]{36}', Severity.CRITICAL, 'GitHub server-to-server token'),
            (r'ghr_[a-zA-Z0-9]{36}', Severity.CRITICAL, 'GitHub refresh token'),
            (r'AKIA[0-9A-Z]{16}', Severity.CRITICAL, 'AWS Access Key ID'),
            (r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*', Severity.CRITICAL, 'Slack token'),
            (r'sk-[a-zA-Z0-9]{20,}', Severity.CRITICAL, 'OpenAI API key'),
            (r'AIza[0-9A-Za-z_-]{35}', Severity.CRITICAL, 'Google API key'),
            (r'[0-9a-f]{32}-us[0-9]{1,2}', Severity.HIGH, 'Mailchimp API key'),
            (r'sq0csp-[0-9A-Za-z_-]{43}', Severity.CRITICAL, 'Square OAuth secret'),
            (r'[A-Za-z0-9_]{21}--[A-Za-z0-9_]{8}', Severity.HIGH, 'Twilio API key'),
            (r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', Severity.LOW, 'UUID pattern - verify if sensitive'),
        ]

    def scan(self, content: str, source: str = 'inline') -> List[Vulnerability]:
        findings = []
        lines = content.split('\n')

        for pattern, severity, description in self.secret_patterns:
            regex = re.compile(pattern, re.IGNORECASE)
            for i, line in enumerate(lines, 1):
                matches = regex.findall(line)
                for match in matches:
                    if self._is_false_positive(match, line):
                        continue

                    vuln = Vulnerability(
                        type=VulnType.JS_VULNERABILITY,
                        severity=severity,
                        title=f"Secret Exposure: {description}",
                        description=f"Potential {description} found in source code",
                        url=source,
                        evidence=Evidence(
                            matched_pattern=str(match)[:50],
                            context=f"Line {i}: {line.strip()[:200]}"
                        ),
                        cwe_id="CWE-798",
                        remediation="Remove secrets from source code. Use environment variables or secret managers.",
                        tags=["secret", "hardcoded", description.lower().replace(' ', '_')]
                    )
                    findings.append(vuln)

        return findings

    def _is_false_positive(self, match: str, line: str) -> bool:
        false_positive_patterns = [
            r'example',
            r'placeholder',
            r'dummy',
            r'test',
            r'fake',
            r'sample',
            r'your_',
            r'my_',
            r'xxx',
            r'password\s*[:=]\s*["\']\*+["\']',
        ]

        line_lower = line.lower()
        for fp_pattern in false_positive_patterns:
            if re.search(fp_pattern, line_lower):
                return True

        return False


class DependencyAnalyzer:
    def __init__(self):
        self.cdn_patterns = [
            (r'cdnjs\.cloudflare\.com', 'Cloudflare CDN'),
            (r'ajax\.googleapis\.com', 'Google CDN'),
            (r'unpkg\.com', 'unpkg CDN'),
            (r'cdn\.jsdelivr\.net', 'jsDelivr CDN'),
            (r'code\.jquery\.com', 'jQuery CDN'),
            (r'bootstrapcdn\.com', 'BootstrapCDN'),
            (r'cdn\.datatables\.net', 'DataTables CDN'),
            (r'cdn\.tinymce\.com', 'TinyMCE CDN'),
        ]

        self.version_patterns = [
            (r'jquery[/-](\d+\.\d+\.?\d*)', 'jQuery'),
            (r'vue[/-](\d+\.\d+\.?\d*)', 'Vue.js'),
            (r'react[/-](\d+\.\d+\.?\d*)', 'React'),
            (r'angular[/-](\d+\.\d+\.?\d*)', 'Angular'),
            (r'bootstrap[/-](\d+\.\d+\.?\d*)', 'Bootstrap'),
            (r'lodash[/-](\d+\.\d+\.?\d*)', 'Lodash'),
            (r'underscore[/-](\d+\.\d+\.?\d*)', 'Underscore.js'),
            (r'moment[/-](\d+\.\d+\.?\d*)', 'Moment.js'),
            (r'axios[/-](\d+\.\d+\.?\d*)', 'Axios'),
            (r'd3[/-](\d+\.\d+\.?\d*)', 'D3.js'),
        ]

        self.known_vulnerable_versions = {
            'jQuery': [
                ('<3.5.0', 'CVE-2020-11022', Severity.HIGH, 'XSS in jQuery.htmlPrefilter'),
                ('<3.4.0', 'CVE-2019-11358', Severity.MEDIUM, 'Prototype pollution'),
            ],
            'Bootstrap': [
                ('<4.3.1', 'CVE-2019-8331', Severity.HIGH, 'XSS in tooltip/popover'),
                ('<4.1.2', 'CVE-2018-14041', Severity.MEDIUM, 'XSS in data-target attribute'),
            ],
        }

    def analyze(self, content: str, source: str = 'inline') -> List[Vulnerability]:
        findings = []

        found_cdns = []
        for pattern, name in self.cdn_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                found_cdns.append(name)

        if found_cdns:
            findings.append(Vulnerability(
                type=VulnType.JS_VULNERABILITY,
                severity=Severity.LOW,
                title="Third-party CDN Dependencies",
                description=f"Uses external CDNs: {', '.join(found_cdns)}",
                url=source,
                evidence=Evidence(
                    matched_pattern=found_cdns[0],
                    context=f"Found CDNs: {', '.join(found_cdns)}"
                ),
                cwe_id="CWE-1104",
                remediation="Verify CDN integrity with SRI hashes. Consider self-hosting critical libraries.",
                tags=["dependency", "cdn"]
            ))

        for pattern, lib_name in self.version_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for version in matches:
                findings.append(Vulnerability(
                    type=VulnType.JS_VULNERABILITY,
                    severity=Severity.LOW,
                    title=f"Version Information Disclosure: {lib_name}",
                    description=f"{lib_name} version {version} exposed in source",
                    url=source,
                    evidence=Evidence(
                        matched_pattern=f"{lib_name}/{version}",
                        context=f"Library version detected"
                    ),
                    cwe_id="CWE-200",
                    remediation="Remove version information from production builds.",
                    tags=["version-disclosure", lib_name.lower()]
                ))

                if lib_name in self.known_vulnerable_versions:
                    for version_range, cve, severity, description in self.known_vulnerable_versions[lib_name]:
                        if self._is_vulnerable_version(version, version_range):
                            findings.append(Vulnerability(
                                type=VulnType.JS_VULNERABILITY,
                                severity=severity,
                                title=f"Known Vulnerable Dependency: {lib_name} {version}",
                                description=f"{lib_name} {version} is affected by {cve}: {description}",
                                url=source,
                                evidence=Evidence(
                                    matched_pattern=f"{lib_name}/{version}",
                                    context=f"CVE: {cve}"
                                ),
                                cwe_id="CWE-1035",
                                remediation=f"Upgrade {lib_name} to a patched version.",
                                references=[f"https://nvd.nist.gov/vuln/detail/{cve}"],
                                tags=["vulnerable-dependency", lib_name.lower(), cve.lower()]
                            ))

        return findings

    def _is_vulnerable_version(self, version: str, version_range: str) -> bool:
        try:
            from packaging import version as pkg_version
            current = pkg_version.parse(version)
            if version_range.startswith('<'):
                compare_version = pkg_version.parse(version_range[1:])
                return current < compare_version
            elif version_range.startswith('<='):
                compare_version = pkg_version.parse(version_range[2:])
                return current <= compare_version
        except:
            pass
        return False


class JSAuditor:
    def __init__(self, client: AsyncHTTPClient, config: JSAuditConfig):
        self.client = client
        self.config = config
        self.pattern_matcher = JSPatternMatcher()
        self.secret_scanner = SecretScanner()
        self.dependency_analyzer = DependencyAnalyzer()
        self.js_files: List[JSFile] = []
        self.inline_scripts: List[str] = []
        self.logger = logging.getLogger(__name__)

    async def discover_js_files(self, html_content: str, base_url: str) -> Set[str]:
        js_urls = set()

        script_tags = re.findall(r'<script[^>]+src=["\']([^"\']+)["\'][^>]*>', html_content, re.IGNORECASE)
        for src in script_tags:
            if src.endswith('.js') or 'js' in src.lower():
                absolute_url = urljoin(base_url, src)
                js_urls.add(absolute_url)

        inline_scripts = re.findall(r'<script(?![^>]*src)[^>]*>([^<]+)</script>', html_content, re.IGNORECASE | re.DOTALL)
        for script in inline_scripts:
            script = script.strip()
            if script and len(script) > 50:
                self.inline_scripts.append(script)

        return js_urls

    async def fetch_js_content(self, js_url: str) -> Optional[str]:
        try:
            response = await self.client.get(js_url)
            if response.is_error or response.status_code != 200:
                return None

            content_type = response.headers.get('Content-Type', '').lower()
            if 'javascript' in content_type or 'application' in content_type or not content_type:
                return response.text
            return None
        except Exception as e:
            self.logger.warning(f"Failed to fetch {js_url}: {e}")
            return None

    async def audit(self, js_urls: Set[str]) -> List[Vulnerability]:
        self.logger.info(f"Starting JavaScript security audit on {len(js_urls)} files")
        all_findings = []

        tasks = []
        for js_url in js_urls:
            tasks.append(self._audit_js_file(js_url))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, list):
                all_findings.extend(result)

        for inline_script in self.inline_scripts:
            findings = self._analyze_js_content(inline_script, 'inline')
            all_findings.extend(findings)

        self.logger.info(f"JS audit complete. Found {len(all_findings)} issues")
        return all_findings

    async def _audit_js_file(self, js_url: str) -> List[Vulnerability]:
        content = await self.fetch_js_content(js_url)
        if not content:
            return []

        js_file = JSFile(
            url=js_url,
            content=content,
            size=len(content),
            is_minified=self._detect_minification(content),
            has_sourcemap=self._detect_sourcemap(content),
            sourcemap_url=self._extract_sourcemap_url(content, js_url)
        )

        self.js_files.append(js_file)

        findings = self._analyze_js_content(content, js_url)

        if js_file.is_minified and self.config.sourcemap_analysis and js_file.sourcemap_url:
            sourcemap_findings = await self._analyze_sourcemap(js_file.sourcemap_url)
            findings.extend(sourcemap_findings)

        return findings

    def _analyze_js_content(self, content: str, source: str) -> List[Vulnerability]:
        findings = []

        findings.extend(self.pattern_matcher.analyze(content, source))
        findings.extend(self.secret_scanner.scan(content, source))
        findings.extend(self.dependency_analyzer.analyze(content, source))

        obfuscation = self._detect_obfuscation(content)
        if obfuscation:
            findings.append(Vulnerability(
                type=VulnType.JS_VULNERABILITY,
                severity=Severity.LOW,
                title="Code Obfuscation/Minification",
                description="Code appears to be obfuscated or minified",
                url=source,
                evidence=Evidence(
                    matched_pattern="Obfuscation detected",
                    context=obfuscation['evidence']
                ),
                tags=["obfuscation"]
            ))

        return findings

    def _detect_minification(self, content: str) -> bool:
        if len(content) < 500:
            return False

        lines = content.split('\n')
        avg_line_length = len(content) / max(len(lines), 1)
        return avg_line_length > 200

    def _detect_obfuscation(self, content: str) -> Optional[Dict[str, str]]:
        if len(content) < 500:
            return None

        short_vars = len(re.findall(r'\b[a-zA-Z_$]\b(?::|\s|[,;)])', content))
        total_ids = len(re.findall(r'\b[a-zA-Z_$][a-zA-Z0-9_$]*\b', content))

        if total_ids > 0 and short_vars / total_ids > 0.3 and len(content) < 50000:
            return {
                'evidence': f'{short_vars} short variables, {total_ids} total identifiers'
            }
        return None

    def _detect_sourcemap(self, content: str) -> bool:
        return '//# sourceMappingURL=' in content or '//#sourceMappingURL=' in content

    def _extract_sourcemap_url(self, content: str, base_url: str) -> Optional[str]:
        match = re.search(r'//#\s*sourceMappingURL\s*=\s*([^\s]+)', content)
        if match:
            return urljoin(base_url, match.group(1))
        return None

    async def _analyze_sourcemap(self, sourcemap_url: str) -> List[Vulnerability]:
        findings = []
        try:
            response = await self.client.get(sourcemap_url)
            if response.is_error or response.status_code != 200:
                return findings

            try:
                sourcemap = json.loads(response.text)
                sources = sourcemap.get('sources', [])
                if sources:
                    findings.append(Vulnerability(
                        type=VulnType.JS_VULNERABILITY,
                        severity=Severity.LOW,
                        title="Source Map Exposed",
                        description=f"Source map exposes {len(sources)} original source files",
                        url=sourcemap_url,
                        evidence=Evidence(
                            matched_pattern="Source map available",
                            context=f"Sources: {', '.join(sources[:5])}"
                        ),
                        cwe_id="CWE-200",
                        remediation="Remove source maps from production builds.",
                        tags=["sourcemap", "information-disclosure"]
                    ))
            except json.JSONDecodeError:
                pass
        except Exception as e:
            self.logger.debug(f"Sourcemap analysis error: {e}")

        return findings

    def generate_report(self) -> Dict[str, Any]:
        severity_summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        all_findings = []

        for js_file in self.js_files:
            all_findings.extend(js_file.findings)

        for finding in all_findings:
            severity_summary[finding.severity.value] = severity_summary.get(finding.severity.value, 0) + 1

        return {
            'files_analyzed': len(self.js_files),
            'inline_scripts_found': len(self.inline_scripts),
            'total_findings': len(all_findings),
            'js_files': [j.url for j in self.js_files],
            'findings': [f.to_dict() for f in all_findings],
            'severity_summary': severity_summary
        }
