#!/usr/bin/env python3
import asyncio
import argparse
import sys
import os
from pathlib import Path

from .core.config import Config
from .core.engine import ScanEngine


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description='AiPT Pro - Commercial-Grade AI-Enhanced Web Application Penetration Testing Platform',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan
  aipt https://example.com

  # Scan with custom output
  aipt https://example.com -o reports/

  # Scan with authentication
  aipt https://example.com --auth-token "Bearer eyJ0eXAiOiJKV1Qi..."

  # Scan with proxy
  aipt https://example.com --proxy "http://127.0.0.1:8080"

  # High-performance scan with more concurrency
  aipt https://example.com --concurrency 200 --depth 3

  # Scan specific vulnerabilities only
  aipt https://example.com --sqli-only --xss-only

  # Full scan with all features
  aipt https://example.com --full --ai-enhanced --js-audit
        """
    )

    parser.add_argument('target', help='Target URL to scan')
    parser.add_argument('-c', '--config', help='Path to YAML configuration file')
    parser.add_argument('-o', '--output', default='reports', help='Output directory for reports')
    parser.add_argument('-f', '--format', nargs='+', choices=['json', 'html', 'csv', 'sarif', 'xml'],
                       default=['json', 'html'], help='Report formats')

    # Scan options
    scan_group = parser.add_argument_group('Scan Options')
    scan_group.add_argument('-d', '--depth', type=int, default=2, help='Crawl depth (default: 2)')
    scan_group.add_argument('--concurrency', type=int, default=100, help='Concurrent requests (default: 100)')
    scan_group.add_argument('--timeout', type=float, default=15.0, help='Request timeout in seconds')
    scan_group.add_argument('--max-urls', type=int, default=1000, help='Maximum URLs to crawl')
    scan_group.add_argument('--user-agent', help='Custom User-Agent string')
    scan_group.add_argument('--no-verify-ssl', action='store_true', help='Disable SSL verification')

    # Authentication
    auth_group = parser.add_argument_group('Authentication')
    auth_group.add_argument('--auth-type', choices=['token', 'basic', 'oauth', 'form', 'cookie'],
                           help='Authentication type')
    auth_group.add_argument('--auth-token', help='Authentication token')
    auth_group.add_argument('--auth-user', help='Username for basic/form auth')
    auth_group.add_argument('--auth-pass', help='Password for basic/form auth')
    auth_group.add_argument('--auth-cookie', help='Cookie string for authentication')

    # Proxy
    proxy_group = parser.add_argument_group('Proxy')
    proxy_group.add_argument('--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080)')
    proxy_group.add_argument('--proxy-rotation', action='store_true', help='Enable proxy rotation')

    # Detection modules
    detection_group = parser.add_argument_group('Detection Modules')
    detection_group.add_argument('--sqli-only', action='store_true', help='SQL injection only')
    detection_group.add_argument('--xss-only', action='store_true', help='XSS only')
    detection_group.add_argument('--full', action='store_true', help='Enable all detection modules')
    detection_group.add_argument('--no-ai', action='store_true', help='Disable AI detection')
    detection_group.add_argument('--no-js-audit', action='store_true', help='Disable JS audit')

    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument('--severity-threshold', choices=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
                             default='INFO', help='Minimum severity to report')
    output_group.add_argument('--quiet', '-q', action='store_true', help='Quiet mode')
    output_group.add_argument('--verbose', '-v', action='store_true', help='Verbose mode')

    return parser


def build_config(args) -> Config:
    if args.config and os.path.exists(args.config):
        config = Config.from_yaml(args.config)
    else:
        config = Config()

    # Override with CLI arguments
    config.scan.max_depth = args.depth
    config.scan.concurrency = args.concurrency
    config.scan.request_timeout = args.timeout
    config.scan.max_urls = args.max_urls
    config.scan.verify_ssl = not args.no_verify_ssl

    if args.user_agent:
        config.scan.headers['User-Agent'] = args.user_agent

    config.report.output_dir = args.output
    config.report.formats = args.format

    # Authentication
    if args.auth_type:
        config.auth.enabled = True
        config.auth.type = args.auth_type
    if args.auth_token:
        config.auth.enabled = True
        config.auth.type = 'token'
        config.auth.token = args.auth_token
    if args.auth_user:
        config.auth.username = args.auth_user
    if args.auth_pass:
        config.auth.password = args.auth_pass
    if args.auth_cookie:
        config.auth.enabled = True
        config.auth.type = 'cookie'
        config.auth.cookie_auth = dict(item.split('=') for item in args.auth_cookie.split(';'))

    # Proxy
    if args.proxy:
        config.proxy.enabled = True
        config.proxy.proxies = [args.proxy]
    if args.proxy_rotation:
        config.proxy.proxy_rotation = True

    # Detection modules
    if args.sqli_only:
        config.detection.sqli_enabled = True
        config.detection.xss_enabled = False
        config.detection.ssrf_enabled = False
        config.detection.idor_enabled = False
        config.detection.cmd_injection_enabled = False

    if args.xss_only:
        config.detection.sqli_enabled = False
        config.detection.xss_enabled = True
        config.detection.ssrf_enabled = False
        config.detection.idor_enabled = False
        config.detection.cmd_injection_enabled = False

    if args.full:
        config.detection.sqli_enabled = True
        config.detection.xss_enabled = True
        config.detection.ssrf_enabled = True
        config.detection.idor_enabled = True
        config.detection.cmd_injection_enabled = True
        config.detection.lfi_enabled = True
        config.detection.rfi_enabled = True
        config.detection.xxe_enabled = True
        config.detection.nosql_injection_enabled = True
        config.detection.template_injection_enabled = True

    if args.no_ai:
        config.ai.enabled = False

    if args.no_js_audit:
        config.js_audit.enabled = False

    # Logging
    if args.quiet:
        config.logging.level = 'WARNING'
        config.logging.console_output = False
    elif args.verbose:
        config.logging.level = 'DEBUG'

    config.report.severity_threshold = args.severity_threshold

    return config


async def main():
    parser = create_parser()
    args = parser.parse_args()

    config = build_config(args)
    engine = ScanEngine(config)

    try:
        result = await engine.run_full_scan(args.target)

        print("\n" + "=" * 60)
        print("SCAN SUMMARY")
        print("=" * 60)
        print(f"Target: {result.target}")
        print(f"Duration: {result.duration:.2f} seconds")
        print(f"URLs Discovered: {result.urls_discovered}")
        print(f"Forms Found: {result.forms_discovered}")
        print(f"Vulnerabilities: {len(result.vulnerabilities)}")
        print("\nSeverity Breakdown:")
        for severity, count in result.severity_summary.items():
            if count > 0:
                print(f"  {severity}: {count}")
        print("=" * 60)

        sys.exit(0)

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)


def run():
    asyncio.run(main())


if __name__ == '__main__':
    run()
