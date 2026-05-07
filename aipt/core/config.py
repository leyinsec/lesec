import os
import yaml
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from pathlib import Path


@dataclass
class ScanConfig:
    max_depth: int = 3
    max_urls: int = 1000
    max_forms: int = 500
    concurrency: int = 100
    connection_pool_size: int = 200
    request_timeout: float = 15.0
    retry_attempts: int = 3
    retry_delay: float = 1.0
    rate_limit: float = 0.1
    adaptive_rate_limit: bool = True
    follow_redirects: bool = True
    max_redirects: int = 5
    verify_ssl: bool = False
    respect_robots_txt: bool = False
    user_agents: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    excluded_paths: List[str] = field(default_factory=list)
    included_paths: List[str] = field(default_factory=list)
    file_extensions: List[str] = field(default_factory=lambda: [
        '.html', '.htm', '.php', '.asp', '.aspx', '.jsp', '.do', '.action',
        '.json', '.xml', '.txt', '.zip', '.bak', '.sql', '.log'
    ])


@dataclass
class AuthConfig:
    enabled: bool = False
    type: str = "none"
    username: str = ""
    password: str = ""
    token: str = ""
    token_header: str = "Authorization"
    token_prefix: str = "Bearer"
    cookie_auth: Dict[str, str] = field(default_factory=dict)
    oauth_client_id: str = ""
    oauth_client_secret: str = ""
    oauth_scope: str = ""
    oauth_token_url: str = ""
    login_url: str = ""
    login_form_data: Dict[str, str] = field(default_factory=dict)
    login_success_indicator: str = ""
    session_refresh_interval: int = 1800


@dataclass
class ProxyConfig:
    enabled: bool = False
    proxies: List[str] = field(default_factory=list)
    rotation_strategy: str = "round_robin"
    rotation_interval: int = 10
    health_check_interval: int = 60
    health_check_url: str = "http://httpbin.org/ip"
    max_failures: int = 3
    cooldown_period: int = 300


@dataclass
class DetectionConfig:
    sqli_enabled: bool = True
    sqli_blind_enabled: bool = True
    sqli_time_delay: float = 5.0
    sqli_boolean_threshold: float = 0.95
    xss_enabled: bool = True
    xss_context_aware: bool = True
    xss_polyglots: bool = True
    ssrf_enabled: bool = True
    ssrf_dnslog_enabled: bool = False
    ssrf_dnslog_domain: str = ""
    idor_enabled: bool = True
    cmd_injection_enabled: bool = True
    cmd_injection_time_delay: float = 5.0
    lfi_enabled: bool = True
    rfi_enabled: bool = True
    xxe_enabled: bool = True
    xpath_enabled: bool = True
    ldap_injection_enabled: bool = True
    nosql_injection_enabled: bool = True
    template_injection_enabled: bool = True
    waf_detection_enabled: bool = True
    waf_bypass_enabled: bool = True
    api_security_enabled: bool = True
    graphql_enabled: bool = True


@dataclass
class AIDetectionConfig:
    enabled: bool = True
    model_type: str = "isolation_forest"
    contamination: float = 0.1
    feature_extraction: bool = True
    behavioral_analysis: bool = True
    response_clustering: bool = True
    anomaly_threshold: float = 0.7
    training_samples: int = 50
    auto_tune: bool = True


@dataclass
class JSAuditConfig:
    enabled: bool = True
    ast_analysis: bool = True
    sourcemap_analysis: bool = True
    dataflow_analysis: bool = True
    dependency_check: bool = True
    secret_scanning: bool = True
    sink_source_tracking: bool = True
    max_file_size: int = 5 * 1024 * 1024
    max_files: int = 100


@dataclass
class ReportConfig:
    formats: List[str] = field(default_factory=lambda: ["json", "html"])
    output_dir: str = "reports"
    template_dir: str = "templates"
    include_screenshots: bool = False
    include_evidence: bool = True
    severity_threshold: str = "INFO"
    max_evidence_length: int = 2000


@dataclass
class LoggingConfig:
    level: str = "INFO"
    file: Optional[str] = None
    max_size: int = 10 * 1024 * 1024
    backup_count: int = 5
    console_output: bool = True
    json_format: bool = False


@dataclass
class PluginConfig:
    enabled: bool = True
    plugin_dir: str = "plugins"
    auto_load: bool = True
    allowed_plugins: List[str] = field(default_factory=list)
    plugin_timeout: int = 30


@dataclass
class Config:
    scan: ScanConfig = field(default_factory=ScanConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)
    proxy: ProxyConfig = field(default_factory=ProxyConfig)
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    ai: AIDetectionConfig = field(default_factory=AIDetectionConfig)
    js_audit: JSAuditConfig = field(default_factory=JSAuditConfig)
    report: ReportConfig = field(default_factory=ReportConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    plugin: PluginConfig = field(default_factory=PluginConfig)

    @classmethod
    def from_yaml(cls, path: str) -> "Config":
        with open(path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        return cls._from_dict(data)

    @classmethod
    def from_env(cls) -> "Config":
        config = cls()
        if os.getenv("AIPT_CONCURRENCY"):
            config.scan.concurrency = int(os.getenv("AIPT_CONCURRENCY"))
        if os.getenv("AIPT_TIMEOUT"):
            config.scan.request_timeout = float(os.getenv("AIPT_TIMEOUT"))
        if os.getenv("AIPT_PROXY"):
            config.proxy.enabled = True
            config.proxy.proxies = os.getenv("AIPT_PROXY").split(",")
        if os.getenv("AIPT_AUTH_TOKEN"):
            config.auth.enabled = True
            config.auth.type = "token"
            config.auth.token = os.getenv("AIPT_AUTH_TOKEN")
        return config

    @classmethod
    def _from_dict(cls, data: Dict[str, Any]) -> "Config":
        config = cls()
        if "scan" in data:
            config.scan = ScanConfig(**data["scan"])
        if "auth" in data:
            config.auth = AuthConfig(**data["auth"])
        if "proxy" in data:
            config.proxy = ProxyConfig(**data["proxy"])
        if "detection" in data:
            config.detection = DetectionConfig(**data["detection"])
        if "ai" in data:
            config.ai = AIDetectionConfig(**data["ai"])
        if "js_audit" in data:
            config.js_audit = JSAuditConfig(**data["js_audit"])
        if "report" in data:
            config.report = ReportConfig(**data["report"])
        if "logging" in data:
            config.logging = LoggingConfig(**data["logging"])
        if "plugin" in data:
            config.plugin = PluginConfig(**data["plugin"])
        return config

    def to_dict(self) -> Dict[str, Any]:
        from dataclasses import asdict
        return asdict(self)
