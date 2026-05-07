# AiPT

AI 增强型 Web 应用渗透测试工具，用于对授权系统进行自动化安全评估。

## 项目描述

本项目是一个基于 Python 的 AI 增强型 Web 应用渗透测试脚本，集成了多种安全检测能力，包括 SQL 注入、XSS、SSRF、IDOR、命令注入等常见漏洞的自动化检测，同时支持 JavaScript 代码审计、安全头检查、CSRF 保护检测等功能。工具内置 AI 异常检测引擎，能够通过基线分析识别异常响应，提升漏洞发现的准确性。

## 使用说明

### 环境要求

- Python 3.x
- requests
- beautifulsoup4
- PySocks（可选，用于 SOCKS 代理）

### 安装依赖

```bash
pip install requests beautifulsoup4
# 如需 SOCKS 代理支持
pip install PySocks
```

### 基本用法

```bash
# 基础扫描
python ai_pentest.py https://example.com

# 指定输出报告文件
python ai_pentest.py https://example.com -o report.json

# 使用代理
python ai_pentest.py https://example.com --proxy http://127.0.0.1:8080

# 启用代理自动轮换
python ai_pentest.py https://example.com --proxy "http://127.0.0.1:8080,socks5://127.0.0.1:1080" --proxy-rotation

# 自定义 User-Agent
python ai_pentest.py https://example.com --user-agent "CustomAgent/1.0"
```

### 扫描功能

| 检测模块 | 说明 |
|---------|------|
| SQL 注入 | 检测基于错误的 SQL 注入漏洞 |
| XSS | 检测反射型跨站脚本漏洞 |
| SSRF | 检测服务器端请求伪造漏洞 |
| IDOR / 路径遍历 | 检测不安全的直接对象引用 |
| 命令注入 | 检测操作系统命令注入漏洞 |
| 安全头检查 | 检查缺失的安全响应头 |
| CSRF 保护 | 检查表单是否缺少 CSRF 令牌 |
| JavaScript 审计 | 分析 JS 代码中的危险模式、硬编码密钥、弱加密等 |

### 输出报告

扫描完成后会生成 JSON 格式的报告文件（默认 `pentest_report.json`），包含发现的漏洞详情、风险等级、证据信息以及 JavaScript 审计结果。

## 技术栈

- **Python 3** — 核心开发语言
- **requests** — HTTP 请求处理
- **BeautifulSoup** — HTML 解析与页面爬取
- **PySocks** — SOCKS 代理支持（可选）

## 免责声明

本工具仅用于对**您拥有授权**的系统进行安全测试。未经授权扫描他人系统可能违反法律法规。使用本工具即表示您同意承担全部责任。
