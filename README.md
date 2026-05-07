# AiPT Pro

<p align="center">
  <strong>AI 增强型 Web 应用渗透测试平台</strong><br>
  用于对授权系统进行自动化安全评估
</p>

<p align="center">
  <a href="https://github.com/aipt/aipt-pro/releases">
    <img src="https://img.shields.io/github/v/release/aipt/aipt-pro?include_prereleases&style=flat-square" alt="Release">
  </a>
  <a href="https://www.python.org/downloads/">
    <img src="https://img.shields.io/badge/python-3.8+-blue.svg?style=flat-square" alt="Python 3.8+">
  </a>
  <a href="LICENSE">
    <img src="https://img.shields.io/badge/license-MIT-green.svg?style=flat-square" alt="License">
  </a>
  <a href="https://github.com/aipt/aipt-pro/actions">
    <img src="https://img.shields.io/github/actions/workflow/status/aipt/aipt-pro/ci.yml?branch=main&style=flat-square" alt="CI">
  </a>
</p>

<p align="center">
  <a href="#-功能特性">功能特性</a> •
  <a href="#-快速开始">快速开始</a> •
  <a href="#-使用说明">使用说明</a> •
  <a href="#-扫描功能">扫描功能</a> •
  <a href="#-报告输出">报告输出</a> •
  <a href="#-常见问题">常见问题</a>
</p>

---

## 项目描述

AiPT Pro 是一个基于 Python 的商用级 AI 增强型 Web 应用渗透测试平台，集成了多种安全检测能力：

- **漏洞检测**：SQL 注入、XSS、SSRF、IDOR、命令注入、NoSQL 注入、SSTI、XXE 等
- **配置审计**：安全头检查、CSRF/CORS 保护检测、开放重定向、WAF 识别
- **代码分析**：JavaScript 代码审计、SourceMap 泄露检测
- **智能分析**：基于 Isolation Forest 的 AI 异常检测引擎，提升漏洞发现准确性

> **适用场景**：安全测试人员、DevSecOps 团队、渗透测试工程师对授权 Web 应用进行自动化安全评估。

---

## 功能特性

| 特性 | 说明 |
|------|------|
| **异步高性能扫描引擎** | 基于 `aiohttp` 的异步 HTTP 客户端，支持高并发请求、速率限制和代理轮换 |
| **AI 异常检测** | 使用机器学习（Isolation Forest）和统计方法检测异常响应，支持行为分析和响应聚类 |
| **多模式运行** | 同时提供命令行界面（CLI）和桌面图形界面（GUI） |
| **多种认证支持** | Token、Basic、OAuth、Form 和 Cookie 五种认证方式 |
| **JavaScript 安全审计** | 检测危险代码模式、硬编码密钥、依赖漏洞和 SourceMap 泄露 |
| **多格式报告输出** | 支持 JSON、HTML、CSV、SARIF 和 XML 五种报告格式 |
| **CI/CD 自动发布** | GitHub Actions 工作流自动构建 Windows 和 Linux 可执行文件并发布 Release |

---

## 环境要求

- **Python**: >= 3.8
- **操作系统**: Windows、Linux、macOS
- **系统依赖**: 部分包（如 `lxml`）需要系统编译工具（详见[常见问题](#-常见问题)）

完整依赖列表见 [requirements.txt](requirements.txt)。

---

## 快速开始

### 方式一：从源码安装（推荐开发者）

```bash
# 克隆仓库
git clone https://github.com/aipt/aipt-pro.git
cd aipt-pro

# 创建虚拟环境（推荐）
python -m venv venv
source venv/bin/activate  # Linux/Mac
# 或 venv\Scripts\activate  # Windows

# 安装依赖
pip install -r requirements.txt

# 安装为系统命令
pip install -e .
```

### 方式二：使用预构建可执行文件（推荐普通用户）

从 [Releases](https://github.com/aipt/aipt-pro/releases) 页面下载对应平台的压缩包：

| 平台 | 文件名 | 包含内容 |
|------|--------|----------|
| **Windows** | `aipt-pro-windows.zip` | `aipt-cli.exe` + `aipt-gui.exe` |
| **Linux** | `aipt-pro-linux.tar.gz` | `aipt-cli` + `aipt-gui` |

下载后解压即可使用，无需安装 Python 环境。

---

## 使用说明

### CLI 命令行模式

#### 基础用法

```bash
# 基础扫描（默认配置）
aipt-cli https://example.com

# 全量扫描（启用所有检测模块 + AI 增强 + JS 审计）
aipt-cli https://example.com --full

# 指定输出目录和报告格式
aipt-cli https://example.com -o reports/ -f json html csv
```

#### 认证与代理

```bash
# 使用 Bearer Token 认证
aipt-cli https://example.com --auth-token "Bearer eyJ0eXAiOiJKV1Qi..."

# 使用 Basic 认证
aipt-cli https://example.com --auth-basic "username:password"

# 使用代理
aipt-cli https://example.com --proxy "http://127.0.0.1:8080"

# 启用代理轮换（自动切换多个代理）
aipt-cli https://example.com --proxy "http://127.0.0.1:8080" --proxy-rotation
```

#### 高级扫描配置

```bash
# 仅扫描 SQL 注入
aipt-cli https://example.com --sqli-only

# 高并发深度扫描（并发 200，深度 3，最多 5000 URL）
aipt-cli https://example.com --concurrency 200 --depth 3 --max-urls 5000

# 使用配置文件
aipt-cli https://example.com -c config.yaml

# 静默模式（仅输出警告及以上级别）
aipt-cli https://example.com --quiet

# 详细模式（输出调试信息）
aipt-cli https://example.com --verbose
```

### GUI 桌面模式

```bash
# 启动图形界面
aipt-gui
```

GUI 模式提供以下功能：

- **目标配置**：URL 输入和扫描参数配置
- **选项卡式配置**：认证、检测模块和代理选项分类管理
- **实时监控**：控制台输出和进度条
- **结果展示**：漏洞结果表格（支持按严重程度着色：高危/中危/低危/信息）
- **快捷操作**：报告文件夹快速打开和结果导出

> **提示**：首次启动 GUI 时，请确保系统已安装 tkinter（详见[常见问题](#-常见问题)）。

### Python 模块方式

#### 直接运行

```bash
# 作为模块运行
python -m aipt https://example.com
```

#### 编程调用

```python
import asyncio
from aipt.core.engine import ScanEngine
from aipt.core.config import Config

async def main():
    # 创建配置
    config = Config()
    config.concurrency = 100
    config.ai_enabled = True

    # 初始化扫描引擎
    engine = ScanEngine(config)

    # 执行全量扫描
    result = await engine.run_full_scan("https://example.com")

    # 输出结果
    print(f"扫描完成：发现 {len(result.vulnerabilities)} 个漏洞")
    for vuln in result.vulnerabilities:
        print(f"  [{vuln.severity}] {vuln.name}: {vuln.url}")

if __name__ == "__main__":
    asyncio.run(main())
```

---

## 配置文件

支持通过 YAML 配置文件加载扫描参数，便于复用和版本管理：

```yaml
# config.yaml
scan:
  max_depth: 3
  concurrency: 100
  request_timeout: 15.0
  verify_ssl: false

auth:
  enabled: true
  type: token
  token: "your-api-token"

detection:
  sqli_enabled: true
  xss_enabled: true
  ssrf_enabled: true
  cmd_injection_enabled: true
  nosql_injection_enabled: true
  ssti_enabled: true
  xxe_enabled: true
  js_audit_enabled: true

ai:
  enabled: true
  model_type: isolation_forest
  sensitivity: medium

report:
  formats: [json, html, csv]
  output_dir: reports
  include_evidence: true
```

加载配置：

```bash
aipt-cli https://example.com -c config.yaml
```

### 环境变量配置

支持通过环境变量快速覆盖配置：

```bash
export AIPT_CONCURRENCY=200
export AIPT_TIMEOUT=30.0
export AIPT_PROXY="http://127.0.0.1:8080"
export AIPT_AUTH_TOKEN="your-api-token"
export AIPT_AI_ENABLED=true
```

---

## 扫描功能

| 检测模块 | 说明 | 严重程度 |
|---------|------|----------|
| **SQL 注入** | 检测基于错误和盲注的 SQL 注入漏洞 | 高危 |
| **XSS** | 检测反射型、存储型和 DOM-based 跨站脚本漏洞 | 高危 |
| **SSRF** | 检测服务器端请求伪造漏洞 | 高危 |
| **IDOR / 路径遍历** | 检测不安全的直接对象引用和路径遍历 | 高危 |
| **命令注入** | 检测操作系统命令注入漏洞（含时间盲注） | 高危 |
| **NoSQL 注入** | 检测 MongoDB 等 NoSQL 注入 | 高危 |
| **SSTI** | 检测服务端模板注入漏洞 | 高危 |
| **XXE** | 检测 XML 外部实体注入漏洞 | 高危 |
| **安全头检查** | 检查缺失的安全响应头（HSTS、CSP、X-Frame-Options 等） | 中危 |
| **CSRF 保护** | 检查表单是否缺少 CSRF 令牌和 SameSite Cookie | 中危 |
| **CORS 配置** | 检测跨域资源共享配置错误 | 中危 |
| **开放重定向** | 检测未经验证的跳转参数 | 中危 |
| **WAF 检测** | 识别 Web 应用防火墙类型 | 信息 |
| **JavaScript 审计** | 分析 JS 代码中的危险模式、硬编码密钥、依赖漏洞和 SourceMap | 中危 |
| **AI 异常检测** | 基于机器学习的响应异常检测和行为分析 | 动态 |

---

## 报告输出

扫描完成后自动生成多格式报告，默认输出到 `reports/` 目录，文件名包含时间戳。

| 格式 | 文件扩展名 | 适用场景 |
|------|-----------|----------|
| **JSON** | `.json` | 完整的结构化扫描数据，便于程序化处理和集成 |
| **HTML** | `.html` | 响应式网页报告，含风险评分、漏洞详情和修复建议，适合展示和分享 |
| **CSV** | `.csv` | 表格化漏洞列表，便于导入 Excel 进行进一步分析 |
| **SARIF** | `.sarif` | 静态分析结果交换格式，兼容 GitHub Code Scanning 和 Azure DevOps |
| **XML** | `.xml` | 标准 XML 格式报告，兼容旧版安全工具和系统 |

### 报告示例

```bash
# 生成所有格式
aipt-cli https://example.com -f json html csv sarif xml

# 仅生成 HTML 和 JSON
aipt-cli https://example.com -f html json -o ./security-reports/
```

---

## 技术栈

- **Python 3.8+** — 核心开发语言
- **aiohttp** — 异步 HTTP 请求处理
- **BeautifulSoup / lxml** — HTML 解析与页面爬取
- **scikit-learn** — AI 异常检测（Isolation Forest）
- **Jinja2** — HTML 报告模板渲染
- **PyInstaller** — 可执行文件打包
- **tkinter** — 桌面 GUI 界面

---

## 项目结构

```
aipt-pro/
├── aipt/                       # 主包
│   ├── __init__.py
│   ├── __main__.py             # 模块入口
│   ├── cli.py                  # 命令行接口
│   ├── gui.py                  # 桌面图形界面
│   ├── core/                   # 核心引擎
│   │   ├── config.py           # 配置系统
│   │   ├── engine.py           # 扫描引擎主控
│   │   ├── async_engine.py     # 异步 HTTP 引擎和爬虫
│   │   ├── models.py           # 数据模型
│   │   ├── ai_detector.py      # AI 异常检测
│   │   ├── auth_manager.py     # 认证管理
│   │   └── report_generator.py # 报告生成器
│   └── scanners/               # 扫描器模块
│       ├── vulnerability_scanner.py  # 漏洞扫描器
│       └── js_auditor.py       # JavaScript 审计器
├── tests/                      # 单元测试
├── .github/workflows/          # CI/CD 工作流
├── requirements.txt            # Python 依赖
├── setup.py                    # 安装脚本
├── aipt-cli.spec               # CLI 打包配置
├── aipt-gui.spec               # GUI 打包配置
└── README.md                   # 本文件
```

---

## 测试

```bash
# 运行全部单元测试
python -m unittest discover tests/

# 运行特定测试模块
python -m unittest tests.test_config
python -m unittest tests.test_models
python -m unittest tests.test_scanners
python -m unittest tests.test_ai_detector

# 生成覆盖率报告
python -m coverage run -m unittest discover tests/
python -m coverage report
```

---

## 构建可执行文件

```bash
# 构建 CLI 可执行文件
pyinstaller aipt-cli.spec --clean --noconfirm

# 构建 GUI 可执行文件
pyinstaller aipt-gui.spec --clean --noconfirm
```

构建产物位于 `dist/` 目录。

---

## 常见问题

### 安装依赖时遇到编译错误

某些依赖（如 `lxml`）可能需要系统编译工具：

**Ubuntu/Debian：**
```bash
sudo apt-get install python3-dev libxml2-dev libxslt1-dev
```

**macOS：**
```bash
xcode-select --install
```

**Windows：**
安装 [Microsoft C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)。

### GUI 模式无法启动

确保系统已安装 tkinter：

**Ubuntu/Debian：**
```bash
sudo apt-get install python3-tk
```

**macOS：**
```bash
brew install python-tk
```

**Windows：**
Python 官方安装包通常已包含 tkinter，如缺失请重新安装 Python 并勾选 "tcl/tk and IDLE"。

### AI 检测模块加载失败

如果 `scikit-learn` 未安装，AI 检测将自动回退到统计检测方法。建议安装完整依赖以获得最佳效果：

```bash
pip install -r requirements.txt
```

### 扫描过程中遇到 SSL 证书错误

对于使用自签名证书的目标，可以禁用 SSL 验证：

```bash
aipt-cli https://example.com --no-verify-ssl
```

或在配置文件中设置 `verify_ssl: false`。

---

## 贡献指南

欢迎提交 Issue 和 Pull Request！在贡献代码前，请确保：

1. **代码通过现有测试**
   ```bash
   python -m unittest discover tests/
   ```

2. **新增功能包含对应的单元测试**

3. **遵循现有代码风格**
   - 使用 [PEP 8](https://pep8.org/) 代码规范
   - 函数和类添加 docstring
   - 保持类型注解

4. **提交信息规范**
   - 使用英文描述
   - 格式：`type(scope): description`
   - 示例：`feat(scanner): add support for GraphQL injection detection`

5. **创建 Pull Request 前**
   - 从 `main` 分支创建功能分支
   - 确保分支是最新的
   - 描述清楚改动内容和测试方式

---

## 安全声明

> **警告**：本工具仅用于对**您拥有授权**的系统进行安全测试。未经授权扫描他人系统可能违反法律法规。使用本工具即表示您同意承担全部责任。
>
> 请勿将本工具用于：
> - 未授权的系统或网络
> - 恶意攻击或数据窃取
> - 任何违反当地法律的活动

---

## 许可证

本项目采用 [MIT License](LICENSE) 开源许可证。

---

<p align="center">
  如有问题或建议，欢迎通过 <a href="https://github.com/aipt/aipt-pro/issues">GitHub Issues</a> 联系我们。
</p>
