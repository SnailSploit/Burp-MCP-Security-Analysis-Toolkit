# Burp MCP Security Analysis Toolkit

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/Platform-macOS-blue.svg)](https://www.apple.com/macos)
[![Claude Code](https://img.shields.io/badge/Claude%20Code-Compatible-green.svg)](https://claude.ai/code)

A skills-based security analysis framework that combines **Burp Suite's traffic capture** with **Claude Code's reasoning** via MCP (Model Context Protocol). Instead of ad-hoc prompts, this toolkit encodes expert penetration testing methodology into reusable skill files.

<p align="center">
  <img src="https://via.placeholder.com/800x400?text=Burp+MCP+Toolkit+Diagram" alt="Architecture Diagram">
</p>

## 🎯 Philosophy

| Principle | Description |
|-----------|-------------|
| **Skills over Prompts** | Expert methodology encoded in skill files, not thrown-together prompts |
| **Phased Analysis** | Scope → Triage → Analyze → Report (not everything at once) |
| **Evidence-Required** | No finding without proof from actual HTTP traffic |

## 🚀 Quick Start

### Installation (macOS)

```bash
# Clone the repository
git clone https://github.com/yourusername/burp-mcp-toolkit.git
cd burp-mcp-toolkit

# Run the installer
chmod +x install.sh
./install.sh

# Configure your scope
cp templates/scope-template.yaml scope.yaml
# Edit scope.yaml with your target information

# Launch
./launch.sh
```

### Manual Installation

See [Installation Guide](#installation-guide) below for step-by-step manual setup.

### Usage

Once Burp Suite is running with MCP enabled:

```bash
# In Claude Code:
"load scope"      # Validate configuration
"triage"          # Classify endpoints  
"analyze all"     # Run all indicator tests
"report"          # Generate final report
```

## 📁 Directory Structure

```
burp-mcp-toolkit/
├── CLAUDE.md                    # Orchestration instructions (auto-loaded)
├── README.md                    # This file
├── install.sh                   # macOS installer
├── launch.sh                    # Launcher script (created by installer)
├── scope.yaml                   # Your engagement config (create from template)
│
├── skills/                      # 🧠 Methodology files (~80KB of expertise)
│   ├── SKILL-burp-mcp.md        # MCP query patterns
│   ├── SKILL-endpoint-triage.md # Endpoint classification
│   ├── SKILL-idor-testing.md    # IDOR detection methodology
│   ├── SKILL-bola-testing.md    # Broken Object Level Authorization
│   ├── SKILL-auth-analysis.md   # Auth bypass testing
│   ├── SKILL-ssrf-testing.md    # SSRF detection
│   ├── SKILL-injection-points.md# SQLi/XSS vector identification
│   └── SKILL-report-format.md   # Report generation format
│
├── lib/                         # 🐍 Python helpers
│   ├── scope_validator.py       # Validate scope.yaml
│   ├── endpoint_filter.py       # Filter/prioritize endpoints
│   ├── finding_formatter.py     # Format findings to markdown
│   └── report_generator.py      # Aggregate findings into report
│
├── templates/
│   ├── scope-template.yaml      # Blank scope configuration
│   └── finding-template.md      # Finding documentation format
│
└── output/                      # 📊 Generated during analysis
    ├── endpoints.json           # Triaged endpoint list
    ├── findings/                # Per-indicator findings
    └── report.md                # Final consolidated report
```

## 🔍 Supported Indicators

| Indicator | Skill File | What It Finds |
|-----------|------------|---------------|
| `idor` | SKILL-idor-testing.md | Insecure Direct Object References |
| `bola` | SKILL-bola-testing.md | Broken Object Level Authorization |
| `auth_bypass` | SKILL-auth-analysis.md | Authentication/session vulnerabilities |
| `ssrf` | SKILL-ssrf-testing.md | Server-Side Request Forgery |
| `injection` | SKILL-injection-points.md | SQLi/XSS/Command injection vectors |

## 💻 Commands Reference

| Command | Phase | Description |
|---------|-------|-------------|
| `load scope` | 1 | Parse and validate scope.yaml |
| `triage` | 2 | Classify and prioritize endpoints |
| `analyze {indicator}` | 3 | Run specific indicator (e.g., `analyze idor`) |
| `analyze all` | 3 | Run all enabled indicators |
| `report` | 4 | Generate consolidated report |
| `full scan` | 1-4 | Run complete pipeline |
| `status` | - | Show current progress |
| `show endpoints` | - | Display triaged endpoints |
| `inspect {path}` | - | Deep dive on specific endpoint |

## 📋 Prerequisites

- **macOS** (Intel or Apple Silicon)
- **Burp Suite** Community or Professional
- **Claude Code** (npm package)
- **Captured HTTP Traffic** through Burp proxy
- **Multiple auth contexts** (for IDOR/BOLA testing)

## 🔧 Installation Guide

### Option 1: Automated (Recommended)

```bash
./install.sh
```

This installs: Homebrew, Burp Suite, Caddy, Node.js, Claude Code, and configures MCP.

### Option 2: Manual

1. **Install Burp Suite**
   ```bash
   brew install --cask burp-suite
   ```

2. **Install MCP Server Extension**
   - Open Burp → Extender → BApp Store
   - Search "MCP Server" → Install
   - Export `mcp-proxy.jar` to `~/.burp-mcp-extension/`

3. **Install Caddy** (reverse proxy)
   ```bash
   brew install caddy
   ```

4. **Install Claude Code**
   ```bash
   npm install -g @anthropic-ai/claude-code
   ```

5. **Configure MCP**
   
   Create `~/.claude.json`:
   ```json
   {
     "mcpServers": {
       "burp": {
         "command": "/path/to/java",
         "args": ["-jar", "/path/to/mcp-proxy.jar", "--", "http://localhost:9877/mcp"]
       }
     }
   }
   ```

6. **Configure Caddy**
   
   Create `~/.config/caddy/Caddyfile`:
   ```
   :9877 {
       reverse_proxy localhost:9876 {
           header_up -Origin
       }
   }
   ```

## 🛡️ Configuration

Copy and edit the scope template:

```bash
cp templates/scope-template.yaml scope.yaml
```

Key sections:
- **target**: Primary domain and additional hosts
- **scope**: Include/exclude path patterns
- **indicators**: Which vulnerability types to test
- **auth**: Multi-user tokens for IDOR/BOLA testing

See `templates/scope-template.yaml` for full documentation with examples.

## 📊 Output

All findings are written to `output/`:

| File | Description |
|------|-------------|
| `endpoints.json` | Triaged endpoints with scores and indicators |
| `findings/idor.md` | IDOR-specific findings |
| `findings/bola.md` | BOLA-specific findings |
| `findings/auth.md` | Auth bypass findings |
| `findings/ssrf.md` | SSRF findings |
| `findings/injection.md` | Injection point findings |
| `report.md` | **Consolidated final report** |

## 🐍 Python Helpers

The `lib/` directory contains standalone Python utilities:

```bash
# Validate scope configuration
python lib/scope_validator.py scope.yaml

# Generate report from findings
python lib/report_generator.py output/
```

## ✏️ Extending

### Add New Indicator

1. Create `skills/SKILL-{indicator}-testing.md` with methodology
2. Add to `indicators.enabled` in scope-template.yaml
3. Update CLAUDE.md with new skill reference

### Custom Skills

Follow the structure of existing skills:
- Purpose and scope
- Prerequisites
- Step-by-step methodology
- Evidence requirements
- Output format

## 🔒 Security Notes

- **Scope files contain tokens** - Add `scope.yaml` to `.gitignore`
- **Use only on authorized targets** - Standard pentest rules apply
- **Evidence is redacted by default** - Configure in scope.yaml

## 📄 License

MIT License - See [LICENSE](LICENSE)

## 🤝 Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md)

## 📚 Related Projects

- [Burp Suite MCP Server](https://github.com/PortSwigger/mcp-server)
- [Claude Code](https://claude.ai/code)
- [AATMF](https://github.com/example/aatmf) - Adversarial AI Threat Modeling Framework

---

**Disclaimer:** Use responsibly and only on systems you have explicit permission to test.
