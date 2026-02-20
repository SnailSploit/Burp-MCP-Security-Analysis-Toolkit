# Burp MCP Security Analysis Toolkit - SnailSploit Edition

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/Platform-macOS%20%7C%20Linux-blue.svg)]()
[![Claude Code](https://img.shields.io/badge/Claude%20Code-Compatible-green.svg)](https://claude.ai/code)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://python.org)
[![Tests](https://img.shields.io/badge/Tests-Passing-brightgreen.svg)]()

A skills-based security analysis framework by **SnailSploit** that combines **Burp Suite's traffic capture** with **Claude Code's reasoning** via MCP (Model Context Protocol). Instead of ad-hoc prompts, this toolkit encodes expert penetration testing methodology into reusable skill files.

## Philosophy

| Principle | Description |
|-----------|-------------|
| **Skills over Prompts** | Expert methodology encoded in skill files, not thrown-together prompts |
| **Phased Analysis** | Scope > Triage > Analyze > Report (not everything at once) |
| **Evidence-Required** | No finding without proof from actual HTTP traffic |

## Quick Start

### Installation (macOS / Linux)

```bash
# Clone the repository
git clone https://github.com/SnailSploit/Burp-MCP-Security-Analysis-Toolkit.git
cd Burp-MCP-Security-Analysis-Toolkit

# Install Python dependencies
pip install -r requirements.txt

# Run the installer (macOS)
chmod +x install.sh
./install.sh

# Configure your scope
cp templates/scope-template.yaml scope.yaml
# Edit scope.yaml with your target information

# Launch
./launch.sh
```

### CLI Usage

The toolkit includes a unified CLI for standalone operations:

```bash
# Validate scope configuration
python -m lib validate scope.yaml

# Generate report from findings
python -m lib report ./output

# Run interactive demo
python -m lib demo

# Show version
python -m lib version
```

### Claude Code Commands

Once Burp Suite is running with MCP enabled:

```bash
# In Claude Code:
"load scope"      # Validate configuration
"triage"          # Classify endpoints
"analyze all"     # Run all indicator tests
"report"          # Generate final report
```

## Directory Structure

```
Burp-MCP-Security-Analysis-Toolkit/
├── CLAUDE.md                    # Orchestration instructions (auto-loaded)
├── README.md                    # This file
├── install.sh                   # macOS installer
├── launch.sh                    # Launcher script (created by installer)
├── scope.yaml                   # Your engagement config (create from template)
│
├── skills/                      # Methodology files (~80KB of expertise)
│   ├── SKILL-burp-mcp.md        # MCP query patterns
│   ├── SKILL-endpoint-triage.md # Endpoint classification
│   ├── SKILL-idor-testing.md    # IDOR detection methodology
│   ├── SKILL-bola-testing.md    # Broken Object Level Authorization
│   ├── SKILL-auth-analysis.md   # Auth bypass testing
│   ├── SKILL-ssrf-testing.md    # SSRF detection
│   ├── SKILL-injection-points.md# SQLi/XSS vector identification
│   └── SKILL-report-format.md   # Report generation format
│
├── lib/                         # Python helpers
│   ├── __init__.py              # Package exports (v2.1.0)
│   ├── __main__.py              # CLI entry point
│   ├── scope_validator.py       # Validate scope.yaml
│   ├── endpoint_filter.py       # Filter/prioritize endpoints
│   ├── finding_formatter.py     # Format findings to markdown
│   └── report_generator.py      # Aggregate findings into report
│
├── tests/                       # Test suite
│   ├── test_scope_validator.py  # Scope validation tests
│   ├── test_endpoint_filter.py  # Endpoint filtering tests
│   ├── test_finding_formatter.py# Finding formatting tests
│   └── test_report_generator.py # Report generation tests
│
├── templates/
│   ├── scope-template.yaml      # Blank scope configuration
│   └── finding-template.md      # Finding documentation format
│
└── output/                      # Generated during analysis
    ├── endpoints.json           # Triaged endpoint list
    ├── findings/                # Per-indicator findings
    └── report.md                # Final consolidated report
```

## Supported Indicators

| Indicator | Skill File | What It Finds |
|-----------|------------|---------------|
| `idor` | SKILL-idor-testing.md | Insecure Direct Object References |
| `bola` | SKILL-bola-testing.md | Broken Object Level Authorization |
| `auth_bypass` | SKILL-auth-analysis.md | Authentication/session vulnerabilities |
| `ssrf` | SKILL-ssrf-testing.md | Server-Side Request Forgery |
| `injection` | SKILL-injection-points.md | SQLi/XSS/Command injection vectors |

## Commands Reference

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

## Prerequisites

- **macOS** (Intel or Apple Silicon) or **Linux**
- **Python 3.9+**
- **Burp Suite** Community or Professional
- **Claude Code** (npm package)
- **Captured HTTP Traffic** through Burp proxy
- **Multiple auth contexts** (for IDOR/BOLA testing)

## Installation Guide

### Option 1: Automated (macOS)

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
   - Open Burp > Extender > BApp Store
   - Search "MCP Server" > Install
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

## Configuration

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

## Output

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

## Python Helpers

The `lib/` directory contains standalone Python utilities accessible via CLI:

```bash
# Unified CLI
python -m lib validate scope.yaml
python -m lib report output/
python -m lib demo
python -m lib version

# Direct module usage
python lib/scope_validator.py scope.yaml
python lib/report_generator.py output/
```

## Testing

Run the full test suite:

```bash
pip install pytest
python -m pytest tests/ -v
```

## Extending

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

## Security Notes

- **Scope files contain tokens** - Add `scope.yaml` to `.gitignore`
- **Use only on authorized targets** - Standard pentest rules apply
- **Evidence is redacted by default** - Configure in scope.yaml

## License

MIT License - See [LICENSE](LICENSE)

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md)

## Credits

- **SnailSploit** - Framework author and maintainer
- **Kai Aizen** - Original toolkit concept
- Built with [Burp Suite MCP Server](https://github.com/PortSwigger/mcp-server) and [Claude Code](https://claude.ai/code)

---

**Disclaimer:** Use responsibly and only on systems you have explicit permission to test.
