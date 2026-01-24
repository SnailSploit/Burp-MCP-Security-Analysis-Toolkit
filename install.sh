#!/bin/bash
#
# Burp MCP Toolkit Installer
# ==========================
# Installs all dependencies for the Burp MCP Security Analysis Toolkit on macOS.
#
# What this installs:
#   - Homebrew (if not present)
#   - Burp Suite Community Edition
#   - Caddy (reverse proxy for MCP)
#   - Node.js (for Claude Code)
#   - Claude Code CLI
#   - Burp MCP Server extension (from GitHub, not BApp Store)
#
# Usage:
#   chmod +x install.sh
#   ./install.sh
#
# After running:
#   1. Open Burp Suite once to accept the license
#   2. Enable the MCP Server extension in Burp's Extender tab
#   3. Run ./launch.sh to start everything
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MCP_EXT_DIR="$HOME/.burp-mcp-extension"
CADDY_CONFIG_DIR="$HOME/.config/caddy"
CLAUDE_CONFIG="$HOME/.claude.json"

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
}

check_os() {
    if [[ "$(uname)" != "Darwin" ]]; then
        log_error "This installer is for macOS only."
        exit 1
    fi
    log_success "macOS detected"
}

check_arch() {
    ARCH=$(uname -m)
    if [[ "$ARCH" == "arm64" ]]; then
        log_success "Apple Silicon (M1/M2/M3) detected"
        HOMEBREW_PREFIX="/opt/homebrew"
    else
        log_success "Intel Mac detected"
        HOMEBREW_PREFIX="/usr/local"
    fi
}

install_homebrew() {
    if command -v brew &> /dev/null; then
        log_success "Homebrew already installed"
    else
        log_info "Installing Homebrew..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        
        # Add to PATH for this session
        eval "$($HOMEBREW_PREFIX/bin/brew shellenv)"
        log_success "Homebrew installed"
    fi
}

install_burp() {
    if [[ -d "/Applications/Burp Suite Community Edition.app" ]] || [[ -d "/Applications/Burp Suite Professional.app" ]]; then
        log_success "Burp Suite already installed"
        return
    fi
    
    log_info "Installing Burp Suite Community Edition via Homebrew..."
    brew install --cask burp-suite
    log_success "Burp Suite installed"
}

install_caddy() {
    if command -v caddy &> /dev/null; then
        log_success "Caddy already installed"
    else
        log_info "Installing Caddy..."
        brew install caddy
        log_success "Caddy installed"
    fi
    
    # Create Caddy config directory
    mkdir -p "$CADDY_CONFIG_DIR"
    
    # Create Caddyfile for MCP proxy
    cat > "$CADDY_CONFIG_DIR/Caddyfile" << 'EOF'
# Caddy reverse proxy for Burp MCP Server
# Removes Origin header to bypass Burp's origin validation

:9877 {
    reverse_proxy localhost:9876 {
        header_up -Origin
    }
    log {
        output file /tmp/caddy-mcp.log
        level ERROR
    }
}
EOF
    log_success "Caddy configuration created"
}

install_node() {
    if command -v node &> /dev/null; then
        log_success "Node.js already installed: $(node --version)"
    else
        log_info "Installing Node.js..."
        brew install node
        log_success "Node.js installed"
    fi
}

install_claude_code() {
    if command -v claude &> /dev/null; then
        log_success "Claude Code already installed"
    else
        log_info "Installing Claude Code..."
        npm install -g @anthropic-ai/claude-code
        log_success "Claude Code installed"
    fi
}

install_burp_mcp_extension() {
    log_info "Setting up Burp MCP Server extension..."
    
    # Clone from GitHub
    if [[ -d "$MCP_EXT_DIR" ]]; then
        log_info "Updating existing MCP extension..."
        cd "$MCP_EXT_DIR"
        git pull
    else
        log_info "Cloning Burp MCP Server from GitHub..."
        git clone https://github.com/PortSwigger/mcp-server.git "$MCP_EXT_DIR"
        cd "$MCP_EXT_DIR"
    fi
    
    # Check for pre-built JAR in releases
    if [[ -f "$MCP_EXT_DIR/mcp-proxy.jar" ]]; then
        log_success "MCP proxy JAR found"
    else
        log_warn "MCP proxy JAR not found in repo"
        log_info "You may need to:"
        log_info "  1. Install extension from BApp Store in Burp"
        log_info "  2. Export mcp-proxy.jar from Burp's Extensions tab"
        log_info "  3. Copy it to: $MCP_EXT_DIR/mcp-proxy.jar"
    fi
    
    log_success "Burp MCP extension directory setup"
}

configure_claude_mcp() {
    log_info "Configuring Claude Code MCP connection..."
    
    # Determine Java path
    # First check if Burp's bundled Java exists
    BURP_JAVA="/Applications/Burp Suite Community Edition.app/Contents/Resources/jre.bundle/Contents/Home/bin/java"
    BURP_JAVA_PRO="/Applications/Burp Suite Professional.app/Contents/Resources/jre.bundle/Contents/Home/bin/java"
    
    if [[ -f "$BURP_JAVA" ]]; then
        JAVA_PATH="$BURP_JAVA"
    elif [[ -f "$BURP_JAVA_PRO" ]]; then
        JAVA_PATH="$BURP_JAVA_PRO"
    elif command -v java &> /dev/null; then
        JAVA_PATH="$(which java)"
    else
        log_warn "Java not found. Installing OpenJDK..."
        brew install openjdk@17
        JAVA_PATH="$HOMEBREW_PREFIX/opt/openjdk@17/bin/java"
    fi
    
    log_info "Using Java: $JAVA_PATH"
    
    # Create or update Claude config
    if [[ -f "$CLAUDE_CONFIG" ]]; then
        log_info "Updating existing Claude config..."
        # Backup existing config
        cp "$CLAUDE_CONFIG" "${CLAUDE_CONFIG}.bak"
    fi
    
    # Check if mcp-proxy.jar exists
    MCP_JAR="$MCP_EXT_DIR/mcp-proxy.jar"
    if [[ ! -f "$MCP_JAR" ]]; then
        log_warn "mcp-proxy.jar not found at $MCP_JAR"
        log_warn "MCP configuration will be created but may not work until JAR is present"
        MCP_JAR="[PATH_TO_MCP_PROXY_JAR]"
    fi
    
    # Create Claude config with MCP server
    cat > "$CLAUDE_CONFIG" << EOF
{
  "mcpServers": {
    "burp": {
      "command": "$JAVA_PATH",
      "args": [
        "-jar",
        "$MCP_JAR",
        "--",
        "http://localhost:9877/mcp"
      ]
    }
  }
}
EOF
    
    log_success "Claude Code MCP configuration created"
    log_info "Config location: $CLAUDE_CONFIG"
}

create_launcher() {
    log_info "Creating launcher script..."
    
    cat > "$SCRIPT_DIR/launch.sh" << 'EOF'
#!/bin/bash
#
# Burp MCP Toolkit Launcher
# Starts Caddy proxy and opens Claude Code
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CADDY_CONFIG="$HOME/.config/caddy/Caddyfile"
CADDY_PID="/tmp/caddy-mcp.pid"

cleanup() {
    echo -e "\n${YELLOW}Shutting down...${NC}"
    
    # Stop Caddy
    if [[ -f "$CADDY_PID" ]]; then
        kill $(cat "$CADDY_PID") 2>/dev/null || true
        rm -f "$CADDY_PID"
    fi
    
    # Kill any orphaned Caddy processes on our port
    lsof -ti:9877 | xargs kill 2>/dev/null || true
    
    echo -e "${GREEN}Cleanup complete${NC}"
}

trap cleanup EXIT INT TERM

# Check Burp is running
check_burp() {
    if ! lsof -ti:9876 > /dev/null 2>&1; then
        echo -e "${RED}[!] Burp MCP Server not detected on port 9876${NC}"
        echo -e "${YELLOW}Make sure:${NC}"
        echo "  1. Burp Suite is running"
        echo "  2. MCP Server extension is installed and enabled"
        echo "  3. MCP Server is listening on port 9876"
        echo ""
        read -p "Continue anyway? (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    else
        echo -e "${GREEN}[✓] Burp MCP Server detected${NC}"
    fi
}

# Start Caddy
start_caddy() {
    # Kill existing Caddy on port 9877
    lsof -ti:9877 | xargs kill 2>/dev/null || true
    sleep 1
    
    echo -e "${BLUE}[*] Starting Caddy reverse proxy...${NC}"
    caddy start --config "$CADDY_CONFIG" --pidfile "$CADDY_PID"
    sleep 1
    
    if lsof -ti:9877 > /dev/null 2>&1; then
        echo -e "${GREEN}[✓] Caddy running on port 9877${NC}"
    else
        echo -e "${RED}[!] Caddy failed to start${NC}"
        exit 1
    fi
}

# Main
echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     Burp MCP Toolkit Launcher          ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"
echo ""

check_burp
start_caddy

echo ""
echo -e "${GREEN}[✓] Ready!${NC}"
echo ""
echo "Starting Claude Code in: $SCRIPT_DIR"
echo ""
echo -e "${YELLOW}Commands:${NC}"
echo "  load scope     - Load and validate scope.yaml"
echo "  triage         - Classify endpoints"
echo "  analyze all    - Run all indicator tests"
echo "  report         - Generate final report"
echo ""
echo "Press Ctrl+C to stop"
echo ""

cd "$SCRIPT_DIR"
claude

# Keep running until interrupted
wait
EOF
    
    chmod +x "$SCRIPT_DIR/launch.sh"
    log_success "Launcher script created: $SCRIPT_DIR/launch.sh"
}

create_gitignore() {
    cat > "$SCRIPT_DIR/.gitignore" << 'EOF'
# Output files (generated during analysis)
output/endpoints.json
output/findings/*.md
output/report.md

# Scope config (contains tokens)
scope.yaml

# System files
.DS_Store
*.pyc
__pycache__/
*.egg-info/
.eggs/

# Editor files
.vscode/
.idea/
*.swp
*.swo
*~

# Logs
*.log

# Local testing
test/
tmp/
EOF
    log_success ".gitignore created"
}

print_summary() {
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║             Installation Complete!                         ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BLUE}Next Steps:${NC}"
    echo ""
    echo "  1. ${YELLOW}Open Burp Suite${NC} and accept the license agreement"
    echo ""
    echo "  2. ${YELLOW}Install MCP Server extension${NC}:"
    echo "     - Go to Extender > BApp Store"
    echo "     - Search for 'MCP Server'"
    echo "     - Click Install"
    echo ""
    echo "  3. ${YELLOW}Export mcp-proxy.jar${NC} (if not already present):"
    echo "     - Go to Extender > Extensions > MCP Server"
    echo "     - Click 'Export mcp-proxy.jar'"
    echo "     - Save to: $MCP_EXT_DIR/mcp-proxy.jar"
    echo ""
    echo "  4. ${YELLOW}Configure your scope${NC}:"
    echo "     cd $SCRIPT_DIR"
    echo "     cp templates/scope-template.yaml scope.yaml"
    echo "     # Edit scope.yaml with your target info"
    echo ""
    echo "  5. ${YELLOW}Start the toolkit${NC}:"
    echo "     ./launch.sh"
    echo ""
    echo -e "${BLUE}Documentation:${NC}"
    echo "  README.md       - Quick start guide"
    echo "  CLAUDE.md       - Orchestration instructions"
    echo "  skills/         - Methodology files"
    echo ""
}

# Main execution
main() {
    echo ""
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║         Burp MCP Toolkit Installer                         ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    check_os
    check_arch
    
    echo ""
    log_info "Installing dependencies..."
    echo ""
    
    install_homebrew
    install_burp
    install_caddy
    install_node
    install_claude_code
    install_burp_mcp_extension
    
    echo ""
    log_info "Configuring..."
    echo ""
    
    configure_claude_mcp
    create_launcher
    create_gitignore
    
    print_summary
}

main "$@"
