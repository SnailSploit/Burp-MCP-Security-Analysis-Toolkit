# Contributing to Burp MCP Toolkit

Thank you for your interest in contributing! This document provides guidelines for contributions.

## How to Contribute

### Reporting Issues

- Check existing issues before creating a new one
- Include reproduction steps
- Provide environment details (macOS version, Burp version, etc.)
- For security vulnerabilities, please report privately

### Adding New Indicators

1. **Create the skill file**: `skills/SKILL-{indicator}-testing.md`
   
   Follow the structure of existing skills:
   ```markdown
   # SKILL: {Indicator} Testing Methodology
   
   ## Severity Context
   [Table of severity ratings by data type]
   
   ## Prerequisites
   [What needs to be in place before testing]
   
   ## Methodology
   [Step-by-step testing approach]
   
   ## Evidence Requirements
   [What constitutes proof]
   
   ## Output Format
   [How to document findings]
   ```

2. **Update templates**:
   - Add to `templates/scope-template.yaml` under `indicators.enabled`
   - Update `CLAUDE.md` skill table

3. **Test thoroughly**:
   - Run against a test target
   - Verify Claude Code follows the methodology
   - Check output format consistency

### Improving Existing Skills

Skills encode methodology - improvements should be based on:
- Real-world testing experience
- New attack patterns or techniques
- Better evidence collection approaches
- Clearer step-by-step instructions

### Python Helpers (`lib/`)

- Follow existing code style
- Add docstrings and type hints
- Include usage examples in docstrings
- Maintain backward compatibility

## Code Style

### Python
- Follow PEP 8
- Use type hints
- Docstrings for all public functions
- Meaningful variable names

### Markdown (Skills)
- Use consistent heading hierarchy
- Include code blocks with language hints
- Tables for structured data
- Clear step numbering in methodology

### Shell Scripts
- Use shellcheck-clean bash
- Include comments for complex logic
- Handle errors with `set -e`
- Use meaningful function names

## Pull Request Process

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-indicator`
3. Make your changes
4. Test thoroughly
5. Update documentation
6. Submit PR with clear description

### PR Checklist

- [ ] Code follows style guidelines
- [ ] Documentation updated
- [ ] Tested with real Burp traffic
- [ ] No sensitive data in commits
- [ ] Commit messages are clear

## Skill Writing Guidelines

### Good Methodology Characteristics

✅ **Specific**: "Check if user_id parameter accepts other users' IDs"  
❌ **Vague**: "Look for access control issues"

✅ **Actionable**: "Query Burp for requests where response contains 'user_id' field"  
❌ **Abstract**: "Analyze the response for interesting data"

✅ **Evidence-focused**: "Capture request ID where User A accesses User B's data"  
❌ **Result-focused**: "Find IDOR vulnerability"

### Methodology Structure

1. **What to look for** - Specific patterns, parameters, behaviors
2. **How to test** - Exact steps with example queries
3. **How to verify** - Distinguishing true positives from false positives
4. **How to document** - Evidence format with Burp request IDs

## Development Setup

```bash
# Clone
git clone https://github.com/yourusername/burp-mcp-toolkit.git
cd burp-mcp-toolkit

# Python deps (optional, for helpers)
pip install pyyaml

# Run tests
python -m pytest lib/ -v
```

## Questions?

Open an issue with the `question` label.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
