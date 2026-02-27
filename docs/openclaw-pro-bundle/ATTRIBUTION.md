# Attribution & Credits

This product builds on work from the open source community and production deployment experience.

## Core Dependencies

### OpenClaw
- **License**: MIT License
- **Author**: Peter Steinberger ([@steipete](https://x.com/steipete))
- **Source**: [github.com/steipete/openclaw](https://github.com/steipete/openclaw)
- **Description**: Self-hosted MCP gateway for Claude
- **License Text**: See LICENSE file in this distribution

### Node.js
- **Version**: 22.x (LTS)
- **License**: MIT License
- **Purpose**: Runtime environment for OpenClaw gateway

### Anthropic Claude
- **API**: Claude API via MCP protocol
- **Documentation**: [docs.anthropic.com/claude/docs](https://docs.anthropic.com/claude/docs)
- **Purpose**: AI model integration

### Tailscale
- **Purpose**: VPN mesh networking for secure remote access
- **Referenced for**: Security configuration guidance
- **Website**: [tailscale.com](https://tailscale.com)

## Original Work

The following components were created specifically for this product:

### Interactive Setup Scripts (`Setup.command`, `Setup-VPS.sh`)
- Unified beginner flow for macOS and Linux/VPS
- Uses official OpenClaw installer with `--no-onboard`, then runs onboarding with safe defaults
- Generates SOUL.md, USER.md, and MEMORY.md
- Derived from production deployment patterns and OpenClaw docs

### Identity System
- SOUL.md, USER.md, and MEMORY.md generated dynamically by setup scripts
- 100% original content
- Designed for agent personalization workflow

### Security Configurations
- Hardening checklists and procedures
- Cost control frameworks
- VPN setup guides
- Based on industry best practices and community research

### Handoff Structure
- 6-folder workflow system
- Original organizational methodology
- Optimized for agent-human collaboration

## Security Research Citations

### Shodan Exposure Findings
- **Researcher**: Jamieson O'Reilly ([@vmprotect](https://x.com/vmprotect))
- **Date**: January 2025
- **Finding**: 780+ exposed OpenClaw instances
- **Source**: [x.com/vmprotect/status/1879590453876359461](https://x.com/vmprotect/status/1879590453876359461)

### Gartner Advisory
- **Organization**: Gartner
- **Advisory**: GenAI Security Risks (MCP/LLM gateway vulnerabilities)
- **Purpose**: Industry context for security best practices

## License

### This Product
- **Personal Use**: Unlimited
- **Business Use**: Unlimited
- **Resale**: Not permitted
- **Modification**: Encouraged for personal/business use
- **Redistribution**: Not permitted without written consent

### Included OpenClaw Software
- **License**: MIT License (see LICENSE file)
- **Modifications**: Scripts customize but do not modify OpenClaw source
- **Distribution**: OpenClaw installed via official installer (`https://openclaw.ai/install.sh`)

## Disclaimer

This product provides setup automation and configuration guidance for OpenClaw. It does not modify OpenClaw's source code. All security recommendations are provided as guidance and do not constitute security guarantees. Users are responsible for their own infrastructure security.

## Contact

- **Product Support**: [skillstack.ai/support](https://skillstack.ai/support)
- **General Inquiries**: hello@skillstack.ai
- **Security Issues**: security@skillstack.ai

## Changelog

Significant updates and changes to this product will be documented in CHANGELOG.md (if provided).

---

**Last Updated**: 2026-02-17
**Product Version**: 4.0.0
**SkillStack Product ID**: SKILLSTACK-008
