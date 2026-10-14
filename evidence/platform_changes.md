# Platform Changes Log

Log of every platform write, including configuration registrations and dashboard policy changes.

## 2026-10-14T05:32:00Z — Initial Registration: vigil-containment
- **Action**: `armoriq register --config config/vigil-containment.armoriq.yaml`
- **Identity**: `vigil-containment`
- **MCP Server**: `vigil-containment`
- **Tool**: `quarantine_agent`
- **Tunnel URL**: `https://camel-technical-tournament-karma.trycloudflare.com/mcp`
- **Policy**: `allow: ["vigil-containment.quarantine_agent"]`
- **Pre-validation**: Passed (`armoriq validate`)
