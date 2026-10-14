# Platform Changes Log

Log of every platform write, including configuration registrations and dashboard policy changes.

## 2026-10-14T05:32:00Z — Initial Registration: vigil-containment
- **Action**: `armoriq register --config config/vigil-containment.armoriq.yaml`
- **Identity**: `vigil-containment`
- **MCP Server**: `vigil-containment`
- **Tool**: `quarantine_agent`
- **Tunnel URL**: `https://camel-technical-tournament-karma.trycloudflare.com/mcp`
- **Pre-validation**: Passed (`armoriq validate`)

## 2026-10-14T06:40:00Z — Updated Registration: vigil-containment-v2
- **Action**: `armoriq register --config config/vigil-containment.armoriq.yaml`
- **Identity**: `vigil-containment-v2`
- **MCP Server**: `vigil-containment-v2`
- **Tool**: `quarantine_agent`
- **Tunnel URL**: `https://friday-gaming-controller-operators.trycloudflare.com/mcp`
- **Policy**: `allow: ["vigil-containment-v2.quarantine_agent"]`
- **Pre-validation**: Passed (`armoriq validate`)
- **Status**: Registered with proxy endpoint `https://customer-proxy.armoriq.ai`

## 2026-10-14T06:50:00Z — Initial Registration: customer-bot
- **Action**: `armoriq register --config config/customer-bot.armoriq.yaml`
- **Identity**: `customer-bot`
- **MCP Server**: `vigil-tools`
- **Tools**: `order_status`, `billing_database`
- **Tunnel URL**: `https://monthly-theatre-reward-licence.trycloudflare.com/mcp`
- **Policy**: `allow: ["vigil-tools.order_status", "vigil-tools.billing_database"]`
- **Pre-validation**: Passed (`armoriq validate`)
- **Status**: Registered with proxy endpoint `https://customer-proxy.armoriq.ai`
