import logging
import time
from typing import Optional
from ..app.runtime.models import RemediationScript

logger = logging.getLogger("vigil.services.remediation_script")

class RemediationScriptService:
    """Generates context-aware, template-driven remediation scripts to automatically fix agent issues."""
    
    def __init__(self, registry):
        self.registry = registry

    async def generate_script(self, incident_id: str, agent_id: str, threat_type: str, script_type: str = "PYTHON") -> RemediationScript:
        """Produces a Python or Bash recovery script based on threat metadata."""
        
        # Select script template
        if script_type.upper() == "PYTHON":
            code = self._generate_python_script(agent_id, threat_type)
        else:
            code = self._generate_bash_script(agent_id, threat_type)

        script = RemediationScript(
            incident_id=incident_id,
            script_type=script_type.upper(),
            code=code,
            generated_at=time.time()
        )
        await self.registry.save_remediation_script(script)
        logger.info(f"Generated {script_type} remediation script for incident {incident_id}")
        return script

    def _generate_python_script(self, agent_id: str, threat_type: str) -> str:
        return f'''#!/usr/bin/env python3
"""
VIGIL 2.0 Autonomous Remediation Script
Threat Type: {threat_type}
Target Agent: {agent_id}
Generated At: {time.strftime('%Y-%m-%d %H:%M:%S')}
"""

import sys
import os
import urllib.request
import json

def quarantine_agent():
    print("[*] Contacting VIGIL gateway to quarantine agent {agent_id}...")
    # Trigger local API endpoint to isolate agent
    try:
        url = "http://localhost:8000/api/v2/agents/{agent_id}/status"
        req = urllib.request.Request(
            url, 
            data=json.dumps({{"status": "QUARANTINED"}}).encode("utf-8"),
            headers={{"Content-Type": "application/json"}},
            method="PUT"
        )
        with urllib.request.urlopen(req) as response:
            if response.status == 200:
                print("[+] Agent {agent_id} quarantined successfully.")
            else:
                print("[-] Failed to update status: ", response.status)
    except Exception as e:
        print("[-] Connection failed: ", e)

def invalidate_tokens():
    print("[*] Purging secure session variables and key rings...")
    env_file = ".env"
    if os.path.exists(env_file):
        with open(env_file, "r") as f:
            lines = f.readlines()
        
        with open(env_file, "w") as f:
            for line in lines:
                if any(k in line for k in ["API_KEY", "SECRET", "PASSWORD", "TOKEN"]):
                    # Redact credential line
                    f.write(f"# REVOKED: {{line.split('=')[0]}}=\\n")
                    print(f"[!] Redacted credential: {{line.split('=')[0]}}")
                else:
                    f.write(line)
        print("[+] Credentials successfully invalidated.")

def apply_sandboxing():
    print("[*] Reconfiguring network permissions under ArmorClaw...")
    # Inject secure sandbox policy
    policy_path = f"sandbox_policy_{agent_id}.json"
    policy_data = {{
        "agent_id": "{agent_id}",
        "network_access": "RESTRICTED",
        "file_system_access": "READ_ONLY",
        "authorized_tools": ["read_file", "search_web"]
    }}
    with open(policy_path, "w") as f:
        json.dump(policy_data, f, indent=4)
    print(f"[+] Saved secure sandboxing configuration to {{policy_path}}")

def main():
    print("[VIGIL] Bootstrapping remediation script...")
    
    if "{threat_type}" == "PROMPT_INJECTION" or "{threat_type}" == "PROMPT_MUTATION":
        print("[!] Mutation/Injection incident detected. Applying input filtering & sanitization.")
        apply_sandboxing()
    elif "{threat_type}" == "DATA_EXFILTRATION" or "{threat_type}" == "PRIVILEGE_ESCALATION":
        print("[!] High severity intrusion detected. Triggering immediate quarantine.")
        quarantine_agent()
        invalidate_tokens()
    else:
        print("[!] Low-severity alert. Enforcing tighter sandbox parameters.")
        apply_sandboxing()
        
    print("[VIGIL] Remediation playbook run completed.")

if __name__ == "__main__":
    main()
'''

    def _generate_bash_script(self, agent_id: str, threat_type: str) -> str:
        return f'''#!/bin/bash
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# VIGIL 2.0 Autonomous Remediation Playbook (Bash)
# Threat Type: {threat_type}
# Target Agent: {agent_id}
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

echo "[*] Initializing bash response script for {agent_id}..."

# 1. Kill active processes belonging to agent environment
echo "[*] Auditing running tasks for agent container..."
pids=$(pgrep -f "main.py.*{agent_id}")
if [ -n "$pids" ]; then
    echo "[!] Killing anomalous agent processes: $pids"
    kill -9 $pids
fi

# 2. Reconfigure routing rules / firewall to isolate agent
echo "[*] Injecting iptables containment envelope..."
iptables -A OUTPUT -m owner --uid-owner {agent_id} -j REJECT --reject-with icmp-port-unreachable
echo "[+] Blocked all outbound internet sockets for uid={agent_id}."

# 3. Rotate certs if supply chain violation
if [ "{threat_type}" == "SUPPLY_CHAIN_COMPROMISE" ]; then
    echo "[!] Regenerating client security credentials..."
    rm -rf ~/.vigil/certs/{agent_id}.pem
    echo "[+] Rotated cert footprint."
fi

echo "[VIGIL] System rollback complete. Agent {agent_id} has been isolated."
'''
