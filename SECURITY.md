# Security Policy

## Supported Versions

Security updates and vulnerability patches are applied to the active VIGIL v2 release branch:

| Version | Supported          |
| ------- | ------------------ |
| 2.0.x   | :white_check_mark: |
| < 2.0   | :x:                |

---

## Reporting a Vulnerability

The VIGIL project team takes security vulnerabilities seriously. We appreciate responsible disclosure.

If you discover a security vulnerability in VIGIL, the ArmorIQ integration gate, or the policy immune loop, please follow these reporting guidelines:

1. **Do NOT open a public GitHub issue.** Public issues disclose sensitive vulnerability details before a patch can be validated.
2. **Contact Point**: Send an email directly to the primary maintainer:
   - **Email**: `slssaishankar@gmail.com`
   - **Subject**: `[SECURITY VULNERABILITY] VIGIL - <Brief Summary>`
3. **Include the following details in your report**:
   - Description of the vulnerability and potential impact.
   - Exact steps or proof-of-concept script to reproduce the behavior.
   - Affected components (e.g. `backend/app/channels/slack.py`, `backend/app/immune/`, or FastMCP containment endpoints).
   - Any suggested mitigations or patches.

---

## Response Timeline

- **Initial Acknowledgment**: Within 24 hours of receiving the disclosure.
- **Triage & Assessment**: Within 48 hours to confirm severity and reproduction steps.
- **Remediation & Patch**: A fix will be developed, tested against offline regression suites, and released with an advisory.
