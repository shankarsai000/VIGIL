# VIGIL 2.0 — Hackathon Disclosure & In-Window Audit (DISCLOSURE.md)

## 1. Hackathon Window & Attribution

- **Event**: Flow State Hackathon by ArmorIQ
- **Build Week Window**: October 10, 2026 00:00 UTC – October 17, 2026 23:59 UTC
- **Current Release Tag**: VIGIL 2.0 (Commit on branch `submission-package`)
- **Baseline Commit**: `6942674d9b15e7508518a7b4d6e1c923b4f191e5`
- **Baseline Timestamp**: October 14, 2026 10:51:51 +0530 (05:21:51 UTC)
- **Compliance Guarantee**: All work developed between the baseline commit and `HEAD` was created strictly within the hackathon build window. Git history is linear and untampered (no squashes, rebases, or force pushes).

---

## 2. In-Window Commit History

The following 31 commits represent the sequential milestone deliveries during the Flow State Hackathon build window:

| Commit Hash | Date (UTC) | Milestone | Commit Message / Description |
|---|---|---|---|
| `3cb39f3` | 2026-10-14 | P0.1 | `feat(armoriq): add and verify armoriq_smoke.py for P0.1` |
| `71bde54` | 2026-10-14 | P0.2-P0.3 | `feat(armoriq): register vigil-containment identity and MCP for P0.2 and P0.3` |
| `636531b` | 2026-10-14 | P0.4 | `docs(armoriq): document live findings and answers to P0.4 day-one questions` |
| `f5432e4` | 2026-10-14 | Governance | `feat(governance): record actual containment outcome on human approval and audit log` |
| `d60f5dd` | 2026-10-14 | Matrix | `feat(armoriq): complete live scenario matrix (ALLOW, DENY, HOLD, BENIGN) and record evidence` |
| `cf986fa` | 2026-10-14 | Audit | `feat(audit): verify live audit ledger and prove cryptographic tamper detection` |
| `f4d656f` | 2026-10-14 | Test | `test(armoriq): add live verification test suite and register live mark` |
| `2cac960` | 2026-10-14 | Loop | `feat(policy-loop): close policy loop with live attack synthesis and verified deny enforcement` |
| `1891a3e` | 2026-10-14 | Docs | `docs: add demo script and walkthrough for hackathon evaluation` |
| `9eafd36` | 2026-10-14 | Docs | `docs: finalize architecture, judge reproduction guide, and hackathon submission` |
| `c813942` | 2026-10-14 | P0-0 | `fix(containment): route all containment paths through ArmorIQ gate and enforce allowlist (P0-0)` |
| `7471c7d` | 2026-10-14 | P0-1 | `feat(quarantine): release only by human operator with reason and ledger logging (P0-1)` |
| `50ffb6e` | 2026-10-14 | P0-2 | `feat(dashboard): derive enforcement header badge from health gate mode (P0-2)` |
| `ad8c31f` | 2026-10-14 | P0-3 | `feat(metrics): derive all executive and command bar metrics honestly (P0-3)` |
| `b61aa73` | 2026-10-14 | P0-4 | `feat(governance): separate policy decision from containment outcome (P0-4)` |
| `2983747` | 2026-10-14 | P0-5 | `feat(explainer): honest narrative reflecting storage type and ArmorIQ mode (P0-5)` |
| `cfd6836` | 2026-10-14 | P1-1 | `P1-1: Attack feedback states, 10s timeout, origin tagging, dock scenarios verification` |
| `8420471` | 2026-10-14 | P1-2 | `P1-2: Grouped approval queue with deduplication, bulk actions, expiry, and preview` |
| `cc02912` | 2026-10-14 | P1-3/6 | `P1-3 & P1-6: 3-state connection resilience, error banners naming settings, self-hosted fonts, and Vite proxy stabilization` |
| `585db6c` | 2026-10-14 | P1-7 | `P1-7: Tamper-evident audit ledger with GET /audit/verify, Verify button, and INCIDENT column` |
| `38d957b` | 2026-10-14 | P2 | `P2: Attack graph label collision fixes, relative timestamps with absolute tooltips, and focus rings` |
| `3684133` | 2026-10-14 | Chore | `chore: bind Vite server to 0.0.0.0` |
| `39be2aa` | 2026-10-14 | UI | `docs(ui): add 1440x900 and 390x844 responsive screenshots of all 5 views` |
| `11c0939` | 2026-10-14 | M0 | `docs(M0): baseline truth check and product spec` |
| `f6bfb0a` | 2026-10-14 | M1 | `feat(M1): action records, structural redaction, and labelled traces` |
| `7794071` | 2026-10-14 | M2 | `feat(M2): pure counterfactual replay engine and false-block bound` |
| `bbce971` | 2026-10-15 | M3 | `feat(M3): candidate rules and dry-run compiler` |
| `5413f51` | 2026-10-15 | M4 | `feat(M4): proposal workflow and UI` |
| `b6155f9` | 2026-10-15 | M5 | `feat(M5): armoriq verification and signed receipts` |
| `91ef1fb` | 2026-10-16 | SLACK-1 | `feat(SLACK-1): implement slack approval adapter and telegram removal` |
| `0821628` | 2026-10-16 | SLACK-1 | `docs(SLACK-1): mark live slack verification claims as verified pass with evidence` |
| `3803c72` | 2026-10-17 | R0 | `feat(R0): establish requirements baseline and compliance checker` |

---

## 3. Diff Statistics & Scope of In-Window Work

```
Total In-Window Commits: 32 (including R0 and pending R1)
Files Changed: 204
Insertions: +23,772 lines
Deletions: -700 lines
```

### Key Subsystems Built During Build Week
1. **ArmorIQ Policy Loop & Gate**: Direct integration with ArmorIQ management API (`https://api.armoriq.ai`) and customer proxy (`https://customer-proxy.armoriq.ai`), returning cryptographically signed receipts for all containment actions.
2. **Policy Immune System (M1–M4)**:
   - Action recorder and structural redaction (`backend/app/immune/redaction.py`).
   - Counterfactual replay engine with Clopper-Pearson exact binomial false-block bound calculations (`backend/app/immune/replay.py`).
   - Automated candidate rule generation and OPA / ArmorIQ YAML compilation (`backend/app/immune/compiler.py`).
   - Dual-approver proposal lifecycle and interactive web UI (`backend/app/immune/proposals.py`, `frontend/src/components/PolicyProposalsView.tsx`).
3. **Evidence Vault & Offline Cryptographic Verifier**: Standalone Ed25519-signed offline verification bundle (`backend/app/evidence/bundle.py`, `verify_bundle.py`).
4. **Slack Corporate Approval Adapter (SLACK-1)**: Enterprise approval adapter verifying HMAC-SHA256 signatures and corporate Slack identity mappings, replacing legacy Telegram bot hooks.
5. **Requirements Compliance System (R0–R1)**: Machine-checkable requirements matrix (`docs/brief/REQUIREMENTS.md`, `scripts/check_requirements.py`).

---

## 4. Pre-Existing Code vs. New Features

- **Pre-existing (Baseline `6942674`)**: Early structural scaffold of dashboard UI components, mock detector heuristics, and SQLite event schema.
- **In-Window (Oct 14–17)**: Every production ArmorIQ integration, signed receipts, policy immune compiler, Clopper-Pearson replay engine, cryptographic evidence vault, Slack approval adapter, and audit ledger chain verification.
