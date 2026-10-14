# VIGIL v2 — Policy Synthesis & Closed-Loop Governance

Empirical verification of the "Incident to Policy" closed-loop governance cycle:

## 1. Lifecycle Timeline
1. **Initial Baseline**: `customer-bot` had permissions for both `order_status` and `billing_database`. Both tools succeeded.
2. **Attack Observed**: Adversary attempted unauthorized prompt injection and credential exfiltration on `billing_database`.
3. **Automated Synthesis**: `synthesize()` analyzed the attack calls against benign history:
   - Evaluated `billing_database`: 2 attack calls, 0 benign calls -> **Proposed for DENIAL**.
   - Evaluated `order_status`: Legitimate production tool -> **Protected from denial**.
4. **Human Confirmation**: Operator approved the policy patch.
5. **Platform Registration**: Patch registered with ArmorIQ control plane (`cli-customer-bot-vigil-tools`).
6. **Enforcement Proved**:
   - `order_status`: **ALLOWED** (Status: `success`)
   - `billing_database`: **BLOCKED** (`PolicyBlockedException: Tool 'billing_database' denied by OPA: policy_constraints_not_satisfied`)

## 2. Evidence Artifacts
- Baseline Invocations: [`evidence/policy_loop/step1_baseline.json`](file:///evidence/policy_loop/step1_baseline.json)
- Proposed Patch: [`evidence/policy_loop/proposed_patch.yaml`](file:///evidence/policy_loop/proposed_patch.yaml)
- Before Config: [`evidence/policy_loop/customer-bot.before.yaml`](file:///evidence/policy_loop/customer-bot.before.yaml)
- After Config: [`evidence/policy_loop/customer-bot.after.yaml`](file:///evidence/policy_loop/customer-bot.after.yaml)
- Patch Diff: [`evidence/policy_loop/policy_diff.patch`](file:///evidence/policy_loop/policy_diff.patch)
- Enforcement Proof: [`evidence/policy_loop/step3_verification.json`](file:///evidence/policy_loop/step3_verification.json)
