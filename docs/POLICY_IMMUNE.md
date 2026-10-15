# VIGIL: Policy-Immune AI Agent Governance Architecture

## 1. The Problem
Enterprise autonomous AI agents operate with high privileges, invoking internal APIs, executing database queries, and delegating sub-tasks across complex multi-agent graphs. Traditional security architectures fall short:
- **Perimeter Defenses are Blind**: Perimeter firewalls cannot inspect the semantic context or intent of internal agent tool invocations.
- **Naive Autonomous Blocking Breaks Operations**: Heuristic detectors that aggressively block agent execution incur high false-positive rates, disrupting mission-critical business workflows.
- **The Metric Hierarchy**: In enterprise agent security, the true objective is **safe blocking**. Minimising the false-block rate is the primary metric; blocking attacks is secondary. An immune system must never cause autoimmune destruction of normal business operations.

---

## 2. Product Principles

### 2.1 Safe Blocking
- Candidate security policies generated from incident post-mortems must be verified against recorded historical traffic before live enforcement.
- A proposed rule is rejected if it collides with legitimate historical behavior of that agent.
- Policies are dry-run by default until proven safe.

### 2.2 Fail Closed
- Every decision path, gate invocation, credential lookup, and authorization check must fail closed.
- If a check times out, encounters a network error, receives an unexpected HTTP status, or fails authorization, the outcome must be `DENIED` or `ESCALATE`.
- Default-allow or fail-open fallbacks are strictly prohibited.

### 2.3 One Enforcement Path
- Containment actions (such as agent quarantine) and policy alterations must traverse a single, unified enforcement gate (`ArmorIQGate`) and approval workflow.
- Direct status modifications (e.g., setting `status = QUARANTINED` directly on agent profiles or database records) are forbidden across the codebase and enforced by AST scanning tests.

---

## 3. Metric Definitions

### 3.1 Coverage
Coverage measures the fraction of observed attack vectors or tools targeted during an incident that have candidate deny rules synthesized:
$$\text{Coverage} = \frac{|\mathcal{T}_{\text{attacked}} \cap \mathcal{T}_{\text{policy_denied}}|}{|\mathcal{T}_{\text{attacked}}|}$$
Where $\mathcal{T}_{\text{attacked}}$ is the set of tool names identified in confirmed attack telemetry.

### 3.2 False-Block Rate (Empirical)
The empirical rate at which a synthesized candidate policy would block legitimate, non-malicious operations across recorded baseline traffic:
$$\text{False-Block Rate} = \frac{|\{e \in \mathcal{D}_{\text{benign}} : \text{Policy}(\text{agent}(e), \text{tool}(e)) = \text{DENY}\}|}{|\mathcal{D}_{\text{benign}}|}$$
A candidate policy proposal is valid if and only if empirical false-block rate equals $0$ across the verification corpus.

### 3.3 Statistical Upper Bound
Given $n$ recorded benign events where $k = 0$ false blocks are observed, the one-sided upper confidence bound on the true out-of-sample false-block probability $p$ at confidence level $1 - \delta$ is calculated via the Clopper-Pearson / Beta distribution quantile:
$$\bar{p}_{1-\delta} = 1 - \delta^{1/n}$$
For example, across $n = 300$ benign samples with $0$ violations, the $95\%$ confidence upper bound on false blocks is:
$$\bar{p}_{0.95} = 1 - (0.05)^{1/300} \approx 0.00994 \text{ (0.99%)}$$

---

## 4. Foundational Assumptions

### 4.1 Exchangeability
- Historical recorded interactions and future agent interactions are assumed to be conditionally exchangeable given the agent's profile, role, and operational context.
- If an agent's operational scope, underlying model, or prompt template changes (covariate shift), the empirical safety bounds must be re-calibrated on fresh traffic.

### 4.2 Assumed Benign Labels
- Unlabelled historical agent traffic is **assumed benign** rather than confirmed benign.
- Ground truth malicious labels derive exclusively from simulator scenario ground truth or human-confirmed incident triage.
- All evaluation reports and safety metrics must explicitly acknowledge the "assumed benign" baseline.
