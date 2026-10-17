# VIGIL: standing instructions

## Purpose
VIGIL is a policy immune system for AI agents. It detects agent misbehaviour, turns confirmed incidents into candidate ArmorIQ policies, proves each candidate on recorded traffic before it may block anything, enforces approved policies through ArmorIQ, and keeps tamper-evident evidence. We win on safe blocking. False blocks are the metric we minimise. Attacks blocked is secondary.

## Non-negotiable rules
1. Fail closed. Any check that errors, times out, or returns something unexpected must deny or escalate. Never approve by default.
2. One enforcement path. Containment and policy changes go through the gate and the approval workflow. Do not add direct status writes or direct policy writes. A test must enforce this.
3. Labels never come from the detector. Ground truth comes from simulator labels or human-confirmed incidents. Unlabelled traffic is "assumed benign", and every report must say so.
4. Dry-run by default. Writing armoriq.yaml, registering with ArmorIQ, or quarantining agents requires either a test mock or an explicit live flag.
5. No secrets in logs, commits, or reports. The armoriq-sdk key and the local operator secret must stay out of git and out of evidence/. Redact to [REDACTED].

## Report format:
Every phase ends with evidence/<phase>/report.md containing:
- acceptance table: row per item in phase with status (pass / fail / blocked) and the exact evidence file and line that proves it.
- files added or modified, with line counts and reasons.
- what is not verified and why.
- blockers for next phase.

## Git rules:
- Work on branch named in the prompt.
- Commit after each completed phase. Commit message format: <type>(<phase>): <short summary>.

## VIGIL v3 rules (append to CLAUDE.md)

A. ArmorIQ decides every tool-call block. VIGIL computes provenance, budgets, canaries, and scanner output, then passes them to ArmorIQ as inputs: a mint-time inline policy, plan contents, or a containment directive. VIGIL never returns allowed or denied for an agent's tool call on its own. A static test fails the build if any function outside the gate returns such a verdict for a tool call.

B. Every containment action is an ArmorIQ-authorized call on the containment MCP server: downgrade, shadow routing, quarantine, and rollback. The gate stays the single enforcement path. Data-plane effects, such as which database a session reads, happen only after ArmorIQ authorizes the directive, and every one is recorded in the ledger.

C. Statistical claims are bounds, never point claims. Zero events in n trials is reported as "0 of n; one-sided 95% upper bound from Clopper-Pearson." Never write "0% FPR" for a finite sample.

D. Demo and UI numbers come from the pipeline. No percentage, score, or badge text is hard-coded in a component, a demo script, or a narrative. A test scans UI source for numeric literals in metric contexts.

E. Antibodies and any LLM-generated rule are proposals. They go through the M3 dry-run compiler and the M4 approval flow. LLM output is parsed as JSON against a schema, is never executed or evaluated, and is never applied automatically.

F. Honeypot, canary, and shadow routing are sandbox-only. They never receive real credentials or real data. Every use is disclosed in docs/SANDBOX.md, and operators see every routing decision in the ledger and the dashboard.

G. Compensations exist only for tools that declare an inverse in config/tool_compensations.yaml. Anything else is marked IRREVERSIBLE. Compensating calls are ArmorIQ-authorized too.

H. One threshold table. Every score threshold and budget lives in config/thresholds.yaml, and the docs are generated from it. The P0 rules stay in force: no direct status writes, no timer-based release, and no auto path that bypasses the gate.

I. Map to the real package. New code goes under backend/app/. Never create flat backend/*.py modules, and never import from archive/.

J. Novelty needs prior art. An innovation claim stays UNVERIFIED until docs/research/ holds a prior-art note for it, citing sources the human provides.

