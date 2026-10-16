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
