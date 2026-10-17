<USER_REQUEST>
I read the PDF. Most of its ideas are worth building, but several would fail the hackathon brief, break the fail-closed rules we already set, or claim numbers the data can't support. The prompts below keep the innovations and correct those problems.

## Changes from the PDF

- **Blocking moves to ArmorIQ.** The PDF's `evaluate_sink_policy` and `select_adaptive_remediation` return allowed or denied inside VIGIL. The brief requires actual ArmorIQ enforcement, so VIGIL can only supply inputs (taint-derived inline policies and containment directives), and ArmorIQ decides.
- **"POST /intent/verify" doesn't exist in the ArmorIQ SDK we pinned (0.6.10).** The real flow is `capture_plan`, `get_intent_token`, then `invoke_with_policy`.
- **"0.0% false positives" from 500 replayed events isn't a valid claim.** Zero in 500 gives a one-sided 95% upper bound of about 0.6%. Every statistical claim needs a bound.
- **The demo numbers (22%, the 3-second badge, 0.0% FPR) are outcomes.** The pipeline has to compute them, and the demo shows whatever it measures.
- **The thresholds conflict.** The PDF uses 0.45, 0.75, and 0.92. The monitor uses 0.45, and the gate uses 0.65 and 0.85. They need one table.
- **The paths are stale.** The PDF writes to flat `backend/services/*.py` files. Those duplicates are archived, so the code goes under `backend/app/`.
- **"Cryptographic" taint is only accurate if the lineage records are signed.** Taint and capability defenses for agents already have prior work, such as CaMeL (2025). The defensible part is the combination, enforced through ArmorIQ and measured.
- **Honeypot and canary routing are deception.** They stay sandbox-only, they're disclosed to operators, and they never touch real credentials or data.

The biggest unknown is the mint-time probe: does an inline deny fail at `get_intent_token` or at `invoke`? If it fails at invoke, taint enforcement is not real, and the prompts label it that way. Run the probe first.

If this is for the Flow State window, it closes today. None of V1 to V9 fits in that window, so run V0 and the probe, and treat the rest as the post-hackathon roadmap.

## Run order

| Phase | Builds | Depends on | Gate |
|---|---|---|---|
| V0 | PDF triage, v3 spec, threshold table | M0 | Spec reviewed |
| V1 | Provenance: lineage, taint, mint-time policy input | V0, mint probe | Probe result recorded |
| V2 | Graduated containment ladder | V1, M5 | Tier and boundary tests |
| V3 | Low-and-slow budgets and canaries | M1 | Benchmark reproduces |
| V4 | Schema pinning and output scanning | V1 | Pinning tests |
| V5 | Antibody candidates (proposals only) | M3, M4, V3 | Backtest bounds |
| V6 | Compensating rollback and blast radius | V1, V2 | Rollback tests |
| V7 | UI upgrades | V1 to V6 | Vitest, screenshots |
| V8 | Demo scenarios 5 and 6 | V1 to V6 | Evidence files |
| V9 | Benchmark and ablations | V1 to V5 | Reproducible |
| VF | Final gate and judge pack | All | F1 checks |

## Addendum for CLAUDE.md

```text
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
```

## V0: PDF triage and v3 spec

```text
PHASE V0: PDF TRIAGE AND v3 SPEC (no feature code)

Read CLAUDE.md, the v3 rules, and docs/POLICY_IMMUNE.md. Copy the uploaded PDF to docs/research/VIGIL_v3_proposal.pdf and extract its text to docs/research/VIGIL_v3_proposal.md.

GOAL
Turn the proposal into a spec that can be built and tested honestly. Mark each claim KEEP, CHANGE, or DROP, with a reason.

STEPS
1. Branch v3-spec. Create evidence/V0/.
2. Write docs/V3_SPEC.md.
   a. Claim table. Every claim in the PDF gets a row: claim, status, reason, and the phase that builds it. Include these known issues:
      - evaluate_sink_policy and select_adaptive_remediation are pre-checks that return allowed or denied. Mark CHANGE.
      - "POST /intent/verify" is not an ArmorIQ SDK API in the pinned version. Mark CHANGE, and cite the introspection output.
      - "0.0% false positives" from 500 events. Mark CHANGE. Zero in 500 gives an upper bound of about 0.6%.
      - Thresholds 0.45, 0.75, and 0.92 conflict with the monitor and gate thresholds. Mark CHANGE.
      - Demo numbers (22%, the 3-second badge, 0.0% FPR) must be computed. Mark CHANGE.
      - Flat backend/services paths. Mark CHANGE to backend/app/.
      - "Cryptographic" taint. Mark CHANGE unless the lineage records are signed.
   b. Architecture diagram in Mermaid. Show the boundary: VIGIL computes inputs, ArmorIQ decides, the containment MCP carries out directives, and the ledger records everything.
   c. config/thresholds.yaml. Every value has a source. Do not invent values. A value you propose is marked PROPOSED and is calibrated in the phase that owns it.
   d. Risk register: operator trust and deception, false taint on legitimate delegations, canary leakage, retention of prompts and PII, honeypot misuse, and LLM-generated rules.
   e. Prior-art table, one row per innovation. Fill it only from sources in docs/research/. Otherwise write UNVERIFIED.
3. List the ArmorIQ probes that V1 and V2 need, with the exact question each one answers. Do not run them in V0.

ACCEPTANCE
- Every PDF claim appears in the claim table.
- No threshold appears without a source or a PROPOSED mark.
- A grep for flat backend/services paths in the spec finds none.

STOP RULES
- If the PDF text is missing, record BLOCKED. Never reconstruct the PDF from memory.
```

## V1: Provenance and lineage

```text
PHASE V1: PROVENANCE AND LINEAGE (taint, delegation DAG, mint-time policy input)

Read CLAUDE.md, the v3 rules, and docs/V3_SPEC.md. Gate: V0 is complete. The mint probe must be recorded in evidence/P1/mint_probe.json. If it is missing, build the offline parts only, and mark live steps BLOCKED.

GOAL
Every agent event and delegation carries a lineage record. Taint only rises along a delegation chain. VIGIL passes a taint-derived policy into ArmorIQ at token mint, and ArmorIQ decides.

BRANCH ON THE PROBE
- If an inline deny raises at mint: build the mint-time path below.
- If it raises only at invoke: do not claim taint enforcement. Build the lineage records and the DAG, mark enforcement NOT ENFORCED in the spec and the UI, record the negative result, and stop.

BUILD
1. backend/app/provenance/lineage.py
   - TaintLevel, ordered: SYSTEM_TRUSTED, VERIFIED_INTERNAL, USER_UNTRUSTED, EXTERNAL_UNTRUSTED.
   - LineageRecord: trace_id, span_id, parent_span_id, from_agent, to_agent, taint, source_label, ts. It is append-only and written to the ledger.
   - Propagation: a child's taint is the maximum of its parent's taint and the taint of its new input. It never decreases.
2. Cycles and depth. Detect cycles with a walk over the delegation graph, not by counting hops. Enforce a depth limit from thresholds.yaml. A cycle or an overflow marks the lineage DEGRADED.
3. Fail closed. A missing lineage record means the token is minted with the privileged-tool deny. ArmorIQ then refuses those tools for that token. Test the minted policy.
4. Mint-time policy. For a privileged tool, get_intent_token receives an inline policy derived from the lineage. It denies the sink when taint exceeds the sink's ceiling. Ceilings live in config/sinks.yaml. Use only the SDK signatures you introspected.
5. Signing, optional and labelled. Ed25519-sign each lineage record if the key exists. Otherwise the field reads UNSIGNED.
6. Static test. Fail the build if any function outside the gate returns allowed or denied for a tool call.

ACCEPTANCE
- Unit tests: monotonic propagation, cycle detection, depth overflow marks DEGRADED, and missing lineage produces the privileged-tool deny in the minted policy.
- Offline golden file: a tainted lineage produces an inline policy that denies the sink.
- Live, with credentials: a tainted delegation to BillingAgent is refused by ArmorIQ, as the probe predicted. Save evidence/V1/live_*.json with trace IDs.
- Benchmark: false-taint rate on 2,000 benign delegations, including legitimate summarization of external content. Report it with a one-sided 95% bound.

STOP RULES
- If the probe contradicts the design, stop and report. Do not change the design to fit the result without a human decision.
```

## V2: Graduated containment ladder

```text
PHASE V2: GRADUATED CONTAINMENT LADDER

Read CLAUDE.md, the v3 rules, and V1. Gate: V1 offline acceptance is green, and M5 offline acceptance is green. Live steps need credentials.

GOAL
Replace binary quarantine with four tiers. Each tier is an ArmorIQ-authorized containment action, so the gate stays the only enforcement path.

TIERS (thresholds from config/thresholds.yaml, never hard-coded)
- LOG_ONLY: audit only.
- DOWNGRADE_SCOPE: the session's intent token carries an inline deny for write and admin tools. Read tools stay allowed.
- SHADOW_SANDBOX: the session is routed to a synthetic data source.
- QUARANTINE_ROLLBACK: the existing gate path, then rollback (V6).

BUILD
1. Extend backend/app/policies/containment_mcp.py with three tools: downgrade_session, route_to_shadow, and rollback_session. Each takes a session ID and a reason, requires the containment secret, and is authorized through the gate exactly as quarantine_agent is.
2. Downgrade. The gate mints the session's token with the deny list. Test that ArmorIQ refuses a write call and accepts a read call in the same session.
3. Shadow. The tools server reads the session directive and switches that session's data source to the mirage database. The mirage database holds synthetic rows only, created by a generator script. Check that no real row is copied. Run two sessions side by side: the shadowed one reads mirage, and the other reads the real sandbox data. Log every shadowed call to the ledger.
4. Tier selection is a pure function of score, criticality, and canary hit. Table-driven tests cover the boundaries. Critical agents never receive LOG_ONLY.
5. Escalation is monotonic within a session. Tiers move up automatically. Moving down requires a human release, using the P0-1 release action.
6. Expose the current tier per session at GET /sessions/{id}/containment, with the ledger entry IDs that produced it.

ACCEPTANCE
- Boundary tests for tier selection pass.
- Downgrade and shadow each have live evidence when credentials exist, labelled as such.
- Isolation test: no call from the shadowed session reaches the real database. Verify from the call log.
- The static test from V1 still passes.

STOP RULES
- If ArmorIQ cannot enforce a tier, do not offer that tier. Do not fall back to a VIGIL-side block.
- Never copy real rows into the mirage database.
```

## V3: Low-and-slow budgets and canaries

```text
PHASE V3: LOW-AND-SLOW BUDGETS AND CANARIES

Read CLAUDE.md, the v3 rules, and docs/V3_SPEC.md. Gate: the M1 action records exist.

GOAL
Catch exfiltration that stays under per-request thresholds, using per-trace budgets and canary records. Store aggregates only, never raw content.

BUILD
1. backend/app/budgets/ledger.py: per-principal and per-trace budgets over sliding windows (one minute, one hour, and the session). Counters: bytes returned to the agent, records returned, sensitive-record count, and a Shannon entropy estimate over returned bytes. Persist aggregates only.
2. Thresholds come from config/thresholds.yaml, calibrated on benign fixtures with a train and test split. Save the calibration to evidence/V3/calibration.json.
3. Canaries. Add a canary table to the sandbox database with synthetic rows whose tokens are HMAC-derived from a secret. No legitimate workflow reads that table, and the schema documents this. Any read of it is a trigger. An outbound tool call containing a canary token is also a trigger.
4. A canary hit selects QUARANTINE_ROLLBACK. A budget breach selects a tier from the table, never from an inline constant.
5. Benchmark. Simulate low-and-slow exfiltration of 250 chunks of about 2 KB each. Compare three detectors: the EWMA layer alone, the budget alone, and the canary alone. Report the chunk of first alert for each, and the budget's false-trip rate on benign fixtures with a one-sided 95% bound.

ACCEPTANCE
- Unit tests: window roll-over, per-trace isolation, and entropy on known inputs.
- A test proves no raw content is written to any table.
- The benchmark reproduces from a fixed seed. Results go to evidence/V3/.
- Negative results stay in. If EWMA alerts earlier than the budget, say so.

STOP RULES
- Do not tune thresholds on the test split.
```

## V4: Schema pinning and output scanning

```text
PHASE V4: SCHEMA PINNING AND TOOL OUTPUT SCANNING

Read CLAUDE.md, the v3 rules, and V1. Gate: V1 offline acceptance is green.

GOAL
Detect tool rug-pulls (a schema or description change after registration) and tool outputs that carry injected instructions. Both signals feed the lineage taint in V1 and the tier selection in V2. VIGIL does not block on its own.

BUILD
1. Pinning. At registration, store the SHA-256 of each tool's canonical schema and description in a hash-chained table. On every tools-list refresh, recompute and compare. A mismatch marks that tool's policy input as UNTRUSTED_SCHEMA and raises an alert. Blocking the tool is an ArmorIQ decision, requested through the gate as a hold or deny.
2. Output scanning. Stage 1 is deterministic rules for instruction-like content in tool results: role markers, "ignore previous" phrasing, hidden markup, and base64 blobs in text fields. Stage 2 is an optional classifier behind an interface, with no weights bundled. Only Stage 1 runs in offline tests.
3. A flagged output sets the child's taint to EXTERNAL_UNTRUSTED through V1. It does not block the call.
4. Scope limit. VIGIL scans only the tools it hosts, unless a third-party tool's results are routed through VIGIL. State this limit in docs/V3_SPEC.md and the UI.
5. Labelled corpus. Write benign tool outputs and injected outputs ourselves. Use third-party attack data only if the human places it in docs/research/ with its license. Report precision and recall with confidence bounds, and state where the corpus came from.

ACCEPTANCE
- A planted schema change is detected on the next refresh, and its ledger entry verifies.
- A planted injection raises the child's taint. The test checks the lineage record, not a block.
- Precision and recall are reported with bounds, with the corpus origin stated.
- The static test from V1 still passes.

STOP RULES
- If a scan result would block a call without an ArmorIQ decision, stop and redesign it as a taint input.
```

## V5: Antibody candidates (proposals only)

```text
PHASE V5: ANTIBODY CANDIDATES (proposals only)

Read CLAUDE.md, the v3 rules, and M2 to M4. Gate: M4 is green, and the V3 benchmark exists.

GOAL
When an incident family repeats, propose a candidate rule with a backtested bound. A human approves it. Nothing deploys automatically.

BUILD
1. Candidate generation. For an incident family, produce a candidate JSON with a fixed schema: pattern (tool, argument-shape class, optional sequence constraint), armoriq_constraint (deny or hold), and a rationale string.
   - Offline: a deterministic generator built from the family's features.
   - With ANTHROPIC_API_KEY: a model proposes the JSON. Validate it against the schema, reject any extra field, cap its length, and never execute or evaluate it.
2. Backtest. Replay the candidate against the last N benign records for the same agents, with N from thresholds.yaml. Compute observed false blocks, the one-sided 95% Clopper-Pearson bound, and recall on the family's attacks.
3. Readiness. A candidate reaches "ready for review" only if observed false blocks are zero AND recall meets the threshold. The UI shows the count and the bound, for example "0 of 500; upper bound 0.6%". The phrase "0% false positives" is not allowed.
4. Hand-off. The candidate becomes an M3 dry-run compile and an M4 proposal. Do not write armoriq.yaml. The UI button reads "Submit for approval", not "Deploy".
5. Injection test. Give the generator an incident whose text asks it to approve everything. Its output must still pass the schema, and the backtest must still gate it.

ACCEPTANCE
- Schema, length-cap, and extra-field tests pass.
- Bound math matches a known-answer table.
- A candidate with one benign false block never reaches "ready for review".
- The injection test passes.

STOP RULES
- No code path may apply a generated rule. A test enforces this.
```

## V6: Compensating rollback and blast radius

```text
PHASE V6: COMPENSATING ROLLBACK AND BLAST RADIUS

Read CLAUDE.md, the v3 rules, and V1 to V2. Gate: V2 offline acceptance is green.

GOAL
Undo what a contained session changed, for tools that can be undone, and show clearly what cannot be undone.

BUILD
1. config/tool_compensations.yaml: for each state-changing tool, its inverse tool, the argument mapping, and the pre-state reference the checkpoint must capture. A tool with no inverse is IRREVERSIBLE and gives a reason, for example "email already sent".
2. Checkpoints. Before each state-changing call, record a pre-state reference (row ID and version hash) in the ledger, linked to the lineage span.
3. Rollback. rollback_session walks the session's checkpoints backward. Each compensating call is authorized through the gate like any other containment call. A failed compensation marks the session PARTIAL and records the failure. Never retry in a loop.
4. Blast radius DAG. Built from lineage edges and tool-call records for one trace. Each node is a call with a state: REVERSED, IRREVERSIBLE, FAILED, or NOT_APPLICABLE. Expose it at GET /traces/{id}/blast-radius.
5. Tests against the sandbox database: a write is undone and the row returns to its pre-state; an irreversible call stays marked; a failed compensation marks the session PARTIAL.

ACCEPTANCE
- Rollback tests pass, with before and after row hashes in the evidence.
- The DAG shows every call in the trace, including the irreversible ones.
- A test checks the call log: no compensation runs without a gate decision.

STOP RULES
- Do not describe rollback as undoing external side effects. State the limit in the docs.
```

## V7: UI upgrades

```text
PHASE V7: UI UPGRADES

Read CLAUDE.md, the v3 rules, and the V1 to V6 endpoints. Gate: each endpoint this UI reads exists and has tests.

GOAL
Show the immune loop on one screen, with every number and label coming from the API.

BUILD
1. Taint graph. Replace the static agent cards with a graph built from the lineage endpoint. Nodes are agents. Edges are delegations, coloured by taint. Animate packets from the event stream. Support prefers-reduced-motion by turning off animation and keeping the colours.
2. Containment pill. Four states from the containment endpoint: NORMAL, SCOPED DOWNGRADE, MIRAGE HONEYPOT, and QUARANTINED + ROLLED BACK. Each state links to its ledger entry.
3. Antibody card. Shows observed false blocks, the bound, and recall from the backtest JSON, with a "Submit for approval" button. No hard-coded text.
4. Blast radius view. Renders the V6 DAG, with each node's state.
5. Architecture explorer. Built from a JSON file generated from the diagram data in docs/V3_SPEC.md. Each step links to its evidence file.
6. Remove any leftover fixed metric text. Keep the rule from the previous UI phase: every number has a definition in docs/UI_METRICS.md or a tooltip.

ACCEPTANCE
- Vitest: pill mapping for all four states, graph rendering from a fixture, and antibody card text built from a fixture with a bound.
- A test scans src/ for numeric literals in metric contexts and fails on any it finds.
- Screenshots of all four views at 1440x900 and 390x844, saved to docs/ui/v3/.
- No console errors beyond the expected offline warnings.

STOP RULES
- If an endpoint is missing, show "no data" and log the gap. Never fill in a placeholder number.
```

## V8: Demo scenarios 5 and 6 (real pipeline)

```text
PHASE V8: DEMO SCENARIOS 5 AND 6 (real pipeline)

Read CLAUDE.md, the v3 rules, and the demo docs. Gate: V1 to V6 offline acceptance is green, and V7 screenshots exist.

GOAL
Two demo scenarios that run through the real pipeline against our own sandbox agents. Every number on screen comes from the run's evidence.

SCENARIO 5: CONFUSED DEPUTY
1. CustomerBot reads a support ticket with hidden instructions. It sends a summary to AnalyticsAgent, which asks BillingAgent to export records.
2. Run it through the real monitor and lineage. Record BillingAgent's detector score as the pipeline produces it. Do not set it.
3. Record the lineage taint on the BillingAgent call and ArmorIQ's decision with its trace ID. If the V1 probe failed, label the scenario NOT ENFORCED, and say so in the demo.

SCENARIO 6: LOW-AND-SLOW
1. AnalyticsAgent extracts records in about 2 KB chunks. Run it through the budget ledger and the canary table.
2. Record the chunk of first alert, the tier V2 selects, and the timestamp of any canary hit.
3. Record the time from first alert to antibody candidate, and compare it with the "3 seconds" in the source proposal. Report the measured time. Do not reword the claim to match a target.

SCRIPTS AND EVIDENCE
- scripts/scenario_confused_deputy.py and scripts/scenario_low_and_slow.py, each with an --offline flag.
- evidence/V8/scenario_5.json and scenario_6.json, with timestamps, scores, decisions, and IDs.
- docs/DEMO_SCRIPT.md updated with the steps. Every number in the script is marked "from evidence".

ACCEPTANCE
- Each scenario runs end to end offline.
- Each scenario runs live when credentials exist, or is BLOCKED with the missing value named.
- A test checks that every number in the demo script appears in an evidence file.

STOP RULES
- If a measured value differs from the proposal, keep the measured value and record the difference.
```

## V9: Benchmark and ablations

```text
PHASE V9: BENCHMARK AND ABLATIONS FOR v3 CLAIMS

Read CLAUDE.md, the v3 rules, and I1. Gate: V1 to V5 offline acceptance is green.

GOAL
Show which v3 components help, and by how much, with reproducible numbers. Report negative results.

ABLATIONS
- E0: EWMA and rules only (the current v2 detector).
- E1: E0 plus lineage taint (V1). ArmorIQ decisions are simulated only in the offline harness, and are labelled OFFLINE-HARNESS. They are never used as live evidence.
- E2: E1 plus budgets (V3).
- E3: E2 plus canaries.
- E4: E3 plus output scanning (V4).
- E5: E4 plus antibody candidates (V5), measured by detection on repeats.

SCENARIO FAMILIES (fixtures, fixed seed)
Confused deputy, low-and-slow exfiltration, tool rug-pull, injected tool output, benign delegations, and benign bulk reads.

METRICS
Detection rate with a 95% interval. Events to first alert. False-block rate on benign traffic with a one-sided 95% bound. Containment actions per 1,000 benign events, which measures self-inflicted disruption.

STEPS
1. Build bench/v3/ with the fixture generator and one runner per ablation.
2. Run each ablation twice with the same seed and diff the output.
3. Write evidence/V9/results.json and results.md. A script generates every number in results.md from the JSON.
4. Update docs/INNOVATION.md. Each claim is MEASURED-OFFLINE, MEASURED-LIVE, NEGATIVE, or UNVERIFIED, and links to its row in results.json.

ACCEPTANCE
- Reproducible output.
- Every claim in the innovation register has a status and a link.
- Negative results appear in both the register and the report.

STOP RULES
- Do not tune thresholds to improve any ablation. A change requires a finding for the human.
```

## VF: v3 final gate and judge pack

```text
PHASE VF: v3 FINAL GATE AND JUDGE PACK

Read CLAUDE.md, the v3 rules, docs/brief/REQUIREMENTS.md, and F1. Gate: V0 to V9 are complete, or their open items are recorded.

GOAL
Prove every v3 claim with evidence, or remove it. Keep the brief checks from F1 green.

STEPS
1. Run scripts/check_requirements.py and the innovation-register check. Save both outputs to evidence/VF/.
2. For each row in docs/INNOVATION.md:
   - MEASURED-LIVE or MEASURED-OFFLINE: confirm the evidence file exists and supports the claim.
   - NEGATIVE: keep it in the judge guide's limitations.
   - UNVERIFIED: remove it from the one-pager, or mark it clearly as a roadmap item.
3. Rewrite docs/ONE_PAGER.md with only measured claims, each linked to its evidence, plus a limitations section.
4. Run the secret scan over the repo and the history since the baseline. Report file and line only.
5. Tag v3.0.0-candidate. Tag v3.0.0-submission only if every brief item is PASS and every v3 claim is measured or removed.

ACCEPTANCE
- The judge guide's commands run from a clean clone in a new folder.
- No UI or demo text contains a number absent from the evidence.
- The secret scan is clean.

STOP RULES
- Do not tag a submission while the one-pager contains an UNVERIFIED claim.
```

Start with V0 and the mint probe. Paste the probe result here, and I'll adjust V1 before you run it.  
</USER_REQUEST>
<ADDITIONAL_METADATA>
The current local time is: 2026-10-17T13:19:07+05:30.

The user's current state is as follows:
Active Document: d:\vigil-v2\vigil-v2\docs\DEMO_SCRIPT.md (LANGUAGE_MARKDOWN)
Cursor is on line: 1
Other open documents:
- d:\vigil-v2\vigil-v2\docs\brief\BRIEF_RAW.md (LANGUAGE_MARKDOWN)
- d:\vigil-v2\vigil-v2\backend\app\immune\signatures.py (LANGUAGE_PYTHON)
- d:\vigil-v2\vigil-v2\docs\POLICY_IMMUNE.md (LANGUAGE_MARKDOWN)
- d:\vigil-v2\vigil-v2\backend\app\immune\workflow.py (LANGUAGE_PYTHON)
- d:\vigil-v2\vigil-v2\backend\app\immune\verify.py (LANGUAGE_PYTHON)
No browser pages are currently open.
</ADDITIONAL_METADATA>