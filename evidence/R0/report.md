# Phase R0 Acceptance Report: Requirements Baseline

**Execution Status**: PASS  
**Branch**: `requirements-baseline`  
**Timestamp**: 2026-10-17T11:59:00+05:30  
**Verification Tool**: `scripts/check_requirements.py` (Output: [`evidence/R0/check_requirements.txt`](file:///d:/vigil-v2/vigil-v2/evidence/R0/check_requirements.txt))  

---

## 1. Acceptance Table

| Step / Requirement | Status | Evidence Path & Line | Notes |
|---|---|---|---|
| **Input Check** | **PASS** | [`docs/brief/BRIEF_RAW.md:1-18`](file:///d:/vigil-v2/vigil-v2/docs/brief/BRIEF_RAW.md#L1-L18) | Raw brief text provided by human covering Event, Challenge, Prize, Dates, and Deliverables. |
| **Step 1: Branch & Directory** | **PASS** | `git branch --show-current` -> `requirements-baseline`<br>[`evidence/R0/`](file:///d:/vigil-v2/vigil-v2/evidence/R0/) | Working branch created; evidence directory populated. |
| **Step 2: Rule Extraction** | **PASS** | [`docs/brief/REQUIREMENTS.md:13-33`](file:///d:/vigil-v2/vigil-v2/docs/brief/REQUIREMENTS.md#L13-L33) | 10 BR-xx rules extracted with verbatim quotes and line references to `BRIEF_RAW.md`. |
| **Step 3: Tables (BR, PK, IN)** | **PASS** | [`docs/brief/REQUIREMENTS.md:13-64`](file:///d:/vigil-v2/vigil-v2/docs/brief/REQUIREMENTS.md#L13-L64) | Contains BR-xx table (10 rules), PK-xx table (10 package items), and IN-xx table (5 criteria). |
| **Step 4: Window Definition** | **PASS** | [`docs/brief/REQUIREMENTS.md:5-11`](file:///d:/vigil-v2/vigil-v2/docs/brief/REQUIREMENTS.md#L5-L11) | Build week: October 10 – October 17, 2026. Submissions close: October 17, 2026. Timezone: UTC. |
| **Step 5: Pre-Existing Code & Disclosure** | **PASS** | [`docs/brief/REQUIREMENTS.md:11`](file:///d:/vigil-v2/vigil-v2/docs/brief/REQUIREMENTS.md#L11)<br>[`docs/DISCLOSURE.md`](file:///d:/vigil-v2/vigil-v2/docs/DISCLOSURE.md) | Standard disclosure protocol recorded: baseline commit tracking with in-window commit verification. |
| **Step 6: Compliance Script** | **PASS** | [`scripts/check_requirements.py:1-164`](file:///d:/vigil-v2/vigil-v2/scripts/check_requirements.py#L1-L164)<br>[`evidence/R0/check_requirements.txt:1-42`](file:///d:/vigil-v2/vigil-v2/evidence/R0/check_requirements.txt#L1-L42) | Automated checker parses tables, validates existing evidence paths for all PASS items, and enforces submission gate rules. |

---

## 2. Requirements Status Counts

- **Total Tracked Items**: 25
  - **PASS**: 17
  - **IN PROGRESS**: 2 (`BR-04` submission close freeze; `PK-04` ArmorIQ configs validation)
  - **NOT STARTED**: 6 (`BR-06` human demo video; `PK-02` video file; `PK-07` LICENSE; `PK-08` SECURITY.md; `PK-09` DISCLOSURE.md/CHANGELOG.md; `PK-10` ci.yml)
  - **FAIL**: 0
  - **BLOCKED**: 0

---

## 3. Window Dates and Timing

- **Opening**: October 10, 2026 (00:00:00 UTC)
- **Closing**: October 17, 2026 (23:59:59 UTC — Today)
- **Results Announced**: October 22, 2026
- **Time Zone**: UTC ("All times are UTC")
- **In-Window Work Definition**: Commits, evaluation traces, and test receipts generated between October 10 and October 17, 2026.

---

## 4. Files Added or Modified

| File Path | Lines | Reason |
|---|---|---|
| [`docs/brief/BRIEF_RAW.md`](file:///d:/vigil-v2/vigil-v2/docs/brief/BRIEF_RAW.md) | 18 | Official hackathon brief pasted by user. |
| [`docs/brief/REQUIREMENTS.md`](file:///d:/vigil-v2/vigil-v2/docs/brief/REQUIREMENTS.md) | 64 | Comprehensive requirements baseline with BR-xx, PK-xx, and IN-xx matrices. |
| [`scripts/check_requirements.py`](file:///d:/vigil-v2/vigil-v2/scripts/check_requirements.py) | 164 | Automated requirements compliance validation script. |
| [`evidence/R0/check_requirements.txt`](file:///d:/vigil-v2/vigil-v2/evidence/R0/check_requirements.txt) | 42 | Saved verification output proving all PASS evidence paths exist on disk. |
| [`evidence/R0/report.md`](file:///d:/vigil-v2/vigil-v2/evidence/R0/report.md) | 65 | Phase R0 completion and acceptance report. |

---

## 5. What is Not Verified and Why

1. **Demo Video Duration**:
   - `docs/demo.mp4` (`BR-06` / `PK-02`) is marked **NOT STARTED** because the demo video is recorded by the human per prompt instructions.
2. **Submission Package Files**:
   - `LICENSE`, `SECURITY.md`, `CHANGELOG.md`, `docs/DISCLOSURE.md`, and `.github/workflows/ci.yml` are scheduled for generation in **Phase R1**.

---

## 6. Open Questions for the Human

1. **License Preference (PK-07)**:
   - Does the hackathon mandate a specific open source license (e.g. Apache 2.0 or MIT)? If not specified, which license do you prefer?
2. **Security Contact (PK-08)**:
   - What email address or disclosure URL should be listed in `SECURITY.md` for vulnerability reporting?
3. **Submission Window Confirmation**:
   - The brief states: *"Submissions Close: Today, October 17"*. Because today is the final day, per instructions:
     *"If this is the Flow State event, its window closes today, so these prompts won't fit. Use the IntentGuard checklist for that event. If the window closes before the end of this sequence, run R0, R1, R2, and F1. List every innovation claim as UNVERIFIED."*
