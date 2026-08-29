# P1 review — result

**Provisional.** The intended reviewer (Gemini, per owner preference) was unavailable on 2026-08-29: `gemini-3.1-pro-high` and `gemini-3.6-flash-high` both returned `Individual quota reached … Resets in 166h` (≈ 2026-09-05). The only non-co-author model with quota was **GPT-OSS 120B (medium)** via `agy --sandbox`; its text is below, **verbatim and unedited**. Whether it satisfies the owner's HOLD gates is the owner's decision; the authors' assessment follows in its own section and does not modify the reviewer text.

---

## Round 1 — GPT-OSS 120B, against HEAD `c78b218` (verbatim)

We need to wait for test completion.We need to wait for test completion.We will set a timer to check later? Actually system sends notification when task finishes. We can proceed to other analysis.<|start|>assistant<|channel|>commentary to=functions.view_file<|message|>{"AbsolutePath": "/home/test/zynq_psmap/scripts/p1_runner.py", "toolAction": "Viewing p1 runner", "toolSummary": "File view"}<|call|>
**Verdict (host‑only P1)** – **PASS**  
All host‑only checks (write‑stream guards, DMA tuple, CRC‑register omission, terminal JTAG) succeed, and the unit‑test suite reports **OK** with no failures (see the “Ran 293 tests … OK” output from `python3 -m unittest discover -s tests`).  

---

## Gate 1 – Two successive writes A→B  

| Requirement | Evidence |
|-------------|----------|
| All 49 LUT‑INIT bits for this carrier lie in word 51 of frames `0x00400A20‥0x00400A23` and those frames are **all‑zero** in the base bitstream. | `docs/p1_spec.md` §3, lines 46‑55: “the only certified LUT‑INIT addresses … are in word 51 … **all‑zero in the carrier**”. |
| No other certified LUT‑INIT address exists on this die. | Same passage (lines 66‑71) notes “no other LUT‑INIT address … is certified”. |
| The base frames are indeed blank. | `tests/test_p1.py` line 95 (`self.assertTrue(all(w == 0 for w in BASE[wp.TARGET_FAR]))`). |
| The write‑stream validator refuses any change outside the certified mask and only allows the two pinned patterns A and B. | `scripts/pcap_write_plan.py` lines 104‑108 (`target_frame`) and lines 195‑199 (`_check_frames`). |
| The **A→B** write (step 5) is therefore the **only discriminating step** – the read after step 5 can only return the B pattern, a blank, or an error. | `p1_spec.md` §3, lines 85‑89 describe step 5 as “the discriminating one”. |
| Keeping the blank→A step (step 1) **adds risk** because a read after step 1 cannot distinguish a true blank from a mis‑addressed write to any of the 4 716 blank FARs. | `tests/test_p1.py` line 225‑229 (`test_baseline_not_blank_stops_before_any_write`) and the test‑run log (`STOP BLANK: the DMA replaced the destination with zeros … indistinguishable`). |

**Gate 1 decision – ACCEPT** (the amendment to use two successive writes is sound). The step 5 (A→B) is unambiguous; however, retaining step 1 (blank→A) introduces a non‑discriminating risk that must be documented (see the “STOP BLANK” refusal in the test log).

---

## Gate 2 – No CRC‑register write  

| Requirement | Evidence |
|-------------|----------|
| UG470 v1.17 explicitly states that a CRC‑register write **performs** a CRC check and a mismatch pulls `INIT_B` low, aborting configuration. | `docs/p1_spec.md` §4b, lines 119‑130 quote UG470: “Writes to this register are used to perform a CRC check … If the value written matches the current calculated CRC, the CRC_ERROR flag is cleared … If it does **not** match … the device pulls INIT_B Low and aborts”. |
| The carrier header (decoded from `carrier.bit`) has `COR1 = 0` and `RBCRC_SW = 0`, i.e. read‑back CRC is disabled. | `tests/test_p1.py` lines 310‑313 (`CarrierHeader.test_cor1_and_rbcrc_sw_are_zero`). |
| The terminal JTAG verifier requires `STAT.CRC_ERROR = 0`; the test suite checks this explicitly. | `tests/test_p1.py` lines 263‑271 (`test_jtag_verdict_requires_crc_error_clear`). The passing case (`config_status "0x00000000"`) yields “PASS”. |
| The residual running‑CRC value after the 231‑word stream is **never used** by any later step (no `START` or further CRC check). | The specification (lines 154‑156) notes the residual is “named here rather than argued away”. No code reads it, and the JTAG check only looks at `STAT.CRC_ERROR`. |

**Gate 2 decision – CHECKABLE WARRANT**. The three sources (UG470 text, carrier header, JTAG status) together **verify** that omitting the CRC‑register write does **not** leave a visible error state. The only remaining un‑covered effect is the leftover CRC value that persists in the register but is never consulted; this does not affect the host‑only verdict.

---

## Other defects (most severe first)

| # | Defect (brief) | File:line(s) | Minimal fix |
|---|----------------|--------------|-------------|
| 1 | **Step 1 ambiguity (blank→A) can cause a *STOP BLANK* failure**, because a read of a blank frame is indistinguishable from a mis‑addressed write to any of the 4 716 blank FARs. | `tests/test_p1.py` line 225‑229 (`test_baseline_not_blank_stops_before_any_write`) and test‑run log (`STOP BLANK`). | Either **drop step 1** (write directly A→B) or add a *pre‑write* verification that the target FAR is non‑blank before proceeding. |
| 2 | **Missing /dev/ebaz‑uart handling** – the runner attempts to stat `/dev/ebaz-uart` (REFUSED in test log) even though host‑only P1 must not touch serial devices. | Test log (`REFUSED: cannot stat /dev/ebaz-uart`). | Guard the UART‑stat call with a `try/except` that skips it when the device is absent, or remove the check entirely. |
| 3 | **Residual temporary files (`/tmp/...` evidence) are never overwritten**, causing “REFUSED: evidence is never replaced”. | Test log (`REFUSED: /tmp/tmpcjtz_onf exists`). | Ensure the runner clears or overwrites temporary evidence directories before each run. |
| 4 | **Ruling file consumption errors** – attempts to read a non‑existent ruling cause REFUSED messages. | Test log (`REFUSED: no readable ruling …`). | Validate ruling‑path existence early and produce a clear “HOLD” rather than a REFUSED error; or require the ruling file to be present before launching P1. |
| 5 | **Dependency on external `lrzsz` (`sb`) utility** – test log shows REFUSED when missing. | Test log (`REFUSED: 'sb' (lrzsz) is not installed`). | Remove optional external‑tool requirement for host‑only mode or stub it out. |
| 6 | **`PCAP_RATE_EN` bit is never examined** – the spec states it stays as‑found, but no test verifies it isn’t inadvertently altered. | No explicit test; described in `p1_spec.md` line 34‑35. | Add a guard in the write‑plan that reads `PCAP_RATE_EN` before the write and asserts it is unchanged after. |
| 7 | **Pad‑frame handling relies on a strict base copy**, but no explicit test for pad‑frame corruption on DMA errors. | `pcap_write_plan.py` line 205‑206 (`_check_frames` verifies pad match). | Add a dedicated unit test that mutates the pad frame and expects a failure, confirming the guard is effective. |

---

## Commands actually run (and what they showed)

| Command | Working directory | Outcome |
|---------|-------------------|----------|
| `python3 -m unittest discover -s tests` | `/home/test/zynq_psmap` | Executed 293 tests; all **PASS** (final line of log: `OK`). The log also listed several *REFUSED* messages (UART stat, missing ruling, missing `lrzsz`, evidence file, and a *STOP BLANK* case) but they did not cause test failures. |
| `view_file` on `docs/p1_spec.md`, `docs/line_plan.md`, `scripts/pcap_write_plan.py`, `tests/test_p1.py` | – | Provided the textual evidence cited above (certified LUT‑INIT locations, amendment description, write‑stream guards, and test assertions). |
| `view_file` on `scripts/p1_runner.py` (not shown here) – not required for the verdict as the runner’s logic is exercised by the unit tests. | – | – |

---

**Summary** – The host‑only P1 implementation satisfies all required guarantees: the two‑write amendment (A→B) is sound, the omission of the CRC‑register write is fully justified, and the test suite passes. The only material risk is the retained blank→A step, which can cause an ambiguous *STOP BLANK*; removing or protecting this step would improve robustness. All other REFUSED messages stem from peripheral concerns (UART, missing rulings, external utilities) that can be safely ignored or handled more gracefully in a pure host‑only context.

---

## Authors' assessment of round 1 (not reviewer text)

- The verdict (PASS; GATE 1 ACCEPT; GATE 2 CHECKABLE WARRANT) is recorded but **not relied on**: the review cites the specification and test names as its evidence, and explicitly credits the passing test run, which the brief told it not to do. It does not reach the D2 bar (`d2_review_result.md`), where the reviewer produced its own mechanism claim and then withdrew it against sources.
- Its "other defects" 1–5 misread **expected** output: the `REFUSED …` and `STOP BLANK` lines it saw are printed by tests that deliberately exercise those refusals (`test_baseline_not_blank_stops_before_any_write`, the ruling/`sb`/evidence-directory refusal tests). Defect 7 is already covered (`_mutant(... pad not base)`).
- Defect 6 is genuine and cheap: `CTRL` — including `PCAP_RATE_EN` — was stated to be "as found" across the write but not asserted. Fixed in the commit that adds this file: the write plan reads `CTRL` before the stream and after the completion wait, and the runner stops (`PRECONDITION`, non-discriminating) if the two differ.
- **Status unchanged:** P1 stays HOLD under the owner's cross-review; the two gates await an independent ruling that the owner accepts (Gemini after its quota resets, or another reviewer the owner names). No ruling, no board contact.
