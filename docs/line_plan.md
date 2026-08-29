# Line plan — where the PS line is going, and what the probe is for

Status: **planning note. It records the S0b host-only scope authorisation (§6 D4); it is
not a board claim and not a board authorisation.** Drafted 2026-08-29 after
a cross-repository review of `zynq-ehw`, `zynq-autoehw`, `zynq-fabricmap` and this
repository. **Revision 2 (2026-08-29): incorporates the review at
[`line_plan_review_2026_08_29.md`](line_plan_review_2026_08_29.md) (R1–R6, all accepted)
and records the owner rulings on D1–D4 in §6.** The first revision is `e039ebf`; it is not
the accepted execution order. Nothing here changes the status table in `README.md`, the specification in
`pcap_probe_spec.md`, or the stop-loss in `stop_loss.md`; where this note and those
documents differ, **they govern**. This note exists because the repository's own charter and
the reason it was created had drifted apart, and the runner that S0b must build would have
been shaped by whichever of the two its author had in mind.

The format follows `zynq-ehw/docs/future_plan.md` (claim → non-claims → falsification →
milestones with PASS/HOLD/KILL) and `zynq-autoehw/docs/m2_prework_fuzz_and_map.md`
(settled facts first, decisions for the human listed separately).

## 1. The drift this note corrects

The repository pins itself, in three places, to one instrument-feasibility question:

> does a PS/PCAP-side configuration read return the frame that was requested, on this die?

`pcap_probe_spec.md` §0 adds "not a Claim B experiment", and `stop_loss.md` adds "not a
scientific claim". That narrowing was deliberate and is kept.

The reason this line exists, however, is stated only obliquely (`authority_requirements.md`:
"a future PS-guided architecture"; `pcap_probe_spec.md` §1: "where this line is going").
Stated plainly:

> **Far goal.** A PS-driven evolutionary-hardware loop that can extend and certify its own
> device-local map of **content-bit classes** in regions the vendored database does not
> cover — `zynq-autoehw` M2 prework §5 level 2 ("on-board self-cartography") and level 3
> ("evolution as fuzzing"), with the PS rather than an in-fabric engine as the oracle.

Three consequences that were not written down anywhere, and now are:

1. **The probe does not test what the far goal needs.** Self-cartography needs
   readback **after a write**. The probe is zero-FDRI in every stage (`stop_loss.md`) and
   reads a frame that the canonical setup load put there. A pass at S1–S3 establishes that
   PCAP can return a known frame; it says nothing about returning a frame **this line
   changed**, which is precisely where `zynq-fabricmap` stopped
   (`claimb_findings.md` §3.1: the write lands, the internal readback stages blank). The
   post-write question is a **separate stage with a separate ruling** (§4, P1 below), and
   an S1–S3 pass may not be read as evidence for it.
2. **"Unknown regions" means content-bit classes only.** `zynq-autoehw` M2 prework §1
   and §5, and the K7 line's hold ruling (2026-08-02), reserve routing-class autonomous
   fuzzing for sacrificial silicon. This line inherits that split unchanged: LUT-INIT and
   FF-init classes on the EBAZ boards; **no routing-class write in any stage of this line,
   on any board it owns.** A stage that needs one belongs to the K7 line, which is on hold.
3. **The far goal is a separate repository.** `zynq-ehw/docs/future_plan.md` says future
   research should *prefer* a new repository over appending to a completed ladder, and
   `zynq-autoehw/docs/workflow.md` hard rule 5 isolates source projects from working
   copies (an isolation model, not by itself a rule that every restart creates a
   repository). Applied here as a choice, not a citation: `zynq-psmap` stays an
   **instrument repository**: it delivers the PS-side
   readback capability and its evidence, and hands the far goal a certified path. It does
   not grow an evolution loop.

## 2. Settled facts this plan starts from

Verified in-repo or in a sibling repository at a pinned commit; not re-derived here.

| fact | where |
|---|---|
| Write delivery to the intended FAR is proven, twice, by JTAG (16/16 controls, 101/101 words at `0x00400A20`) | `zynq-fabricmap/docs/claimb_findings.md` §2.1 |
| The blocker on the JTAG/ICAP leg is the **read side**: the carrier's internal readback stages blank; the interlock has only ever succeeded on all-zero content | same, §2.2–§2.3, §3.1 |
| The JTAG read path only returns content after `JSHUTDOWN` — a whole-die transition applied to the design under test; that is why the JTAG gate was rejected | same, §2.6, §3.4 |
| The PCAP/devcfg path was **deliberately never folded in** to that leg and must be argued on its own terms | same, §4 |
| What would reopen Claim B: a **new, reviewed measurement architecture** in which the write-integrity interlock is re-established around an oracle that can observe non-blank content — or a 15/15 same-FAR non-blank fresh-load result | same, §3.5, §7 |
| PCAP readback = two unidirectional DMA commands, non-active endpoint length 0, per AMD `XDcfg_PcapReadback()`; MCTRL loopback gate read-only; no SHUTDOWN/START/RCRC issued | `s0_derived_sequence.md` §8a; `pcap_probe_spec.md` §2a |
| Positive control FAR `0x00000B99`, min Hamming 822, globally unique; 4,716 FARs share the blank hash, so reverse lookup returns a set | `pcap_probe_spec.md` §3 |
| Content-bit classes are the complete, silicon-proven part of the map (the entire `zynq-ehw` ladder and `zynq-xpart` M7.5 ran on LUT-INIT alone); routing is excluded for electrical reasons that database completion does not remove | `zynq-autoehw/docs/m2_prework_fuzz_and_map.md` §1 |
| Two dies available with a verified U-Boot control plane (EBAZ4203 `17A6` is this line's board; `zynq-autoehw` M1 reproduced bit-identically across dies) | `pcap_probe_spec.md` snapshot §11; `zynq-autoehw` `m1-complete` |

## 3. Research claim, non-claims, falsification

Kept in the `zynq-ehw` discipline: one defendable claim, explicit non-claims, a falsifier.

### Claim P (the mechanism this line proposes)

> On this part, a PS-side PCAP readback issued as the **S0-pinned sequence** —
> two unidirectional DMA commands with the non-active endpoint's length 0
> (`s0_derived_sequence.md` §8a), no SHUTDOWN/START/RCRC — can return the **current** content
> of a configuration frame, including content written after the setup load, **without the
> device-wide shutdown transition the JTAG path requires**. Whether the read leaves the
> design under test unperturbed is **not** inferred from that; it is what P2 tests.

This is the "new mechanism" that `claimb_findings.md` §7 asks for: it is a specific,
falsifiable account (the read path differs, not the instrument count) and it predicts
something different (non-blank content returned, no `JSHUTDOWN`).

### Non-claims

- Not Claim B. No map-guided arm, no random-safe control, no score, in any stage here.
- Not a statement about the carrier's internal ICAPE2 engine; W2's verdict stands.
- Not a statement about routing-class bits, about any other die, or about a Linux control
  plane, until a stage says so by name.
- Not an interlock. A readback that works is a precondition for the architecture in §3.5
  of the findings, not that architecture.

### Falsification of Claim P — a stopped line is not a falsified mechanism (R3)

`stop_loss.md` stops the line on **every** S1–S3 failure, including ones that say nothing
about the silicon: an invalid identity, an unmet precondition, a DMA or register error, a
stale completion, a sentinel that never moved. Those are **non-discriminating
observations**: they KILL the P0 line under the stop-loss, and they do **not** establish a
physical negative about Claim P. The two outcomes are recorded under different names and
may not be merged.

Claim P is falsified only by an **attributable payload observation** — one made after the
identity, precondition, completion and attribution gates have all passed and the raw buffer
is sealed:

- S1–S3: the known frame is returned, but not bit-exactly, or not repeatably;
- P1: after a content-bit write whose landing is confirmed terminally by JTAG (R4 order),
  the sealed PCAP buffers hold the **pre-write** content (`PRE_WRITE_CONTENT`), blank, or a
  non-matching frame;
- P1: the PCAP **acquisition** returns the written content only when a shutdown-class
  command is issued — PCAP is then structurally equivalent to the rejected JTAG path and
  P1 ends with KILL, not with a retry that adds the command. (This says nothing about the
  terminal JTAG verifier, which is *expected* to shut down.)
- P2: a causally attributable violation of the pre-registered continuity rule
  (`pcap_probe_spec.md` snapshot §9 names this gap; P2 must fill it or stop).

## 4. Milestone ladder with PASS / HOLD / KILL

The existing probe stages keep their names. New stages are prefixed P. **No stage below
authorises the one after it**; every board stage needs its own whole-of-probe ruling, per
`pcap_probe_spec.md` §2.

### P0 — the readback probe (= the existing S0a / S0b / S1–S3)

Unchanged in content. **S0b is U-Boot-only and implements the current probe contract**
(`pcap_probe_spec.md` §1); its `BoardSession` is not the far goal's control-plane
abstraction and does not wait on D1 (R1). Two additions, both bookkeeping:

- **S0b carries a scope cap, not a line-ratio (R6).** The §8a episode spent eleven review
  rounds on a four-row status table and added 1,191 test lines while the runner stayed at
  zero lines. The cap: every S0b test must map to runner, `BoardSession`, identity, epoch,
  sequencing, fail-closed verdict or authority behaviour that the governing specification
  requires; the status-table / parser / test-aware-mutant guards stay frozen except where a
  wrong technical conclusion or wrong gate state would otherwise be accepted; and **three
  consecutive review deltas with no runner or `BoardSession` behaviour change put S0b on
  HOLD** for an owner scope ruling. The last rule is the one with teeth — the first is a
  judgement and will be argued.
- **The independent review is of completed S0 as a whole, including §8a, and it is the
  gate on the board ruling (R2).** `pcap_probe_spec.md` §2 already says so; both current
  co-authors are ineligible. It is not a residual risk the S1–S3 ruling can carry, and no
  number of tests substitutes for it. With no eligible reviewer available, the line HOLDS
  before board contact.

PASS: S1–S3 all `PASS` under the existing spec.
HOLD: S0b breaches its scope cap; completed S0 has no eligible reviewer.
KILL: any of S1–S3 fails — `stop_loss.md` governs, and the line stays stopped unless a new
mechanism (not a new instrument) is named.

### P1 — post-write readback on a known-answer content-bit change

The one stage the current specification excludes, stated so it cannot be smuggled in as
"just checking" after an S3 pass.

What it does, **in this order and no other (R4)**:

1. fresh load of the canonical carrier; identity;
2. **baseline PCAP read** of the target frame (S1 shape) — the frame is **non-blank in the
   base** (the Claim B FARs are blank in the base and therefore useless here —
   `pcap_probe_spec.md` snapshot §9);
3. **one** pre-registered LUT-INIT known-answer content-bit write;
4. post-write PCAP read 1;
5. post-write PCAP read 2;
6. seal and hash all raw buffers;
7. **terminal** JTAG landing confirmation.

JTAG uses `JSHUTDOWN` (`claimb_findings.md` §2.6). It may not precede or be interleaved
with either post-write PCAP read; it is an after-the-observation verifier of the write, not
part of the mechanism under test. If it cannot be kept terminal and separable, P1 is HELD.

The write goes through whichever write path P1's ruling names — the point of P1 is the
read, and the write must be one already proven to land (`claimb_findings.md` §2.1 proves
the carrier's ICAP write; a PCAP write is a second unknown and is **not** to be combined
with the first).

Non-negotiables inherited: zero routing-class bits; SHUTDOWN/START/RCRC never issued;
sentinel prefill; every raw buffer kept; verdict vocabulary from the snapshot §7 plus one
new verdict `PRE_WRITE_CONTENT` (the read returned the base frame, not the written one —
the single most informative failure for Claim P).

PASS: post-write reads 1 and 2 both bit-exact against the pre-registered expectation,
**and** identical to each other, **and** the terminal JTAG confirms the write landed.
Three conjuncts; two of three is a stop.
HOLD: the write path's ruling is not separable from the read's; JTAG cannot be kept
terminal.
KILL (line): any non-discriminating failure — stop-loss, no physical claim.
KILL (Claim P falsified for this part): `PRE_WRITE_CONTENT` or `BLANK` in sealed buffers
with a JTAG-confirmed landing, or PCAP acquisition succeeding only with a shutdown-class
command.

### P2 — non-perturbation observable

Fills the gap the snapshot §9 names: "S3 proves read repeatability, not non-perturbation".
A pre-registered observable of the running design (a counter the carrier already exposes
over AXI, a mailbox checksum, or a phenotype score from the M1 shell) is read before and
after N PCAP readbacks. **The rule is an observable-specific continuity invariant, not
literal equality (R5)**: a live counter must *advance* within a pinned envelope; a stable
checksum must remain equal. N, the tolerances, and a **matched no-read baseline/control**
are fixed before the run. This is where `zynq-autoehw`'s M1 island/mailbox shell is likely
reused; it is also the first stage where the far goal's authority model (§6 D1) matters,
because the observable may need the PS to run more than U-Boot.

PASS: the continuity rule holds across N reads and the no-read control behaves the same.
HOLD: the baseline is unstable or non-discriminating.
KILL: a causally attributable continuity violation with no shutdown-class command issued —
PCAP readback is then not usable as an in-loop oracle on this part.

### P3 — hand-off: interlock architecture (the far goal's first milestone, **new repository**)

`claimb_findings.md` §3.5: links 2–3 (bytes handed to the guard == bytes read back) may be
replaced by a stronger oracle only via a new, reviewed architecture that **re-establishes**
the interlock. With P0–P2 passed, the PS is that oracle candidate. P3 is out of scope for
`zynq-psmap`; this repository's deliverable to P3 is the evidence bundle of P0–P2 and the
pinned sequence. Nothing in P3 may modify this repository except to add a pointer.

## 5. Risk register

- **PCAP readback is a whole-frame DMA, and the design lives in the fabric being read.**
  Mitigated by P2 being a stage rather than an assumption. Not mitigated by anything else.
- **The 4,716-blank-FAR ambiguity** makes a `BLANK` verdict uninformative about address.
  P1 therefore targets a non-blank base frame, never a Claim B FAR.
- **DEVCFG wedge.** Known from the bring-up line: a bad load leaves DEVCFG stuck and only a
  power cycle recovers. P1 issues exactly one write and it is a known-answer; the
  known-answer regression runs before anyone suspects damage (snapshot §11).
- **Proportionality.** The instrument-adding failure mode is the reason this line has a
  stop-loss; the review-adding failure mode is the reason §8a's PASS was withdrawn. The
  cap in P0 is the only structural defence proposed; it is a rule, not a guard, on purpose
  (the status-table guards are frozen).
- **Authority model drift.** `authority_requirements.md` asserts the far goal needs Linux.
  That assertion is unjustified in the repository (§6 D1) — but S0b does not touch it: the
  probe's `BoardSession` is U-Boot-only by specification, so nothing is baked in by
  building it. The risk becomes live at P2/P3, which is when D1 is taken.

## 6. Decisions for the human — rulings recorded 2026-08-29

The owner accepted the review's recommended rulings (§3 of the review) as a set.

| decision | ruling | effect now |
|---|---|---|
| **D1** — control plane of the far goal (standalone vs Linux vs U-Boot-only) | **DEFERRED to P2/P3.** The author's recommendation of standalone (uses the `XDcfg` driver that settled §8a; no `clk_disable_unused()` FCLK trap, no `fpgautil` DEVCFG wedge; no Linux identity/epoch) stands as a recommendation only. `authority_requirements.md` and `README.md` are **not** rewritten now. | does not block S0b |
| **D2** — independent review | **Third-party review of completed S0 as a whole, including §8a, is required before any board ruling.** No eligible reviewer → HOLD before board contact. There is no option in which more test lines close it. | gate between S0b and the S1–S3 ruling |
| **D3** — ratify §1's three consequences (P1 is a separate ruling; content-bit only; far goal in a new repository) | **RATIFIED**, with the source wording narrowed as in §1.3. | plan boundary accepted |
| **D4** — S0b | **AUTHORISED, host-only**, under the current U-Boot-only specification and the P0 scope cap. **No board authority.** | S0b may start |

## 7. Immediate next step

None on the board. Order: **S0b (host-only, U-Boot-only, under D4) → eligible third-party
review of completed S0 (D2) → application for the existing S1–S3 whole-of-probe board
ruling.** D1 waits for P2/P3. The status table is unchanged by this document: S0 is not
complete, S0b is authorised but not started, S1–S3 are not authorised, and the board has
not been touched.

**Dated note, 2026-08-29 (evening):** S1–S3 **PASS** on `17A6` under ruling `2026-08-29-02`,
run #3 (`docs/s1s3_findings.md`). P0 is PASS. P1 and P2 each still need their own ruling.

**Dated note, 2026-08-29 (later the same day):** S0b was written (`4e2c032`) and
cross-reviewed (`bde1d07`); the D2 third-party review was performed by an LLM (Gemini 3.1
Pro) per the owner's ruling that the third party may be an LLM, and passed at `7a5b990`
(`d2_review_result.md`). **S0 is therefore complete.** The next step in the order above is
the owner's decision on the S1–S3 whole-of-probe board ruling; nothing in this note takes
it.
