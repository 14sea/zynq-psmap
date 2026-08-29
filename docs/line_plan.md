# Line plan — where the PS line is going, and what the probe is for

Status: **planning note, not a board claim, not an authorisation.** Drafted 2026-08-29 after
a cross-repository review of `zynq-ehw`, `zynq-autoehw`, `zynq-fabricmap` and this
repository. Nothing here changes the status table in `README.md`, the specification in
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
3. **The far goal is a separate repository.** `zynq-ehw/docs/future_plan.md` rules that a
   restart is a new repository and `zynq-autoehw/docs/workflow.md` §5 makes isolation
   absolute. `zynq-psmap` stays an **instrument repository**: it delivers the PS-side
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

> On this part, a PS-side PCAP readback can return the **current** content of a configuration
> frame — including content written after the setup load — **without a device-wide
> shutdown transition**, and therefore without perturbing the design under test in the way
> the JTAG path does.

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

### Falsification of Claim P

Any one of these, observed under the pinned verdict vocabulary, falsifies it:

- S1–S3: the known frame is not returned bit-exactly and repeatably (the existing probe);
- P1: after a content-bit write that JTAG confirms landed, PCAP returns the **pre-write**
  content, blank, or a non-matching frame, on a fresh-load no-op where the write is a
  known-answer LUT-INIT change;
- P1: the readback only succeeds if a shutdown-class command is issued — that would make
  PCAP structurally equivalent to the rejected JTAG path and P1 ends with KILL, not with a
  retry that adds the command;
- P2: the design under test does not survive a readback unchanged, by a pre-registered
  observable (`pcap_probe_spec.md` snapshot §9 names this gap; P2 must fill it or stop).

## 4. Milestone ladder with PASS / HOLD / KILL

The existing probe stages keep their names. New stages are prefixed P. **No stage below
authorises the one after it**; every board stage needs its own whole-of-probe ruling, per
`pcap_probe_spec.md` §2.

### P0 — the readback probe (= the existing S0a / S0b / S1–S3)

Unchanged in content. Two additions, both bookkeeping:

- **S0b carries a proportionality cap.** The §8a episode spent eleven review rounds on a
  four-row status table and added 1,191 test lines while the runner stayed at zero lines.
  S0b's test file may not exceed **2×** the runner's line count, and a review round that
  changes no runner or `BoardSession` behaviour counts against a budget of **three** such
  rounds before the drop is HELD for a scope ruling.
- **Independent review of §8a is a decision, not a task** (see §6 D2). It is not something
  either co-author can complete.

PASS: S1–S3 all `PASS` under the existing spec.
HOLD: S0b exceeds its cap; §8a review model undecided.
KILL: any of S1–S3 fails — `stop_loss.md` governs, and the line stays stopped unless a new
mechanism (not a new instrument) is named.

### P1 — post-write readback on a known-answer content-bit change

The one stage the current specification excludes, stated so it cannot be smuggled in as
"just checking" after an S3 pass.

What it does: fresh load of the canonical carrier; identity; JTAG-independent readback of a
target frame (S1 shape); **one** content-bit write of a pre-registered LUT-INIT
known-answer candidate into a frame that is **non-blank in the base** (the Claim B FARs are
blank in the base and are therefore useless here — `pcap_probe_spec.md` snapshot §9);
PCAP readback of the same frame; compare to the pre-computed post-write expectation. The
write goes through whichever write path P1's ruling names — the point of P1 is the read,
and the write must be one already proven to land (`claimb_findings.md` §2.1 proves the
carrier's ICAP write; a PCAP write is a second unknown and is **not** to be combined with
the first).

Non-negotiables inherited: zero routing-class bits; SHUTDOWN/START/RCRC never issued;
sentinel prefill; every raw buffer kept; verdict vocabulary from the snapshot §7 plus one
new verdict `PRE_WRITE_CONTENT` (the read returned the base frame, not the written one —
the single most informative failure for Claim P).

PASS: post-write frame bit-exact against the pre-registered expectation, **and** a
same-session second read identical, **and** JTAG (the proven instrument) confirms the
write landed. Three conjuncts; two of three is a stop.
HOLD: the write path's ruling is not separable from the read's.
KILL: `PRE_WRITE_CONTENT` or `BLANK` after a JTAG-confirmed landing (Claim P falsified for
this part), or success only with a shutdown-class command.

### P2 — non-perturbation observable

Fills the gap the snapshot §9 names: "S3 proves read repeatability, not non-perturbation".
A pre-registered observable of the running design (a counter the carrier already exposes
over AXI, a mailbox checksum, or a phenotype score from the M1 shell) is read before and
after N PCAP readbacks. This is where `zynq-autoehw`'s M1 island/mailbox shell is likely
reused; it is also the first stage where the far goal's authority model (§6 D1) matters,
because the observable may need the PS to run more than U-Boot.

PASS: observable unchanged across N reads, N pre-registered.
KILL: observable perturbed by a readback with no shutdown-class command issued — PCAP
readback is then not usable as an in-loop oracle on this part.

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
  That assertion is unjustified in the repository (§6 D1). Building `BoardSession` for
  Linux before D1 is decided would bake the assertion in.

## 6. Decisions for the human — none of these can be taken by an author

**D1 — control plane of the far goal: standalone (bare-metal) vs Linux vs U-Boot-only.**
Recommendation: **standalone**. It uses the `XDcfg` driver whose source settled §8a, has
no `clk_disable_unused()` FCLK trap and no `fpgautil` DEVCFG wedge (both recorded in the
bring-up line), and needs no Linux identity/epoch. If adopted, `authority_requirements.md`
§"The required split" is rewritten as *U-Boot identity + standalone-application identity*,
and the repository-split rationale in `README.md` is restated (the split still holds — the
authority model still differs from the Claim B preregistration — but the reason is no
longer "Linux"). This must be decided **before S0b**, which builds the session object.

**D2 — the §8a independent review.** Both co-authors are disqualified. Options: (a) a third
reviewer; (b) accept "technically resolved; independently reviewed: NO" as a permanent
label and let the S1–S3 ruling carry the residual risk explicitly. There is no option (c)
in which more test lines close it.

**D3 — ratify §1's three consequences** (P1 is a separate ruling; content-bit only; the far
goal is a new repository). If any is rejected this note is withdrawn, not amended.

**D4 — authorise S0b** under the P0 cap, after D1.

## 7. Immediate next step

None on the board. In order: D1 → D2 → D3 → S0b under D4. This note does not authorise
S0b, and the status table is unchanged: S0 is not complete, S0b is not started, S1–S3 are
not authorised, and the board has not been touched.
