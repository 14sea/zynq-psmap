# P2 — non-perturbation of a running design by PS/PCAP reads (and one write): specification

> **HOST-SIDE SPECIFICATION. No board run is authorised by this document.** P2 needs its
> own whole-of-probe ruling with the text `whole-of-probe P2` (`pcap_probe_spec.md` §2;
> owner rulings 2026-08-29). Neither the S1–S3 nor the P1 ruling extends to it.

Status: drafted 2026-08-29 after P1 passed (`p1_findings.md`). Implements `line_plan.md`
§4 P2 as amended by review R5 ("an observable-specific continuity rule, not literal
equality … a stable checksum remains equal … a matched no-read baseline/control").
**Owner review PASS (host-only) on 2026-08-29 at `5c4f5f1`.** Scope as ruled: a P2 PASS
may claim only that, on this `17A6` carrier, under the specified PCAP operations, no state
perturbation was observed in the eight pinned registers — not a general "the design kept
computing" proof (that is P2b). Board run still needs its own `whole-of-probe P2` ruling
and a fresh power cycle.

## 0. The one question

> While the canonical carrier is configured and running on `17A6`, do PS/PCAP readbacks of
> a frame that holds **live carrier logic** leave the carrier's observable state unchanged —
> and does one certified content-bit write into the isolated target column leave it
> unchanged too?

`s1s3_findings.md` §4 and `p1_findings.md` §4 both list this as NOT TESTED: S3 proved read
repeatability, P1 proved write-then-read, neither had an observable of the design. This
closes that gap for the **stable-state** class of observable. It does not test a running
computation (§8).

## 1. What P2 inherits unchanged

Session (§5a: power cycle, precheck, identity before the load, SHA-gated setup load with the
`PCFG_DONE` edge, `plmark`), the read plan (`pcap_probe_plan.build_plan`) and executor, the
write plan for pattern A (`pcap_write_plan`, P1-proven), `CTRL` read-never-written, the
ruling model (one ruling, claimed before the port opens, consumed by any outcome, no retry),
the stop-loss, and the R3 separation of non-discriminating stops from verdicts.

## 2. The observable — pinned, and why these words

The carrier (`zynq-fabricmap/vivado/carrier/carrier_axil.v`) exposes, over AXI-Lite at
`0x43C00000`, exactly these readable registers:

| word | address | content | rule |
|---|---|---|---|
| `STATUS` | `0x43C02004` | busy, fault, configuration_valid, scorer bits, recovery_required, expect_env, rb_frame_ready, env_committed, rb_frames_ok, rb_latency; **bits 31:27 hard zero** | liveness: bits 31:27 = 0 **and** word ≠ 0 (`recovery_required` is set out of reset, so a live carrier never reads 0) |
| `FAULT` | `0x43C02008` | fault code, bits 3:0 | — |
| `SCORE0‥5` | `0x43C02010‥24` | six per-LUT match counters | — |

**O = these 8 words, read in this order, one `md.l … 1` each.** No other address is read:
the carrier's read decoder answers **SLVERR** to anything else in its window
(`carrier_axil.v` lines 249/256), and on this board's U-Boot an AXI error is a data abort
that **resets the board** — observed in `zynq-fabricmap` `evidence/isolate_2026_08_12b`
(a `md 0x43c02004` on an unconfigured PL returned the SPL banner). Hence:

- **AXI is read only after the setup load's `PCFG_DONE` edge and `plmark`** — never on an
  empty PL — and only at the eight pinned addresses (`p2_observe.ALLOWED_AXI`).
- **FCLK0 must be running.** On `17A6` it is 50 MHz at POR (`board_roles.md`), the precheck
  pins `FPGA0_CLK_CTRL = 0x00400800` (fresh-power value), and U-Boot leaves the FCLKs
  enabled; the known hard hang is Linux's `clk_disable_unused()`, not U-Boot. P2 additionally
  decodes FCLK0 from the PLL/divisor registers read-only (`p2_observe.fclk0_mhz`) and stops
  if it is not 50 ± 0.5 MHz.

**Expected fresh-load O** (recorded on `17A6` in fabricmap's evidence, first sample after a
fresh load): `STATUS = 0x00000080` (`recovery_required` only), `FAULT = 0`, `SCORE = 0 ×6`.
This is an *expectation*, recorded as observation; the P2 invariant is **equality with the
run's own baseline O₀**, not with this constant (§5e's rule: historical values inform, they
do not gate — except liveness).

## 3. The continuity rule (R5)

The observable is of the **stable-state** class: nothing in O is expected to advance while
the carrier idles (no transaction has been begun, the scorer is not armed). The
pre-registered rule is therefore **exact equality of all 8 words with O₀**, sampled after
every read, plus liveness on every sample. A counter-class observable (advancing within an
envelope) is not available on this carrier; §8 names where it is.

**The matched control** is the same 8-word sample taken after the same wall time with **no
PCAP activity**. It runs **before** the treatment arm: if O drifts on its own, the
observable is non-discriminating and the run is `HOLD` before any PCAP read happens
(R5: "an unstable or non-discriminating baseline is HOLD").

## 4. Every device operation, in order, and what is NOT done

| step | stage | operation | gate |
|---|---|---|---|
| 0 | session | as S1–S3/P1 | as before |
| 1 | `P2_0_fclk` | decode FCLK0 from `IO_PLL_CTRL`/`ARM_PLL_CTRL`/`DDR_PLL_CTRL`/`FPGA0_CLK_CTRL` (read-only) | 50 ± 0.5 MHz or PRECONDITION |
| 2 | `P2_1_baseline` | O₀ | liveness |
| 3 | `P2_2_control` | host waits **T_ctrl** seconds sending nothing; then O₁ | O₁ = O₀ or **HOLD** (`CONTROL_UNSTABLE`) |
| 4 | `P2_3_reads` | **N = 10** PCAP reads of **`0x00000B99`** (the live-logic INT frame S1–S3 used; PASS expected each time), **O sampled after each read** (Oᵣ₁‥Oᵣ₁₀) | every read `PASS`; every Oᵣ = O₀, else `CONTINUITY_VIOLATION` |
| 5 | `P2_4_post` | host waits T_ctrl again; O₂ | O₂ = O₀ |
| 6 | `P2_5_write` | **one** PCAP write of pattern **A** into `0x00400A20` (P1's stream and DMA, verbatim); O sampled after it (O_w) | write clean; O_w = O₀ |
| 7 | `P2_6_readback` | one PCAP read of `0x00400A20`, expected A; O after (O_w′) | `PASS`; O_w′ = O₀ |

T_ctrl is **measured**, not chosen: the runner times step 4's ten read-plus-sample blocks
(≈ 10 × ~3 s of UART-paced commands on this board) and uses that measured span for step 5;
for step 3 it uses the pinned pre-run estimate of **30 s** (recorded as `derived`) so that
the control precedes the treatment.

**NOT performed:** no `FDRI` except step 6's single P1-proven write (zero routing bits, same
guards); no write to any AXI address (the carrier's `CTRL` at `0x43C02000` is never
touched — no `begin_txn`, no `arm`); no JTAG and therefore no `JSHUTDOWN`/`JSTART`; no
SHUTDOWN/START/GRESTORE; no devcfg `CTRL` write; no PL clock change. AXI registers are read
with `md.l` — the D-cache state is whatever the read plan left (`dcache off` from the first
read onward); the AXI window is not cached memory, and the baseline/control samples are
taken before any `dcache off` so the comparison spans both states by construction.

## 5. Verdicts

| verdict | meaning | class |
|---|---|---|
| `PASS` | every read `PASS`, write clean, **all 14 O samples equal O₀**, liveness on all | — |
| `CONTROL_UNSTABLE` | O₁ ≠ O₀ before any PCAP activity | **HOLD** (observable non-discriminating; R5) |
| `CONTINUITY_VIOLATION` | some O after PCAP activity ≠ O₀ while O₁ = O₀ | stop; **attributable** only if the change first appears at a PCAP step and O₁ was stable (recorded per sample) |
| `AXI_NOT_ALIVE` | STATUS bits 31:27 ≠ 0 or STATUS = 0 | PRECONDITION (non-discriminating) |
| read/write stops | as P0/P1 vocabulary | as P0/P1 |

A `CONTINUITY_VIOLATION` names **which words changed and at which step**; the stage
records keep all 8 words of every sample so the diff is in the evidence, not in prose.

## 6. What a PASS would and would not establish

**Would:** on this die, over U-Boot, ten PCAP readbacks of a frame holding live carrier
logic, and one certified content-bit write into the isolated column, left every readable
register of the carrier — including its fault code, its write-integrity interlock bit and
its six scorer counters — exactly as they were, while the same registers were shown stable
without PCAP activity over the same span.

**Would not:** that a *running computation* survives (the carrier idles in P2; nothing is
clocking through the scorer); anything about flip-flop state that no register exposes;
anything about a JTAG transition (none is performed); Claim B; other dies; Linux. The
observable's coverage is exactly the eight words, and the spec says so.

## 7. Evidence

Per step a record as §10 (identity, epoch, plmark, all 8 words of every O sample with the
step they follow, the FCLK0 decode with the raw PLL/divisor words, every read's frame hash
and sentinel count, the write's stream and wait); `summary.json` with the full raw UART
log; the ruling and its claim.

## 8. The stronger form this does not attempt — named, for the plan

A **counter-class** observable — a design that is *computing* while PCAP reads it, with a
heartbeat or evaluation counter that must advance within a pinned envelope — is what the
far goal ultimately needs (the PS reading configuration while a NEORV32 evolution loop
runs). `zynq-autoehw`'s M1 shell exposes exactly that (paged mailbox at `0x41200000`,
heartbeat `0x030001`, `m1_board_handoff.md`), but its bitstream is an uncommitted build
artifact and its frames are not the carrier's. That is **P2b**: a separate specification,
a separate setup load, a separate ruling. P2 (this document) is P2a.
