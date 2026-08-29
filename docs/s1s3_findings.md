# S1–S3 findings — the PS/PCAP readback probe on EBAZ4203 `17A6`

**Status: S1, S2 and S3 all `PASS` on 2026-08-29, run #3, under owner ruling
`2026-08-29-02` (consumed).** Evidence: `evidence/s1s3_17A6_2026-08-29-02/` — thirteen
stage records, `summary.json` (identity, precheck, setup load, the complete raw UART log
as base64 + sha256 per reply, 1,044 entries), `ymodem.log`, the ruling and its claim.
Two earlier runs under rulings `2026-08-29` and `2026-08-29-01` were refused by the host
instrument before any probe stage (`sb` handed a non-blocking descriptor; a size regex
without the padding U-Boot prints) and are recorded in their own evidence directories;
neither touched a DMA register.

Written in the discipline of `zynq-fabricmap/docs/claimb_findings.md`: observed, inferred
and not-tested are kept apart and labelled.

## 1. The question (`pcap_probe_spec.md` §0)

> On EBAZ4203 `17A6`, can the PS read one known non-blank configuration frame back
> through PCAP into DDR, such that the returned 101 words are bit-exact against an
> expectation pinned before the run?

**Answer: yes.**

## 2. OBSERVED

All values are read from the records; nothing here is computed after the fact except
where said.

### 2.1 Session (§5a)

| step | observed |
|---|---|
| fresh power (§5a.2) | `CTRL 0x4e00e07f`, `INT_STS 0xa802000b` (PCFG_DONE=0), `STATUS 0x40000a30`, `FPGA0_CLK_CTRL 0x00400800`, `plmark` not defined — 5/5 |
| identity (§5a.3), before the load, same session | `boardid=17A6`, `role=verify`, `PSS_IDCODE 0x13722093` |
| setup load (§5a.4–5) | carrier sha256 `8c3369e8…f0b8a` gate; ymodem 2,083,863 bytes, U-Boot reported the same; `PCFG_DONE` cleared to `0xa802000b` then **edge** to `0x50021004` after `fpga loadb`; `plmark=18d053737497ce9c` |
| epoch | 0 throughout; no disruptions; `plmark` identical at all 13 stages |

### 2.2 Gates, at every stage

`CTRL 0x4e00e07f` (mask `0x0C000000` satisfied; full word equals the historical value —
recorded, never required); `MCTRL 0x30800100` (bit 4 `PCAP_LPBK` = 0); `INT_STS[2]
PCFG_DONE` = 1 before every readback; `Data (writethrough) Cache is OFF` after
`dcache off`; sentinel `0xA5A5A5A5` written and read back over all 202 words before every
DMA; every per-command `INT_STS` clear verified as 0 under the clear mask.

### 2.3 The readbacks

| stage | FAR | verdict | frame sha256 vs pinned | sentinel survivors |
|---|---|---|---|---|
| S1 | `0x00000b99` | PASS | `9029c9d0…6beb6f` = pinned | 0 / 202 |
| S2_0 | `0x00000b98` | PASS | `09e6542e…39351c` = pinned | 0 |
| S2_1 | `0x00000b9a` | PASS | `80f782b9…356477` = pinned | 0 |
| S3_0 … S3_9 | `0x00000b99` | PASS ×10 | all `9029c9d0…` = pinned, **all ten identical** | 0 each |

Each stage was an independent transaction: FAR and readback stream re-written, status
cleared and verified, sentinel re-filled, all raw buffers kept (§8 S3).

### 2.4 The DMA, as pinned in §8a — two unidirectional commands

Three commands per stage, `(CMD|1, PCAP, 43, 0)`, `(PCAP, DST|1, 0, 202)`,
`(CMD|1, PCAP, 5, 0)`. Every wait completed on the **first** `INT_STS` poll, ≈0.20 s after
the `DMA_DEST_LEN` write — that is one UART round trip, so the DMA itself completed in
**less than the instrument's resolution**; the derived 1 s timeout was never approached.
`INT_STS` after each readback `0x50033004`: `PCFG_DONE`, `D_P_DONE`, `DMA_DONE` set;
**no bit of the error mask `0x00F4C840` set at any point** (39 waits). The `2'b01` hold tag
was applied to the DDR-side address in every command (§8b) and completion was observed
via `D_P_DONE`.

### 2.5 The pad half (§6a)

`words[0:101]` were **all zero** in every one of the 13 readouts (pad sha256
`0441772f…` = sha256 of 101 zero words). The pad is not adjudicated (§4d) and was not;
this is recorded because §6a called its content unknown.

## 3. INFERRED

- **PCAP readback of a setup-loaded, non-blank frame is bit-exact and repeatable on this
  die, at the requested address, through the §8a sequence — strong.** Three distinct FARs
  returned three distinct pinned frames (S2), and ten independent reads of one FAR were
  identical (S3). This is the capability question answered, and no more than that.
- **H-FIFO is not supported on this part for a 202-word readback — moderate,
  observational.** Under the two-unidirectional order the RxFIFO did not overflow in 13
  transactions (`RX_FIFO_OV` never set). Whether data can enter the FIFO before the read
  DMA is queued remains unstated by any source; what is observed is that, if it does, it
  did not overflow here. The one-bidirectional alternative was never needed and was not
  run.
- **The DMA completes far below UART timing resolution — weak as a number.** ≈0.20 s is
  the poll latency, not the transfer time; C3's throughput figure is neither confirmed nor
  contradicted (U3 stays open).

## 4. NOT TESTED — so that the pass is not read past its scope (`pcap_probe_spec.md` snapshot §9)

- **Non-perturbation.** No observable of the running design was read before/after; S3
  proves repeatability of the read, not that the carrier's state survived it. That is P2
  (`line_plan.md` §4).
- **Post-write readback.** Zero FDRI in every stage; the frames read were placed by the
  setup load. Whether PCAP returns a frame *this line changed* is P1, a separate ruling.
- **Claim B's FARs** (`0x00400A20‥`), blank in the base, were not read; a `BLANK` there
  would say nothing (4,716 FARs share the blank hash).
- **The carrier's internal ICAPE2 engine.** Untouched; W2's verdict stands.
- **Any other die, a Linux control plane, `PCAP_RATE_EN`'s effect on reads (U2),
  C3's throughput preconditions (U3).**
- **Claim B itself.** Zero data points; this probe is not a Claim B experiment.

## 5. What this changes, and what it does not

The instrument-feasibility question the line was opened for is answered positively, with
the sequence AMD's driver uses and without SHUTDOWN/START/RCRC or any startup transition
(§5c). It does **not** authorise P1 or P2 — each needs its own whole-of-probe ruling under
`pcap_probe_spec.md` §2 — and it does not reopen `zynq-fabricmap`'s paused readback leg,
whose stop-loss asked for a new *mechanism*: this result is a new mechanism candidate
(a PS-side read with no shutdown), and it is now the far goal's job (P3, a new
repository) to build the interlock around it.
