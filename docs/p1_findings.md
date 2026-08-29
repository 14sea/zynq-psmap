# P1 findings — post-write PCAP readback of a known-answer content-bit change on `17A6`

**Status: P1 `PASS` on 2026-08-29, run #1, under owner ruling `whole-of-probe P1`
(`2026-08-29-01`, consumed).** Evidence: `evidence/p1_17A6_2026-08-29-01/` — seven stage
records, `sealed.json` (their hashes, written before the terminal JTAG), `jtag.json` +
`jtag.tcl` (the R4 probe's own record and script, openocd transcript included),
`summary.json` (identity, precheck, setup load, the complete raw UART log: 894 replies),
`ymodem.log`, the ruling and its claim. One run, one ruling, no retry.

Written in the discipline of `s1s3_findings.md`: observed, inferred and not-tested kept
apart. **Scope, ruled by the owner before the run:** `17A6`, U-Boot control plane, the
specified blank→A→B content-bit path. Nothing here extends to P2, Claim B, another die, or
Linux.

## 1. The question (`p1_spec.md` §0)

> After the PS writes a pre-registered content-bit change into one configuration frame
> through PCAP, does a PS/PCAP readback of that frame return the **changed** content
> bit-exactly — and never the pre-write content?

**Answer: yes, twice (blank→A and A→B), confirmed by an independent instrument.**

## 2. OBSERVED

### 2.1 Session (§1)

Fresh-power precheck 5/5; identity `17A6` / `verify` / `0x13722093` before the load;
carrier SHA gate; `PCFG_DONE` edge `0xa802000b` → `0x50021004`; `plmark 18d056da61b87283`
identical at all seven stages; epoch 0; no disruptions.

### 2.2 The chain (§5), in order

| step | stage | observed |
|---|---|---|
| 1 | baseline read `0x00400A20` | `PASS`: frame sha256 = pinned base (blank) `0441772f…`; sentinel 0/202 |
| 2 | write A (`0xA50F`) | 231-word stream, DMA `(0x10400001, 0xFFFFFFFF, 231, 0)`, `D_P_DONE` on the first poll (0.201 s = one UART round trip), `INT_STS 0x50033004`, no error bit; **CTRL `0x4e00e07f` before and after** |
| 3 | read ×2 | both `PASS`: frame sha256 = pinned A `8c78f1ce…`; previous (base) not seen |
| 4 | write B (`0x5A90`) | as step 2; `INT_STS` after clear `0x50030004` — `PCFG_DONE` (bit 2) preserved across the write |
| 5 | read ×2 | both `PASS`: frame sha256 = pinned B `b6c91fb8…`; **previous (A) not seen — the discriminating step** |
| 6 | seal | seven records hashed; verified unchanged after step 7 |
| 7 | terminal JTAG (R4) | `READ`, IDCODE `0x13722093`; `0x00400A20` = pinned B (word 51 `0x00005a90`, word 50 `0x00000003`, 2 non-zero words); `0x00400A21` = blank; STAT `0x46107ffc` → **`CRC_ERROR` (bit 0) = 0** |

Every read's `CTRL` was `0x4e00e07f`, `MCTRL` loopback bit 0, `PCFG_DONE` set, dcache OFF,
sentinel written and verified; 15 DMA waits (3 per read + 1 per write) with no bit of the
error mask.

### 2.3 What the pad frame did

The FDRI burst carried the base's blank `0x00400A21` as its second frame; JTAG read
`0x00400A21` back blank. The pad neither corrupted nor was corrupted.

## 3. INFERRED

- **A PCAP write of a certified content-bit change lands, and a PCAP readback returns the
  changed frame bit-exactly and repeatably, on this die — strong.** Two writes, four reads,
  and an instrument that does not share the PCAP path (JTAG, `claimb_findings.md` §2.1's
  instrument) agree on the frame content.
- **Step 5 discriminated.** The pre-write content (A) is non-blank and unique in the frame
  table; the reads after B returned B, not A, not blank. The blank→A ambiguity named in
  `p1_spec.md` §3 did not have to be resolved by inference because the A→B step resolved it
  by observation.
- **Omitting the CRC-register write left no observable CRC state — moderate,
  observational.** `STAT.CRC_ERROR = 0` after both writes. This is the observable the
  warrant promised; it is not a general statement about CRC-less partial writes.
- **`PCAP_RATE_EN` was not touched by the write path** (CTRL identical before/after) —
  the quarter-rate setting this board carries did not need to be cleared for a 231-word
  write to complete within one UART round trip.
- **`PCFG_DONE` survives the runner's own write DMA**, as predicted from the clear mask;
  the N1 gate held on every subsequent read. (U-Boot's `fpga loadp` would have cleared it.)

## 4. NOT TESTED — so that the pass is not read past its scope

- **Non-perturbation (P2).** No observable of the running carrier was read before/after the
  writes or the reads. That the target column is isolated by design is a design fact, not
  a measurement.
- **Anything beyond LUT-INIT word 51 of one frame.** One frame, 14 certified bits, two
  patterns. Not routing-class bits, not other CLB words, not other frames.
- **A wrong or absent CRC.** The stream never wrote the CRC register; what a mismatching
  CRC write does to this board was not observed (UG470 says: INIT_B low, abort).
- **Claim B.** No map-guided arm, no random arm, no score. Zero data points still.
- **Other dies, Linux, U2 (`PCAP_RATE_EN` on reads), U3 (throughput).**
- **What JTAG's `JSHUTDOWN`/`JSTART` did to the design.** It was terminal by design; the
  board was not read again after it.

## 5. What this changes

`s1s3_findings.md` §5 said a PS-side no-shutdown readback was a *candidate* new mechanism
for the paused `zynq-fabricmap` leg, pending P1. P1 now shows the same PS path can also
**write** a certified content-bit change and read it back, with an independent instrument
confirming the landing — the write-integrity link the fabricmap carrier's internal
readback could not close (`claimb_findings.md` §3.1). Whether that becomes the oracle
around which an interlock is re-established (§3.5 there) is P3's question and a new
repository's; and whether the reads perturb the design under test is P2's. Neither is
answered here.
