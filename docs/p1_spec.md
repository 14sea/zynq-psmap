# P1 — post-write PCAP readback of a known-answer content-bit change: specification

> **HOST-SIDE SPECIFICATION. No board run is authorised by this document.** P1 needs its
> own whole-of-probe ruling (`pcap_probe_spec.md` §2; owner ruling 2026-08-29), with the
> ruling text `whole-of-probe P1`. The S1–S3 ruling does not extend to it.

Status: drafted 2026-08-29 after S1–S3 passed (`s1s3_findings.md`). Implements
`line_plan.md` §4 P1 with **one deliberate amendment** (§3 below), flagged for review.
Not yet reviewed by a non-author.

## 0. The one question

> On EBAZ4203 `17A6`, after the PS writes a pre-registered content-bit change into one
> configuration frame through PCAP, does a PS/PCAP readback of that frame return the
> **changed** content bit-exactly — and never the pre-write content?

This is the question S1–S3 could not ask (zero FDRI, setup-loaded content only) and the one
the far goal needs (`line_plan.md` §1.1). It is still a capability question about a path.
It is not Claim B, and it is not non-perturbation (P2).

## 1. What P1 inherits unchanged

- **Session (§5a of the snapshot):** physical power cycle → read-only fresh-power precheck
  (5 values + `plmark` undefined) → identity `17A6`/`verify`/IDCODE on the same session →
  SHA-gated setup load of the canonical carrier with the `PCFG_DONE` edge → `plmark`; one
  boot, one epoch, `plmark` re-checked at every stage. Code: `board_session.py`,
  `pcap_probe_runner.precheck`, `BoardSession.load_carrier` — as run three times on 2026-08-29.
- **Reads:** exactly `pcap_probe_plan.build_plan(far)` — the plan whose guards and board
  result stand — executed by `pcap_probe_runner.execute_plan`, including its
  PRECONDITION / DMA_ERROR / OVERFLOW / TIMEOUT separation (`line_plan.md` R3) and its
  refusal of any command outside the validated plan.
- **CTRL is read, never written** (§5e). `PCAP_PR` is 1 on this board after `fpga loadb`
  (`0x4e00e07f`) and PCAP owns the engine throughout — there is no ICAP in P1 and no
  `PCAP_PR` toggling. `PCAP_RATE_EN` (bit 25) stays as found; AMD's non-secure write path
  clears it for speed, and P1 does not, so the write runs at whatever rate the board is in.
  Recorded, not adjusted.
- **Ruling model (§2):** one ruling for the whole P1 chain, claimed atomically before the
  port opens, consumed by PASS, stop, refusal or crash. No retry inside a run (§7.4).
- **Stop-loss (`stop_loss.md`):** a P1 failure ends the line's P1 leg; a scoped negative is
  published; only a new mechanism reopens it. PRECONDITION / DMA_ERROR / TIMEOUT stops are
  non-discriminating (R3) and say nothing about the die.

## 2. The target — pinned constants, all derived host-side and checked at load

| quantity | value | provenance |
|---|---|---|
| target FAR | `0x00400A20` (block 0, top 1, row 0, major 20, minor 32) | Claim B target column `CLBLL_L_X2`, tile `CLBLL_L_X2Y25`, site `SLICE_X2Y25`, BEL `A6LUT` = "LUT0" |
| pad FAR | `0x00400A21` | FDRI auto-increment; written with the base's own content |
| INIT word | 51 | every one of LUT0's 49 certified INIT bits lives in word 51 of `0x00400A20‥23` |
| INIT mask in this frame | `0xFF9F` (14 bits: 15–7, 4–0) | `zynq-fabricmap` `local_map.json` `by_lut["CLBLL_L.SLICEL_X0.ALUT"]`, certified `clb_lut_init` class |
| base frame (blank) sha256 | `0441772f66559a1c71f4559dc4405438fc9b8383ce1229139257a7fe6d7b8de9` | 101 zero words; the pad frame is also blank |
| pattern A | word 51 = `0xA50F` (ECC word 50 = `0x00000000`) | `8c78f1ce2829e7522dd08cddfe5b444990de3a94ee14ffd771dcb47635c70e3e` |
| pattern B | word 51 = `0x5A90` (ECC word 50 = `0x00000003`) | `b6c91fb841c0df1240aee405c1cb1f6d9efad09b32c7378221bd702dc3408490` |
| A vs B | disjoint, both non-zero, Hamming 14 | neither hash occurs anywhere in the 5,144-frame table |

Content-bit-only: the frame written differs from the base in word 51 (inside the mask) and
word 50 (the recomputed ECC, `frame_ecc.py`, a port of prjxray's `ecc.cc` validated
against Vivado frames in the source repository). Every other word is the base verbatim. No
routing bit is touched. `pcap_write_plan.validate_write_stream()` refuses anything else.

## 3. The amendment to `line_plan.md` P1 — two writes, and why

`line_plan.md` P1 asked for **one** write into a frame that is **non-blank in the base**, so
that `PRE_WRITE_CONTENT` could not be confused with `BLANK`. That requirement cannot be met
with a certified content-bit change: the only certified LUT-INIT addresses on this carrier
are in the isolated target columns, which are **blank in the base by design**
(`claimb_carrier_design.md`); every non-blank CLB frame belongs to live carrier logic, where
a LUT change is not a known answer but a perturbation of the instrument itself.

P1 therefore performs **two** successive writes at the same FAR:

1. **A** (blank → A). A `BLANK` on the reads after it is `PRE_WRITE_CONTENT` *or* a
   misaddress to any of 4,716 blank FARs — ambiguous, as `line_plan.md` said.
2. **B** (A → B). Now the pre-write content is **non-blank and unique**: a read returning
   the A frame is unambiguously `PRE_WRITE_CONTENT`; a blank is `BLANK`; anything else is
   adjudicated by the table.

Step 2 is the discriminating one. Step 1 is kept because it is the blank→non-blank case the
far goal will meet first, and because a PASS at step 1 is required before step 2 is
attempted (one ruling, one chain, stops on the first failure). The reviewer is asked to
rule on this amendment explicitly.

## 4. The write — every device operation, and what is NOT done

### 4a. The stream (231 words, SelectMAP word order, no bit reversal — §8a's PCAP rule)

```
DUMMY ×8, SYNC, NOOP,
CMD ← RCRC, NOOP, NOOP,
IDCODE ← 0x03722093,
CMD ← WCFG, NOOP,
FAR ← 0x00400A20,
FDRI type-1 (count 0), type-2 count 202,
  frame(0x00400A20, pattern) [101], pad = base(0x00400A21) [101],
CMD ← DESYNC, NOOP ×4
```

This is the sequence `zynq-xpart` proved on ICAPE2 (`hwicap-make-framewrite.py`,
deterministic and reversible over three flips on the 4205), minus its CRC-register write.

### 4b. NOT performed — the write's safety property

- **No GRESTORE, GTS, GCAPTURE, SHUTDOWN, START, IPROG, AGHIGH, GHIGH, MFWR.** The guard
  refuses every configuration command except RCRC, WCFG, DESYNC, and every register write
  except CMD, IDCODE, FAR, FDRI.
- **No CRC-register write.** A CRC write triggers a CRC compare; the carrier's CRC
  setting is not pinned here, and a CRC error is a device-state event. The engine checks
  CRC only when the CRC register is written, so omitting it is a *narrower* operation, not
  a looser one. The terminal JTAG read (§6) is the integrity check that a CRC would have
  been.
- **No second FDRI, no FAR other than the target, no PL AXI, no ICAP, no CTRL write.**

### 4c. The DMA

One command: `(WR_BUF|1, 0xFFFFFFFF, 231, 0)` with `WR_BUF = 0x10400000` (64-byte
aligned, not crossing 4 KiB in a way the engine cares about: 924 B). This is what AMD's
`XDcfg_Transfer(…, XDCFG_NON_SECURE_PCAP_WRITE)` issues and what both AMD examples pass
(`DestWordLength = 0` — `xdevcfg_polled_example.c:253`, `xdevcfg_interrupt_example.c:302`,
devcfg_v3_9). Preceded by the pinned `INT_STS` clear (mask excludes `PCFG_DONE`) and its
verification; completion `D_P_DONE`; the same error mask and the same 1 s derived timeout
as the reads. `STATUS[PCFG_INIT]` is 1 on this board (`0x40000a30`), which is the
precondition `XDcfg_Transfer` checks.

### 4d. What happens to `PCFG_DONE`

U-Boot's own `fpga loadp` clears **all** of `INT_STS` before a partial load, which would
clear `PCFG_DONE` and trip the N1 gate of every subsequent read. P1 therefore does **not**
use `fpga loadp`; its own DMA clears only the pinned mask, and `PCFG_DONE` survives. This
is a reason the write is the runner's own transaction and not U-Boot's.

## 5. The chain, in this order and no other (`line_plan.md` R4)

| step | what | gate |
|---|---|---|
| 0 | session (§1) | as S1–S3 |
| 1 | **baseline** read of `0x00400A20`, expected = base (blank) hash | `PASS` required |
| 2 | **write A** | D_P_DONE, no error bit |
| 3 | read ×2, expected = A hash, previous = base | both `PASS` |
| 4 | **write B** | D_P_DONE, no error bit |
| 5 | read ×2, expected = B hash, previous = A | both `PASS` |
| 6 | **seal**: every record and raw buffer written and hashed | — |
| 7 | **terminal JTAG** (§6) of `0x00400A20` and `0x00400A21` | `0x00400A20` == B hash, `0x00400A21` == pad (blank) |

Verdicts on a read are §7's vocabulary plus one: **`PRE_WRITE_CONTENT`** — the frame half
equals the *previous* pinned content (base at step 3, A at step 5). It is adjudicated after
the `PASS` row and before `BLANK`; at step 3 it coincides with `BLANK` and both are
recorded. Every non-PASS read is a stop; the second read of a pair is not attempted after a
first-read stop.

**PASS for P1 = every read `PASS` ∧ both writes completed clean ∧ terminal JTAG matches B.**
Two of three is a stop.

## 6. The terminal JTAG verifier

`scripts/probe_jtag_config_read.py` (2.4.0) and `scripts/jtag_config_only.cfg`, imported
byte-for-byte from `zynq-fabricmap` at `71666b02…` (sha256 `c3e79a08…`, `06e54204…`) —
the instrument that proved the Claim B write landed (`claimb_findings.md` §2.1, 16/16
controls). It runs on the FT4232H pod, declares no CPU target, and its IR allowlist refuses
JPROGRAM, WCFG, MFWR, IPROG and any FDRI write in code. Its R4 sequence performs
`JSHUTDOWN`/`JSTART` — a whole-die transition — which is why it is **terminal**: nothing is
read from or written to the board after it, and its verdict is an after-the-fact check of
the write, not part of the mechanism under test. If it cannot run (pod absent, openocd
missing) the chain is `HOLD`, not `PASS`: two of the three conjuncts are not enough.

## 7. What a P1 PASS would and would not establish

**Would:** on this die, over U-Boot, PCAP wrote a certified content-bit change into one
frame and PCAP read it back bit-exactly, twice, at the requested address, without any
startup transition — and an independent instrument saw the same content afterwards.

**Would not:** that the write left the running design unperturbed (P2); anything about
routing-class bits; anything about Claim B (no map-guided arm, no score); anything about
another die or a Linux control plane; that a *blank→non-blank* read can distinguish
pre-write from misaddress (it cannot; step 5 is the discriminating step).

## 8. Evidence

Per step a record as §10 plus, for writes: the 231 stream words as sent, the DMA tuple,
`INT_STS` before/after, the wait's elapsed time (`measured`); for the JTAG step: the
probe's own record (`jtag.json`, with its Tcl and openocd transcript). `summary.json`
carries the full raw UART log. The three pinned hashes are copied verbatim into every
record they gate.
