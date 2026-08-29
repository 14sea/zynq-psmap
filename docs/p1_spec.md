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
  Recorded before and after the write, and **asserted unchanged** (a difference is a
  non-discriminating stop) — added 2026-08-29 after the provisional review's one valid point.
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

The evidence for "cannot be met" is mechanical, not a preference:

- `zynq-fabricmap`'s certified local map places **all 49** of LUT0's mapped INIT bits in
  word 51 of frames `0x00400A20‥23` (`tests/test_p1.py` pins the 14 in this frame); those
  four frames are **all-zero in the base** (`pcap_write_plan.base_frames`, and every
  Claim B target FAR reads 0 non-zero words in `carrier.bit`).
- They are blank because `claimb_carrier_design.md` §3 reserves the target columns
  `CLBLL_L_X2`/`CLBLM_L_X6` for evolvable logic and keeps the carrier's own logic out of
  them; that isolation is what makes a write there a known answer rather than a change to
  the instrument.
- No other LUT-INIT address on this die carries a certificate; an uncertified change is
  not a known answer.

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
- **No CRC-register write — warranted by UG470 v1.17, the carrier's own header, and an
  observable, not by the authors' judgement.**
  - *When the check happens.* UG470 v1.17, ch. 5, "CRC Register (00000)": *"Writes to this
    register are used to perform a CRC check against the bitstream data. If the value written
    matches the current calculated CRC, the CRC_ERROR flag is cleared and startup is allowed."*
    And the CRC section of the same chapter: *"After the configuration data frames are
    loaded, the configuration bitstream **can** issue a Check CRC instruction to the device,
    followed by an expected CRC value. If the CRC value calculated by the device does not
    match the expected CRC value in the bitstream, the device pulls INIT_B Low and aborts
    configuration."* The check is an act of the stream (a write to register 00000), not a
    background property of the engine; a stream that does not write the register is not
    checked. `RCRC` at the head of the stream resets the running CRC (command table: *"RCRC
    00111 Resets CRC: Resets the CRC register"*), exactly as every Vivado bitstream — the
    carrier's included — begins.
  - *Why not write it.* Writing an **incorrect** expected value is the abort path quoted
    above ("pulls INIT_B Low and aborts configuration") — a device-state event on the only
    verification board. Writing the **correct** value would require this line to implement
    and certify the 7-series bitstream CRC over the exact 231-word stream, which is a new
    instrument with its own review; `zynq-xpart` sidestepped it by building CRC-disabled
    bitstreams and writing `CRC ← 0`, a value that is only correct when the check is
    disabled. Neither is available here without new work, and the check adds nothing the
    terminal verifier does not establish directly.
  - *Readback CRC (POST_CRC) is off on this carrier — decoded from the bitstream, checked by
    a test.* UG470 places POST_CRC enable and `RBCRC_ACTION` in COR1 (Table 5-33) and the
    precomputed readback CRC in `RBCRC_SW`. The carrier's header (`carrier.bit`, decoded by
    `tests/test_p1.py::CarrierHeader`) writes **`COR1 = 0x00000000`** and
    **`RBCRC_SW = 0x00000000`**, so no readback-CRC logic is armed that a partial write
    without `CRCC` could later trip. (The carrier's full configuration did carry CRC checks —
    `CRC ← 0x40ddde08` after its FDRI and `CRC ← 0xe3ad7ea5` before `DESYNC` — which is why
    `CRC_ERROR` is 0 after the setup load.)
  - *The observable.* UG470 Table 5-29: STAT bit 0 is `CRC_ERROR`. The terminal JTAG probe
    reads STAT and records it as `config_status`; P1 **requires `CRC_ERROR = 0`** there
    (`p1_runner.jtag_verdict`). If omitting the CRC write left any CRC-error state, this
    is where it would show, and a 1 is a stop.
  - *Residual, stated.* The CRC register holds a running value after the stream that no
    later reader interprets: every subsequent bitstream begins with `RCRC`, and P1 issues
    no `START` (the only command whose gating on "a successful CRC check" UG470 mentions).
    That residual is named here rather than argued away.
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
| 7 | **terminal JTAG** (§6) of `0x00400A20` and `0x00400A21` | `0x00400A20` == B hash, `0x00400A21` == pad (blank), **STAT `CRC_ERROR` = 0** |

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
