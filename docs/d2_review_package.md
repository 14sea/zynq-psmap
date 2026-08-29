# D2 — third-party review of completed S0: the package

Status: **request for review, not a status claim.** Prepared 2026-08-29 at `dcd450c` for a
reviewer who has not written any part of S0. Until this review returns a verdict, the
status table stays as it is: S0 is NOT complete, §8a is `independently reviewed: NO`, no
board ruling is sought, the board is not touched.

## 0. Who may review, and what the review is

`pcap_probe_spec.md` §2: the board ruling is applied for only *after S0 has been reviewed
by a party that did not write it*. `line_plan.md` §6 D2 (owner ruling, 2026-08-29): a
**third-party review of completed S0 as a whole, including §8a**, is required; both
co-authors (Claude and ChatGPT) are disqualified because §8a was written by both in
alternation. The owner has ruled (2026-08-29) that the third party may be an LLM.

The reviewer is asked for one of three verdicts, on S0 as a whole:

- **PASS** — S0 may be cited as reviewed; the owner may then consider a whole-of-probe
  board ruling for S1–S3 (that ruling is a separate decision, not part of this review).
- **HOLD** — named defects must be fixed and the review re-run.
- **FAIL** — a defect that a fix cannot close without changing the specification.

The reviewer is **not** asked whether Claim P is true, whether the probe will pass on
silicon, or whether the line is worth running. Those are not S0 questions.

## 1. What S0 is — the four deliverables and where each lives

| deliverable | file(s) | governing text |
|---|---|---|
| **S0a.1** discharge §2b against UG585 (three claims: two transfers / RxFIFO no flow control / ≈145 MB/s; plus the bit-25 rider) | `docs/s0_ug585_discharge.md` (144 lines) | snapshot §2b, §2a |
| **S0a.2** derive and **pin** §2c: register map, endpoint pseudo-address, 43-word command stream, CTRL masked gate, completion/error bits, clear-and-verify, MCTRL loopback gate, cleanup, buffers/cache, timeout | `docs/s0_derived_sequence.md` (598 lines); `scripts/pcap_probe_plan.py` (720 lines, the planner + its guards) | snapshot §2c, §5b, §5d, §5e, §6, §7 |
| **§8a** the DMA command shape: two unidirectional DMA commands, non-active endpoint length 0, per AMD `XDcfg_PcapReadback()` — **resolved by the two co-authors, never reviewed by a non-author** | `docs/s0_derived_sequence.md` §8a (lines ~417–555); planner `LEGAL_DMA_TRANSACTIONS`, `PINNED_DMA_ORDER` | snapshot §2c; `pcap_probe_spec.md` §2a |
| **S0a.3** reproduce the §4 target selection (FAR `0x00000B99`, min Hamming 822, unique hash, 4,716 blank FARs) | `scripts/diag_pcap_target_select.py`, `scripts/bitstream_frames.py`, `tests/test_pcap_probe_target.py` | snapshot §4 |
| **S0b** the runner and the single `BoardSession` (one identity, one epoch across loader and runner) | `scripts/board_session.py` (450), `scripts/pcap_probe_runner.py` (526), `tests/test_s0b_runner.py` (67 tests) | snapshot §5a.3, §5d; `pcap_probe_spec.md` §1, §2a; `line_plan.md` §4 P0 |

Guards: `tests/test_s0_pcap_plan.py` (168 tests, frozen by owner ruling — do not ask for
more of them) and `tests/test_owner_spec.py`, `tests/test_import_manifest.py`.
Entry: `python3 -m unittest discover -s tests` → 270 OK on a clean tree at `dcd450c`.

**Review history the reviewer should know:** S0a passed a co-author cross-review at
`8cb544b`. §8a's PASS was recorded and then **withdrawn** because the delta
(`d0ba146..77e29a5`) was co-written. S0b passed a three-round non-author cross-review by
ChatGPT at `bde1d07` (round 1: 6 blockers + 4 majors; round 2: 2 blockers; round 3: pass).
That cross-review does **not** substitute for this one: it covered S0b alone, and its
reviewer is a co-author of §8a.

## 2. The questions this review must answer

Ordered by weight. The reviewer should answer each with a citation into the file and line.

**Q1 — §8a (the only part never seen by a non-author).** Is the derivation in
`s0_derived_sequence.md` §8a sound? Specifically:
- Is `XDcfg_PcapReadback()` at `embeddedsw` commit
  `cbc5280400e7f08e35203d0dbd6bf09922049361` correctly read — two `InitiateDma` calls,
  `(Source, 0xFFFFFFFF, SrcLen, 0)` then wait `D_P_DONE` then `(0xFFFFFFFF, Dest, 0, DestLen)`?
- Are the three pinned tuples — command `(CMD|1, PCAP, 43, 0)`, readback
  `(PCAP, DST|1, 0, 202)`, cleanup `(CMD|1, PCAP, 5, 0)` — what that driver would issue?
- Is the retained alternative ("one-bidirectional") correctly labelled *not adopted* rather
  than *refuted by hardware*?
- Does the document anywhere still claim that a wrong pin *must* show as `DMA_CMD_ERR` /
  `P2D_LEN_ERR`? (It must not: those are candidate diagnoses only.)
- **§8b** (`2'b01` hold tag when one endpoint is `0xFFFFFFFF`) is pinned UNRESOLVED and the
  planner tags both DDR-side addresses with `|1`. Is leaving it unresolved *and* tagging
  defensible, or does it need a ruling before board time?

**Q2 — UG585 discharge.** For C1, C2, C3 and the bit-25 rider in `s0_ug585_discharge.md`:
does the cited UG585 text support the conclusion drawn, and are the "constraints the
specification did not carry" (its §"Constraints UG585 imposes") all reflected in the
planner or the runner? Name any that are not.

**Q3 — the pinned sequence vs the spec.** Walk `build_plan()`'s `uboot_script` against
snapshot §5b (normative sentinel-before-DMA), §5c (nothing forbidden is issued: no FDRI,
no SHUTDOWN/START/RCRC/GRESTORE/GTS/GCAPTURE/JSHUTDOWN/JSTART, no PL AXI), §5d.5
(clear-and-verify before every DMA, cleanup after), §5e (CTRL read, never written), §6c
(sentinel), §7 (stop conditions). Any command that violates a clause is a FAIL.

**Q4 — S0b against §5a and §5d.** Does the runner implement: identity **before** the
setup load on the same session (§5a.3); one configuration write only (§5a.5, the carrier,
SHA-gated, PCFG_DONE as an edge, `plmark` set); the same `plmark` checked at every stage
(§5a.6); one `BoardSession`, no second port resolution (§5d.1); a named
configuration-read capability distinct from any write (§5d.2); an allowlist that refuses
before transmission (§5d.3); unconditional refusal of FDRI, off-allowlist addresses and a
`linux` executor (§5d.4); §7's verdict vocabulary and nothing else on the payload
(§7.3, §10)?

**Q5 — stop-loss fidelity.** `stop_loss.md`: any S1/S2/S3 failure ends the line; no retry,
no parameter change inside a run (§7.4); one ruling, consumed on any failure (§2). Does
the runner's ruling claim (`claim_ruling`, O_EXCL before the port opens) and its
no-reissue wait loop honour this? Can a second attempt happen without a new ruling file?

**Q6 — R3 separation (line_plan §3).** Are non-discriminating stops (PRECONDITION,
DMA_ERROR, TIMEOUT-before-payload) kept apart from payload verdicts in the records, so
that a stopped line is never later read as a falsified mechanism?

**Q7 — anything that makes a negative uninterpretable.** The reason S0 exists is that the
previous leg produced nulls it could not interpret. Is there any path through the runner
where a `BLANK`, `BUFFER_UNCHANGED_FROM_PREFILL` or `TIMEOUT` could be produced by the
instrument itself (cache, stale status, wrong buffer, wrong slice, wrong endianness in
`frame_sha256`) rather than by the die? Each such path is a HOLD.

## 3. Known weaknesses, declared by the authors

The reviewer should not have to find these; they are listed so that the review can go
past them.

1. `--port` is a runner argument. It selects a cable; it cannot relax identity (a wrong
   board is refused by `verify_identity()` whatever the port). Still, it is an argument.
2. The four precheck register values (`CTRL 0x4E00E07F`, `INT_STS 0xA802000B`,
   `STATUS 0x40000A30`, `FPGA0_CLK_CTRL 0x00400800`) are historical fresh-power readings
   from `17A6`, carried over from the source repository's precheck. They gate a fresh
   power-on; they are not datasheet values.
3. `TIMEOUT_S = 1.0` is derived (≈45,000× the pessimistic estimate), not measured.
4. `§8b` is unresolved (see Q1).
5. The frame-table reverse lookup is by sha256 of the 101 words; two distinct FARs with
   equal content are reported as `MISADDRESS_AMBIGUOUS` with the full set — never a pick.
   4,716 FARs share the blank hash; a `BLANK` therefore says nothing about address.
6. `adjudicate()` compares `words[101:202]` only (§4d). The pad half is hashed and recorded
   but never adjudicated; a correct frame with garbage in the pad is `PASS`.
7. The fake U-Boot in `tests/test_s0b_runner.py` models `md.l`/`mw.l`/`printenv`/`setenv`/
   `dcache`/`fpga loadb`/ymodem size and a devcfg that completes every DMA. It does not
   model timing, the RxFIFO, or a partial transfer; those are exactly what S1–S3 measure.
8. The status-table guards in `tests/test_s0_pcap_plan.py` are frozen by owner ruling. A
   review finding that needs a new guard should say so and stop, not add one.

## 4. What the reviewer may and may not do

- May read everything in the repository at `dcd450c`, run the tests, run
  `scripts/pcap_probe_plan.py --json`, `scripts/diag_pcap_target_select.py`, and any
  host-only script.
- May consult UG585, UG470 and the AMD `embeddedsw` source at the pinned commit.
- **May not** run anything that opens `/dev/ebaz-uart` or any serial port, and may not ask
  the owner to. The runner refuses without a ruling file; the reviewer must not create one.
- **May not** be Claude or ChatGPT (`pcap_probe_spec.md` §2a: both are co-authors of §8a).

## 5. What happens with the verdict

The verdict is recorded verbatim in `docs/d2_review_result.md` (to be created by the
authors from the reviewer's text, unedited), the status table's §8a row moves from
`independently reviewed: NO` to the reviewer's verdict **only on PASS**, and S0's row moves
to `complete` **only if** every other row is at PASS. A HOLD or FAIL leaves every row where
it is. The board ruling for S1–S3 is a separate owner decision and is not implied by PASS.
