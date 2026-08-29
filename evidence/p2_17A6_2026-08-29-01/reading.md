# P2 board run #1 under ruling `whole-of-probe P2` 2026-08-29-01 — transport refusal at read 7

**Outcome: `REFUSED: md line at 0x10300050, expected 0x1030003c`** raised by
`board_session.parse_md` on the 202-word readout of the seventh PCAP read (`P2_3_read_6`,
never recorded). **Not a P2 verdict.** No continuity violation was observed; the chain
was cut by the console transport, and the ruling is consumed by design.

## What the board did (all as specified)

| step | observed |
|---|---|
| session | precheck 5/5; identity `17A6`/`verify`/`0x13722093`; carrier SHA gate; `PCFG_DONE` edge; `plmark` stable; epoch 0; no disruptions |
| `P2_0_fclk` | `IO_PLL_CTRL 0x00030008` (fdiv 48 → 1600 MHz), `FPGA0_CLK_CTRL 0x00400800` (/8 /4) → **50.000 MHz**, gate OK |
| `P2_1_baseline` | `STATUS 0x00000080`, `FAULT 0`, `SCORE0‥5 0` — exactly the expected fresh-load O |
| `P2_2_control` | 30 s with nothing sent; O₁ = O₀ (**stable**) |
| `P2_3_read_0‥5` | six PCAP reads of `0x00000B99`, each `PASS` (bit-exact, 0 sentinel survivors), **each followed by O = O₀** |
| `P2_3_read_6` | the `md.l 0x10300000 0xca` reply carried 50 lines instead of 51 (line `0x10300040` absent; 3,260 bytes); refused |

So 6/10 planned reads, with the observable unchanged after every one, and the write arm
never reached. **The data are consistent with P2's hypothesis and do not test it to the
pre-registered N.**

## Cause class

A dropped segment on the host's receive side of the CH340/usbipd path during a ~3.4 KB
burst (51 lines × ~66 bytes at 115200 baud ≈ 0.3 s). Frequency on this board today:
**1 in 32** 202-word readouts across runs S1–S3 #3 (13), P1 #1 (5) and this run (14).
The session's refusal is correct — an undercounted buffer must not be adjudicated — but
the consequence (a consumed ruling and a lost chain) is disproportionate to a
non-destructive read of DDR.

## Proposed amendment (host-only; for review before ruling #2)

A **malformed `md.l` reply** (line address or word count mismatch) is a transport fault of
the console, not an observation about the die or the DMA. For `md.l` **only** — never
`mw.l`, never a DMA register write — the runner may **re-send the identical `md.l`** up to
**2** more times; every raw reply is preserved; the count of re-reads is recorded per stage;
the adjudication uses only a complete reply. This is not a retry in §7.4's sense: the DMA
is not re-issued, no register is written, DDR is not modified, and the destination buffer
that is re-read is the same bytes the DMA already left there. Implemented in
`board_session.BoardSession.read_command` (`rereads` argument) and used by the runners'
senders; `tests/test_s0b_runner.py` covers a single drop (recovered, counted), a persistent
drop (refused after 3), and that a re-read never sends anything but the same `md.l`.

Ruling `ruling.json` was claimed at 18:45:02 and is consumed. The board was left at the
U-Boot prompt with the carrier configured, `0x00400A20` still blank (the write arm was not
reached). The next run needs a new ruling and a fresh power cycle.
