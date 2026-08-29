# Board run #2 under ruling 2026-08-29-01 — instrument refusal after a complete transfer

**Outcome: `REFUSED: U-Boot did not report the transferred size`, raised by the session's
own size check after the ymodem transfer had completed. No `fpga loadb` was issued, no
probe stage ran, no DMA, no frame read. Not an S1/S2/S3 stop; nothing about the die.**

What the board did (`summary.json`, every reply preserved):

| step | observed |
|---|---|
| precheck (§5a.2) | all five fresh-power values as pinned; `plmark` not defined — PASS |
| identity (§5a.3) | `boardid=17A6`, `role=verify`, `PSS_IDCODE 0x13722093` — PASS |
| `loady 0x04000000` | READY |
| `sb -k carrier.bit` | **3 min 21 s, `Transfer complete`, 2,083,968 bytes sent (2,083,863 + ymodem padding)** — the `blocking_fd()` fix from run #1 is board-proven |
| U-Boot's tail | `## Total Size      = 0x001fcc17 = 2083863 Bytes` / `## Start Addr      = 0x04000000` / prompt — **exactly the file size** |

Cause: `YMODEM_SIZE_RE` was `Total Size = (0x…)` — one space. U-Boot pads the label with
six. The fake in `tests/test_s0b_runner.py` reproduced the author's assumption, not the
board. Fixed in the commit that adds this file: `Total Size\s*=\s*(0x…)`, and the fake now
emits the board's line verbatim.

Ruling `ruling.json` was claimed at 17:16:47 and is consumed. The board was left at the
U-Boot prompt with the carrier in DDR at `0x04000000` and the PL still empty
(`fpga loadb` never ran). A new run needs a new ruling and, per §5a.1, a fresh power cycle.
