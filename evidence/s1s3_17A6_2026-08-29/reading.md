# Board run #1 under ruling 2026-08-29 — instrument refusal at the setup load

**Outcome: `REFUSED: sb failed rc=128` during §5a step 5 (the canonical setup load). No
probe stage ran. No DMA was programmed. No frame was read. This is not an S1/S2/S3 stop
and says nothing about the die; it is a host-side instrument defect, fixed in the commit
that adds this file.**

What the board did, all as specified, in one boot after a physical power cycle
(`summary.json`, `uart_log`, every reply preserved as base64 + sha256):

| step | observed |
|---|---|
| precheck (§5a.2) | `CTRL 0x4e00e07f`, `INT_STS 0xa802000b` (PCFG_DONE=0), `STATUS 0x40000a30`, `FPGA0_CLK_CTRL 0x00400800`, `plmark` not defined — **all five PASS** |
| identity (§5a.3) | `boardid=17A6`, `role=verify`, `PSS_IDCODE 0x13722093` — **PASS** |
| `loady 0x04000000` | `## Ready for binary (ymodem) download ... C` — READY |
| `sb -k carrier.bit` | `Retry 0: Timeout on pathname` / `Transfer incomplete`, rc=128, ~2 s |

Cause (host, verified without the board): pyserial opens the console `O_NONBLOCK` and
never clears it (the "set blocking" line is commented out upstream). `sb`, handed that
descriptor, gets `EAGAIN` on its blocking I/O and reports a timeout on the very first
block. Every previously proven loader on this board opened a *separate blocking* fd for
`sb` — the two-session hole that S0b closed — so the defect could only appear here.

Fix: `board_session.blocking_fd()` clears `O_NONBLOCK` on the session's own descriptor
for the duration of `sb` and restores it (same open file description; §5d.1 intact).
Verified host-only at the transfer level: `sb` through a pyserial fd under `blocking_fd()`
to a single `rb` on the other end of a pty delivered a 64 KiB payload, `rb` exited 0,
sha256 identical. (`sb` then waited for the ymodem batch-end ACK, which `rb` does not send
after exiting; U-Boot's `loady` does, and the session's prompt wait covers that tail.) A
first attempt at this harness started two `rb` receivers on one pty by mistake and failed
with "NAK on sector"; that attempt proved nothing and is recorded only so it is not
repeated. **The fix is proven on the board only by run #2.**

Ruling `ruling.json` (sha256 `8da3044541c14c60…`) was claimed at 17:08:43 and is
**consumed** (`ruling.json.consumed`); a new run needs a new ruling and a fresh power
cycle. The board was left inside `loady`, which times out on its own; nothing else was
sent.
