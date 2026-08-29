# P2 findings — non-perturbation of the carrier's observable state by PCAP reads and one write, on `17A6`

**Status: P2 `PASS` on 2026-08-29, run #3, under owner ruling `whole-of-probe P2`
(`2026-08-29-03`, consumed).** Runs #1 and #2 (`2026-08-29-01`, `-02`) were cut by the
host's usbip console link (a dropped line; a reset mid-burst — `vhci_hcd urb->status -104`)
before completing; each is recorded in its own evidence directory and neither produced a
verdict. Run #3 completed with **no transport re-read needed** (`transport_rereads: []`).

Evidence: `evidence/p2_17A6_2026-08-29-03/` — 16 stage records, `summary.json` (identity,
precheck, setup load, FCLK0 decode, every observable sample, the complete raw UART log:
1,266 replies), `ymodem.log`, the ruling and its claim.

**Scope, ruled by the owner before the run:** a P2 PASS claims only that, on this `17A6`
carrier, in the eight pinned registers, under these PCAP operations, no state perturbation
was observed. It is **not** a proof that a design kept computing (that is P2b, §5).

## 1. The question (`p2_spec.md` §0)

> While the canonical carrier is configured on `17A6`, do PS/PCAP readbacks of a frame
> holding live carrier logic — and one certified content-bit write into the isolated
> column — leave the carrier's observable state unchanged?

**Answer, within scope: yes.**

## 2. OBSERVED

### 2.1 Session and gates

Fresh-power precheck 5/5; identity `17A6`/`verify`/`0x13722093` before the load; carrier SHA
gate; `PCFG_DONE` edge `0xa802000b` → `0x50021004`; `plmark` stable at all 16 stages;
epoch 0; no disruptions. **FCLK0 decoded read-only from the PLL/divisor registers:
`IO_PLL_CTRL 0x00030008` (fdiv 48 → 1600 MHz), `FPGA0_CLK_CTRL 0x00400800` (/8, /4) →
50.000 MHz.**

### 2.2 The observable

O = (`STATUS 0x43C02004`, `FAULT 0x43C02008`, `SCORE0‥5 0x43C02010‥24`).
Baseline O₀ = `STATUS 0x00000080` (`recovery_required` only), all others `0` — the
expected fresh-load value. Liveness held on every sample (bits 31:27 zero, word ≠ 0).

### 2.3 The chain

| step | stage | observed |
|---|---|---|
| control | `P2_2_control` | 30 s (derived) with nothing sent; O₁ = O₀ |
| reads | `P2_3_read_0‥9` | ten PCAP reads of `0x00000B99`, each `PASS` (bit-exact vs the pinned hash, 0/202 sentinel survivors, `CTRL 0x4e00e07f`); **O = O₀ after each** |
| post | `P2_4_post` | 182.6 s (measured span of the ten reads) with nothing sent; O₂ = O₀ |
| write | `P2_5_write` | pattern A (`0xA50F`) into `0x00400A20`, DMA `(0x10400001, 0xFFFFFFFF, 231, 0)`, `D_P_DONE` first poll, no error bit, `CTRL` unchanged; **O = O₀** |
| readback | `P2_6_readback` | `0x00400A20` = pinned A; **O = O₀** |

**15 samples, 14 comparisons, 0 differences.**

## 3. INFERRED

- **Ten PCAP readbacks of a frame that holds live carrier logic did not change any
  readable carrier register — strong, within the observable's coverage.** The control arm
  shows the eight words are stable on their own over the same span, so the equality after
  reads is discriminating in the sense R5 required.
- **One certified content-bit write into the isolated target column did not change any
  readable carrier register — strong, same coverage.** Consistent with the column's
  design isolation (`claimb_carrier_design.md` §3), now measured rather than assumed.
- **The console link, not the probe, is today's dominant failure mode.** Runs #1 and #2
  died on it; run #3 went through with zero re-reads. This says nothing about the die.

## 4. NOT TESTED

- **A running computation.** The carrier idles; no transaction begun, scorer not armed;
  nothing was clocking through the logic whose frame was read. The eight words are the
  observable's entire coverage.
- **Flip-flop or interconnect state that no register exposes.**
- **Non-perturbation by a JTAG transition** (none performed in P2).
- **Routing-class bits, other frames, other dies, Linux, Claim B.**

## 5. What this changes

With S1–S3, P1 and P2 all `PASS` on `17A6`, the PS/PCAP path is now, within scope:
readable bit-exactly and repeatably, writable for a certified content-bit change with
independent confirmation, and non-perturbing to the carrier's observable state. The
remaining open questions are **P2b** (a counter-class observable on a computing design —
autoehw's M1 heartbeat shell, a separate spec, setup load and ruling) and **P3** (the
interlock architecture around the PS oracle, a new repository). `zynq-psmap` stays the
instrument and evidence repository.
