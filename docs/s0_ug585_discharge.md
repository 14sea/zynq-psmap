# S0 — discharging §2b against UG585

**Host-only. No board action is authorised by this document, and none was performed.**

`docs/pcap_probe_spec.md` inherits a class **2b** list: three claims "supplied by review,
citing AMD UG585", explicitly marked *not fetched or read by the author*. S0 owes a
discharge. This is it.

## Source, and how it was obtained

AMD serves UG585 as a JavaScript application; neither the reader URL nor the legacy PDF
path returns document text (both return a 2,575-byte shell). The text below was retrieved
from the site's own Fluid Topics content API, map `27MqOpdJbAciY4iKGTycVA`
("Zynq 7000 SoC Technical Reference Manual (UG585)", `clusterId: UG585`, edition
**2026-02-06**, `khubVersion 5.1.16`), one topic at a time:

| topic | id |
|---|---|
| PL Bitstream Readback | `Vt6feBnn1MmUKUpaLMwXLg` |
| Example: PL Bitstream Readback | `drQtALyBshDvbPgloCEiNA` |
| PCAP Throughput | `clxzQ9JJNJNiwmU~VrWGmg` |
| Register XDCFG_CTRL_OFFSET Details | `JNx9sN5lrVfC9tR6LHPCYA` |
| Register XDCFG_INT_STS_OFFSET Details | `Z0kcL4~cbOD8Tkke0HsgKQ` |
| Register XDCFG_STATUS_OFFSET Details | `RTbyzblxoNiuFCSaaTaEVw` |
| Register XDCFG_DMA_{SRC,DEST}_{ADDR,LEN}_OFFSET Details | `FZLKUmMB13tLG8iztJ_B6A`, `WzJMpxN0_uBuDoxwsJmVjA`, `~9~Hhrz1zAIxmoLNoANv1g`, `vL8HrmvOQCtGq_9wNzaBBg` |

Retrieved 2026-08-28. **The retrieved text is not redistributed in this repository**; the
quotations below are the short extracts the discharge turns on.

## The three §2b claims

### C1 — two DMA transfers, minimum unit one 101-word frame → **DISCHARGED**

> "Two DMA accesses are required to complete a PL configuration readback. The first access
> is used to issue the readback command to the PL configuration module. The second access is
> needed to read the PL bitstream from the PCAP. The smallest amount of bitstream data that
> can be read back from the PL is one configuration frame which contains 101 32-bit words."
> — *PL Bitstream Readback*

Exactly as the review stated. The two-transfer shape and the 101-word unit are now class 2a
for this line.

### C2 — RxFIFO, no PL-side flow control, no splitting → **DISCHARGED, and stronger than stated**

> "A single PCAP readback access cannot be split across multiple DMA accesses. If the
> readback command sent to the PL requests 505 words, the DevC DMA must also be set up to
> transfer 505 words. Splitting the transaction into two DMA accesses results in data loss
> and unexpected DMA behavior."
>
> "The DMA must have sufficient bandwidth to process the PL readback due to a lack of data
> flow control on the PL side of the PCAP. Overflow of the PCAP RxFIFO results in data loss
> and unrecoverable DMA behavior."
> — *Example: PL Bitstream Readback*

Both claims hold verbatim. Two additions the review did not carry:

- **The requested word count and the DMA destination length must be equal.** This is a
  pinnable pre-run invariant, and §7's stop conditions gain a check that costs nothing.
- **Overflow is "unrecoverable"**, not merely lossy — which raises the standing of §7.1 from
  a data-quality stop to a *device-state* stop.

### C3 — ≈145 MB/s → **DISCHARGED, with the assumptions it depends on**

> "In non-secure mode, the transfer rate through the PCAP is approximately 145 MB/s. … This
> approximation assumes a 100 MHz PCAP clock, a 133 MHz APB bus clock, a read issuing
> capability of 4 on the PS AXI interconnect, and a DMA burst length of 8."
> — *PCAP Throughput*

The figure is real and it is an approximation with four named preconditions, none of which
has been measured on `17A6`. Every use of it stays labelled *derived, not measured* (§6b).

## The §2a rider: what bit 25 is → **DISCHARGED, with a naming discrepancy inside UG585**

The specification says UG585 identifies bit 25 as `QUARTER_PCAP_RATE_EN` and requires S0 to
discharge it. Both halves of that turn out to be true, and UG585 is inconsistent with itself:

- the **register table** names bit 25 `XDCFG_CTRL_PCAP_RATE_EN_MASK (PCAP_RATE_EN)`, rw,
  **reset value 0x0**;
- the **PCAP Throughput** prose names the same function `devcfg.CTRL [QUARTER_PCAP_RATE_EN]`.

Semantics are unambiguous either way:

> "This bit is used to reduce the PCAP data transmission to once every 4 clock cycles. This
> bit MUST be set when the AES engine is being used to decrypt configuration data for either
> the PS or PL. Setting this bit for non-encrypted PCAP data transmission is allowed but not
> recommended. 0 - PCAP data transmitted every clock cycle 1 - PCAP data transmitted every
> 4th clock cycle."

**So the review's identification is correct and the difference between the two boards is
real.** Decoding the two recorded words against the table:

| bit | field | `0x4e00e07f` (`17A6`) | `0x4c00e07f` (the 4205) |
|---|---|---|---|
| 27 | `PCAP_PR` | 1 — PCAP owns the engine | 1 |
| 26 | `PCAP_MODE` | 1 — PCAP interface enabled | 1 |
| 25 | `PCAP_RATE_EN` | **1 — quarter rate** | **0 — full rate** |
| 7 | `SEC_EN` (ro) | **0 — the PS did NOT boot securely** | 0 |

`17A6` therefore runs PCAP at quarter rate **with no AES in use** — the case UG585 calls
"allowed but not recommended". **Its bearing on §7.1 is conditional on U2 below and no
relief may be claimed from it**: if the bit throttles the read direction the overflow risk
falls, and if it does not, §7.1 is untouched. What is unconditional is the cost — the
transfer takes longer — which is why §6b's timeout is derived at quarter rate in
[`s0_derived_sequence.md`](s0_derived_sequence.md).

## Constraints UG585 imposes that the specification did not carry

These are the discharge's real yield. Each is now pinned in `s0_derived_sequence.md`.

| # | constraint | source | why it matters |
|---|---|---|---|
| **N1** | "Readback of configuration registers or the bitstream cannot be performed until the devcfg.INT_STS [PCFG_DONE] bit asserts." | *Example: PL Bitstream Readback* | A hard precondition the runner must check. §5a already clears sticky `PCFG_DONE` so the post-load check is an edge; N1 makes that check load-bearing for the probe, not just for the load. |
| **N2** | "All DMA transactions must be 64-byte aligned to prevent accidently crossing a 4K byte boundary." | ibid. | Constrains every buffer address §2c has to choose. |
| **N3** | "It is important that the parameters are programmed in the exact sequence as described" — SRC_ADDR, DST_ADDR, SRC_LEN, DEST_LEN — and the command "is accepted when this register [DEST_LEN] is written to". | the four DMA register topics | The programming order is **normative in UG585**, and the DEST_LEN write is the trigger. §5b's ordering question is answered by the vendor, not by S0's taste. |
| **N4** | "Setting SRC_ADDR[1:0] and DST_ADDR[1:0] to 2'b01 will cause the DMA engine to hold the DMA DONE interrupt until both the AXI and PCAP interfaces are done with the data transfer. Otherwise the interrupt will trigger as soon as the AXI interface is done." | `XDCFG_DMA_SRC_ADDR`/`DEST_ADDR` | **Decisive.** Without the `01` tag, `DMA_DONE` does not mean the readback finished — it means the AXI side finished. A completion check built on the default would pass before the data arrived. |
| **N5** | `STATUS[24:20] RX_FIFO_LVL` — "how many valid 32-Bit words in the Rx FIFO, max. is 31". | `XDCFG_STATUS` | The 202-word destination is **6.5×** the entire RxFIFO. C2's bandwidth warning is not theoretical here. |
| **N6** | `INT_STS` bit 18 `IXR_RX_FIFO_OV`: "RX FIFO overflows. Incoming read data from PCAP will be dropped and the DevC DMA may enter an unrecoverable state." | `XDCFG_INT_STS` | This is the overflow bit §2c demanded — an identified bit, no longer a guess. |

## What could NOT be discharged, and is therefore still open

- **U1 — RETRACTED 2026-08-28. UG470 was obtained and the sequence IS discharged against
  it.** The first pass of this document concluded the primary source was unavailable. That
  was wrong, and the mistake was mine: UG470 is not a *map* on the content API, it is a
  *document*, and I searched only `/api/khub/maps`. `/api/khub/documents` lists it as
  `FOs3lXmlcWxBhTIFxVKyGA`, `ug470_7Series_Config.pdf`, v1.17 (2023-12-05), and
  `/api/khub/documents/FOs3lXmlcWxBhTIFxVKyGA/content` returns the PDF. The per-step
  analysis is in [`s0_derived_sequence.md`](s0_derived_sequence.md) §3a, and it changes the
  standing of the sequence substantially — including one finding that a "source
  unobtainable" conclusion would have buried. **Retracting a conclusion is not the same as
  the conclusion having been harmless: it had already been used to justify shipping.**

- **U2 — whether `PCAP_RATE_EN` throttles the *read* direction is not stated.** UG585 says
  "PCAP data transmission" without naming a direction, and every passage describing it —
  the AES data width, "data sent *to* the PCAP interface" — is about the **write**
  direction. The timeout is derived for the pessimistic case (quarter rate applies) and the
  record keeps the measured elapsed time, so the first S1 record settles it as a by-product.

  **The bearing on §7.1 is conditional and the earlier wording overstated it.** *If* the bit
  throttles reads, the PL-side data rate falls and the overflow risk falls with it. *If it
  does not*, the readback runs at full rate and §7.1 stands exactly where it was. Since U2
  is open, **no relief from the overflow stop condition may be claimed** — the earlier
  "overflow risk falls" was an unconditional claim resting on an unresolved premise.
- **U3 — none of C3's four throughput preconditions was checked on `17A6`.** The PCAP clock
  in particular is unmeasured on this board.
