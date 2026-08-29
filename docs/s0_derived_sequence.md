# S0 — the derived sequence, pinned

**Host-only. Nothing here has been executed on a board, and this document authorises no
board action.** It discharges `pcap_probe_spec.md` §2c, which required the readback command
words, the DMA register fields, the completion indication, the overflow indication, the DDR
buffer addresses and U-Boot's cache handling to be *derived and pinned before any board
time*. Warrant classes follow [`s0_ug585_discharge.md`](s0_ug585_discharge.md).

**§8a is resolved** (two unidirectional DMA commands, host-only, 2026-08-28) and **§8b
remains UNRESOLVED**. What is still open is not an oversight and must not be defaulted away
by an implementation; see **§8**.

## 1. Register map — [UG585, discharged]

devcfg base `0xF8007000`.

| offset | register | use here |
|---|---|---|
| `0x000` | `CTRL` | read-only gate (§4) |
| `0x00C` | `INT_STS` | completion and every error bit |
| `0x014` | `STATUS` | queue/FIFO observation |
| `0x018` | `DMA_SRC_ADDR` | written 1st |
| `0x01C` | `DMA_DEST_ADDR` | written 2nd |
| `0x020` | `DMA_SRC_LEN` | written 3rd |
| `0x024` | `DMA_DEST_LEN` | written 4th — **the write that queues the command** |
| `0x080` | `MCTRL` | read-only loopback gate (§5a-bis) |

`0xF8007000` and `0xF800700C` and `0xF8007014` already appear in this board's committed
fresh-power precheck, at `0x4E00E07F`, `0xA802000B`, `0x40000A30`.

**The order is normative** [N3]: UG585 says "It is important that the parameters are
programmed in the exact sequence as described", and the command "is accepted when this
register [`DMA_DEST_LEN`] is written to".

## 2. The endpoint pseudo-address — [UG585, discharged]

A PCAP endpoint is addressed as **`0xFFFF_FFFF`**, verbatim from *Configure the PL via PCAP
Bridge Example*: "Destination Address: 0xFFFF_FFFF." For a readback the PCAP is the source.

## 3. The readback command words — [UG470, discharged]

Obtained from the content API as a *document* rather than a map:
`/api/khub/documents/FOs3lXmlcWxBhTIFxVKyGA/content` → `ug470_7Series_Config.pdf`,
**v1.17, 2023-12-05**. Chapter 6, *Configuration Memory Read Procedure (SelectMAP)*, is the
governing procedure and Table 6-2 gives the words.

```
FFFFFFFF   dummy
AA995566   sync
20000000   NOOP
20000000   NOOP
30008001   Type-1 WRITE CMD, 1 word     <- UG470 step 6: RCFG first
00000004   RCFG
20000000   NOOP                         <- step 6's "and write one NOOP command"
30002001   Type-1 WRITE FAR, 1 word     <- UG470 step 7: the FAR comes after
00000B99   the pinned target FAR
28006000   Type-1 READ FDRO (reg 3), 0 words    <- step 8
480000CA   Type-2 READ, 202 words
20000000   x32  packet-buffer flush (UG470 step 9)
```

43 words. The Type-2 encoding is confirmed directly against UG470: Table 6-2's own
`482BA521` is "Type 2 Read 2,860,321 Words from FDRO", and `0x48000000 | 0x2BA521` is
exactly that — so `0x48000000 | 202` = `0x480000CA` is the same arithmetic.

Header arithmetic, machine-checked in `tests/test_s0_pcap_plan.py`:

| word | decode |
|---|---|
| `30002001` | Type-1, write, register 1 (`FAR`), count 1 |
| `30008001` | Type-1, write, register 4 (`CMD`), count 1 |
| `28006000` | Type-1, read, register 3 (`FDRO`), count 0 |
| `480000CA` | Type-2, read, count `0xCA` = 202 |

**The word count is UG470's own formula, not an assumption.** Step 8:
*"FDRO Read Length = (words per frame) x (frames to read + 1). One extra frame is read to
account for the frame buffer. The frame buffer produces one dummy frame at the beginning of
the read."* With one frame to read: 101 x 2 = **202**. The specification's §6a could only
call the pad "not established"; it is now vendor-documented, and `words[101:202]` is the
correct slice for reasons that no longer depend on the HWICAP precedent.

### 3a. Every UG470 step, and whether this probe performs it

The procedure has 15 steps and this probe performs 9 of them. **The six omissions are not
oversights and they are not free**; each is listed with its reason and its cost.

| UG470 step | here | why |
|---|---|---|
| 1 bus-width detect + sync | **sync only** | The `000000BB` / `11220044` pattern exists so an 8/16/32-bit SelectMAP bus can be discovered. PCAP is a fixed 32-bit interface — UG585: the bridge "converts 32-bit AXI formatted data to the 32-bit PCAP protocol". There is no width to detect. |
| 2 ≥1 NOOP | yes (two) | |
| **3 SHUTDOWN + NOOP** | **NO** | Spec §5c forbids "any startup transition", and UG470 itself says **"DONE goes Low during the shutdown sequence"**. UG585 separately forbids a readback until `INT_STS[2] PCFG_DONE` asserts. Issuing SHUTDOWN would break the governing specification *and* fight the vendor's own precondition. |
| **4 RCRC + NOOP** | **NO** | Belongs to the shutdown flow; recomputing a CRC over a device that was never shut down has no meaning here. |
| **5 five NOOPs for shutdown to complete** | **NO** | There is no shutdown to complete. |
| 6 RCFG + NOOP | yes | issued **before** the FAR, per Table 6-2; see §3c |
| 7 FAR | yes | after RCFG, with the target FAR rather than `0x00000000` |
| 8 FDRO header, length = 101 x (1+1) | yes | 202 |
| 9 32 dummy words | yes | 32 NOOPs, and they are counted in `SRC_LEN` |
| 10 read FDRO, same length | yes | the receive DMA |
| 11 one NOOP | yes | in the cleanup stream |
| **12 START + NOOP** | **NO** | A startup transition (§5c), and meaningless without step 3. |
| **13 RCRC + NOOP** | **NO** | Same. |
| 14 DESYNC | yes | the cleanup stream; the engine is left desynchronised |
| 15 ≥64 bits NOOP; CCLK until DONE High | NOOPs yes; the DONE clause no | "until DONE goes High" is the recovery from step 3's DONE-Low, which never happened. |

### 3b. The cost of those omissions — stated, because it is the probe's weakest joint

**UG470 documents no non-shutdown configuration-memory readback for SelectMAP.** The
procedure above is the only one it gives, and this probe deliberately does not follow it.

The deviation is *required* — §5c forbids startup transitions, and the whole point of this
line is to read configuration memory **without** the perturbation that ended the JTAG leg
(`JSHUTDOWN` disturbs the state under test). So it is not a free choice. But it has a
consequence that must be carried into the specification's §9:

> **If S1 fails, "a readback without SHUTDOWN is not sufficient on this silicon" is a live
> explanation, and this probe cannot exclude it.**

A negative result from this probe is therefore about *this sequence*, not about PCAP
readback in general. Recording that before the run is the whole point of §9 existing.

### 3c. RCFG before FAR — and a divergence from the measured order, recorded not resolved

UG470 orders steps 6 and 7 as **`CMD = RCFG`, one `NOOP`, then the `FAR`**, and Table 6-2
lists the words in exactly that order: *Type 1 Write 1 Word to CMD / RCFG Command / Type 1
NOOP Word 0 / Type 1 Write 1 Word to FAR*.

**An earlier version of this document emitted `FAR` first and still claimed the sequence was
discharged against UG470. It was not, and review caught it.** The vendor order now governs.

The other order is not imaginary, and pretending it is would be the same mistake in reverse:
`zynq-fabricmap`'s
[ICAPE2 document](https://github.com/14sea/zynq-fabricmap/blob/5ad36a1ca26b42022121f1889172dbe4380b4539/docs/claimb_icape2_readback_sequence.md)
§4c records **FAR → RCFG → NOOP → FDRO(0) → Type-2** as `[MEASURED]`, from an HWICAP
readback that **worked on this silicon**. So there are two orders with two different
warrants:

| order | warrant | used here |
|---|---|---|
| `RCFG`, `NOOP`, `FAR` | **[UG470]** Table 6-2, the primary source | **yes** |
| `FAR`, `RCFG`, `NOOP` | **[MEASURED]** on XC7Z010, over HWICAP, in another project | no |

The primary source wins for a probe whose whole standing is "discharged against the
vendor documentation". But the measured order is a **named alternative**, and if S1 returns
`NO_MATCH` it is the first thing a *new run* — never a retry inside one (§7.4) — should
vary. Recording it now is what stops that from being improvised later.

**Word order.** SelectMAP order, **not** bit-reversed. The `br8` reversal in
`zynq-fabricmap`'s
[ICAPE2 document](https://github.com/14sea/zynq-fabricmap/blob/5ad36a1ca26b42022121f1889172dbe4380b4539/docs/claimb_icape2_readback_sequence.md)
is a property of the ICAPE2 primitive's `I`/`O` pins; PCAP consumes bitstream-order words.
That document's independently `[MEASURED]` shape **diverges from** UG470 steps 6-7 in the
order of `RCFG` and the `FAR` — see §3c, which is where that divergence is adjudicated. The
corroboration it does provide is narrower: that a `FAR`/`RCFG`/`FDRO(0)`/Type-2 *transaction*
returns frame data at all on this silicon. It is not a warrant for the ordering, and the
sentence that previously said it agreed with UG470 contradicted §3c and Table 6-2.

## 4. `CTRL` — the masked-bit gate (§5e)

| | |
|---|---|
| required mask | **`0x0C000000`** — bit 27 `PCAP_PR`, bit 26 `PCAP_MODE` |
| required value under that mask | **`0x0C000000`** (both set) |
| historical full word on `17A6` | `0x4E00E07F` — recorded, **never required** |

Nothing else is required. In particular **bit 25 `PCAP_RATE_EN` is deliberately NOT in the
mask**: `17A6` has it set (quarter rate) with `SEC_EN` clear, which UG585 calls "allowed but
not recommended" rather than wrong, and *Configure the PL via PCAP Bridge Example* would
have non-secure mode clear it. Clearing it is exactly the "reconfigure the engine so the
probe works" that §5e forbids. It is **recorded as an observation** and the timeout below
absorbs its cost.

## 5. Completion and error — [UG585, discharged]

**Completion is `INT_STS[12] D_P_DONE`, not `INT_STS[13] DMA_DONE`.**

UG585 on bit 13: "The bit is set either as soon as DMA is done (**PCAP may not be
finished**) or both DMA and PCAP are done." Bit 12: "Both DMA and PCAP transfers are done."
A readback judged on bit 13 alone can be read before the data has arrived. [N4] gives the
same warning from the address side: only with `SRC_ADDR[1:0] = DST_ADDR[1:0] = 2'b01` is
`DMA_DONE` held until both interfaces finish.

**Both are used**: the `01` tag is set on the DDR-side address *and* the wait is on bit 12.
Two independent expressions of one requirement, because either alone has a documented way
of being weaker than it looks.

**Every error bit is checked after every transfer**, per the vendor's own list:

| bit | name | |
|---|---|---|
| 23 | `AXI_WTO` | AXI write timeout |
| 22 | `AXI_WERR` | AXI write response error |
| 21 | `AXI_RTO` | AXI read timeout |
| 20 | `AXI_RERR` | AXI read response error |
| **18** | **`RX_FIFO_OV`** | **the §2c overflow bit** — "Incoming read data from PCAP will be dropped and the DevC DMA may enter an unrecoverable state" |
| 15 | `DMA_CMD_ERR` | illegal DMA command |
| 14 | `DMA_Q_OV` | command queue overflow |
| 11 | `P2D_LEN_ERR` | inconsistent PCAP-to-DMA length |
| 6 | `PCFG_HMAC_ERR` | HMAC error from the PL |

Error mask **`0x00F4C840`**. Any bit set → STOP (§7.1). The stop condition is now
pre-committed against **identified** bits, which is what §2c demanded.

### 5a. Stale status must be cleared and the clear verified — before every read

`INT_STS` bits are **write-to-clear** (`wtc` in UG585's type column). A `D_P_DONE` left over
from an earlier transfer is bit-for-bit indistinguishable from a completion of *this* one,
so a runner that only polls would read a stale bit and declare success before the DMA had
started. Spec §5d.5 already requires "clear and then verify stale DMA completion/error
status"; this is what it means concretely:

```
mw.l 0xF800700C 0x00F4F840      # clear mask
md.l 0xF800700C 1               # (INT_STS & clear mask) must now read 0, or STOP
```

**Per DMA command, without exception — including the cleanup stream.** An earlier version
cleared once, before the first command. Under `two-unidirectional` the `D_P_DONE` left by
the command transfer would then have satisfied the readback transfer's wait *immediately*,
and the buffer would have been read out before the readback happened — an instrument that
reports a completion that did not occur. The cleanup stream had neither a clear nor a wait,
so `DESYNC` was never known to have been delivered. The hazard is per-command, so the clear,
its verification and the wait are per-command.

**Clear mask `0x00F4F840`** = every error bit, plus `D_P_DONE` (12) and `DMA_DONE` (13).
**`PCFG_DONE` (bit 2) is deliberately excluded**: it is the evidence that the PL holds the
carrier, and [N1] forbids a readback without it. Clearing it would destroy the precondition
in the act of preparing to check it.

### 5a-bis. `MCTRL[PCAP_LPBK]` is read, and a set bit is a STOP

`MCTRL` is at **`0xF8007080`** (`XDCFG_MCTRL_OFFSET = 0x80`) and `PCAP_LPBK` is **bit 4**,
mask **`0x10`** (`XDCFG_MCTRL_PCAP_LPBK_MASK`).

With loopback enabled, PCAP data is looped from the RxFIFO back through the TxFIFO, so the
data path is not PL frame readback. The cited sources do not establish the exact result of
combining this probe's 43-word command transfer with its 202-word read request while
loopback is enabled. AMD's readback path clears the bit on every call, and UG585's
*Configure the PL* example clears it before a configuration transfer. §5e forbids
adjusting, so this probe **reads** it and refuses to proceed:

```
md.l 0xF8007080 1               # (MCTRL & 0x10) must be 0, or STOP before any DMA
```

**The reset value being 0 does not substitute for the live read.** It is writable mode
state — the driver writes it in both directions, *enabling* it for
`XDCFG_CONCURRENT_NONSEC_READ_WRITE` and *clearing* it for the secure variant — so anything
earlier in the boot may have left it set. This is the same argument as §5e's for `CTRL`: a
historical or documented value is an expectation, not a reading.

Without this gate, a loopback-enabled run would use the wrong data path. Depending on
behavior not established by the cited sources for the unequal transfer lengths, it could
stop as `NO_MATCH`, an error, or a timeout. None is a positive match, but the record could
misleadingly blame the table or sequence when the true cause was a mode bit nobody looked
at. Naming it costs one read.

### 5b. Configuration-engine cleanup, after the read

Spec §5d.5's second half. A short second command stream — `NOOP`, `CMD = DESYNC`
(`0x0000000D`), two `NOOP`s — leaves the engine desynchronised, which is UG470 step 14.
UG470's steps 12 and 13 (`START`, `RCRC`) are **not** issued; see §3a.

**Precondition [N1]:** `INT_STS[2] PCFG_DONE` must be asserted before any readback. At fresh
power `INT_STS` reads `0xA802000B`, in which bit 2 is **clear** — so this is a real gate that
the §5a carrier load is what satisfies.

**RxFIFO context [N5]:** `STATUS[24:20] RX_FIFO_LVL` maxes at **31** words. The 202-word
readback is 6.5x the entire FIFO, so it completes only because the DMA drains it
continuously. This is why C2's bandwidth warning is not theoretical and why no retry is
permitted after an overflow.

## 6. Buffers, alignment and cache

| | address | words |
|---|---|---|
| command buffer | `0x1020_0000` | 43 |
| destination buffer | `0x1030_0000` | 202 |

Both are 1 MiB aligned, hence **64-byte aligned** as [N2] requires, and neither transfer can
cross a 4 KiB boundary (172 B and 808 B). They sit in the same DDR region this board already
uses in committed runs — `board_uboot_axi.py` pins `0x1000_0000` and `0x1010_0000` on `17A6`
— at distinct offsets, so neither collides with that work nor with the `0x0400_0000` carrier
load address.

**These addresses are not warranted by a datasheet and do not need to be.** §5b's sentinel
prefill is written and read back before any DMA is programmed, so an address that is not
usable DDR fails at the prefill verify, before anything is queued. That is the fail-closed
property; the addresses are a choice, the verification is the guarantee.

**Cache — and a trap worth naming.** U-Boot on this platform runs with the D-cache enabled.
The sentinel is written with `mw` and read with `md`, both through the cache; the DMA writes
DDR without going through it. A DMA that lands correctly would therefore be **invisible** to
`md`, which would return the still-cached sentinel — and the runner would report
`BUFFER_UNCHANGED_FROM_PREFILL`, a §7 stop, on a *successful* read. The instrument would
manufacture exactly the null result this line already has one of.

Pinned: **`dcache off` before the sentinel prefill**, so the prefill, the DMA and the readout
all see DDR; U-Boot's `dcache off` flushes as it disables. `dcache` is queried and its state
recorded in the stage record. This is a CPU cache setting, not a configuration write; §5c is
untouched.

### 6a. Transactions and streams, not fields — what the checker adjudicates

Three rounds of review each broke a checker that was correct field by field. The lesson is
that **individually legal values combine into illegal operations**, so the unit of
adjudication is the whole transaction and the exact stream, and the per-value sets that
kept being extended are gone.

**Whole DMA transactions.** The four normative register writes are reassembled into a tuple
`(SRC_ADDR, DEST_ADDR, SRC_LEN, DEST_LEN)`, closed by the `DMA_DEST_LEN` write that queues
the command. **Exactly four tuples are legal**, and nothing else is a transaction:

| | SRC_ADDR | DEST_ADDR | SRC_LEN | DEST_LEN |
|---|---|---|---|---|
| command | `CMD_BUF\|1` | `0xFFFFFFFF` | 43 | 43 |
| readback | `0xFFFFFFFF` | `DST_BUF\|1` | 202 | 202 |
| bidirectional | `CMD_BUF\|1` | `DST_BUF\|1` | 43 | 202 |
| cleanup | `CMD_BUF\|1` | `0xFFFFFFFF` | 5 | 5 |

Why a set of legal *addresses* plus a range of legal *lengths* was not enough: every field
of `SRC=DST_BUF|1, DEST=CMD_BUF|1, SRC_LEN=202, DEST_LEN=202` is drawn from those sets, and
the transaction swaps the roles so the readback overwrites the command buffer while reading
202 words out of a 43-word source. Registers written out of order, or a tuple left open, are
errors rather than something skipped.

**Exact streams.** Both configuration streams are reconstructed from the command-buffer
writes and checked position by position:

| | words | shape |
|---|---|---|
| readback | 43 | dummy, sync, NOOP×2, `CMD`+`RCFG`, NOOP, `FAR`+target, `FDRO(0)`, Type-2(202), NOOP×32 |
| cleanup | 5 | NOOP, `CMD`+`DESYNC`, NOOP×2 |

Position-by-position is what a packet-by-packet walk could not do: a `FAR` write with no
payload, a `Type-1 read CMD` where the `FDRO` read belongs, a Type-2 asking for 1 word
instead of 202, a `FAR` write with `count=2` — all parse as packets and all are structurally
wrong. **The target FAR is pinned at word 8**, so a stream that reads a different frame
cannot be produced.

**`mw.l`'s repeat count is expanded.** A single `mw.l CMD_BUF 0x20000000 43` really fills the
buffer with 43 NOOPs; a reconstruction that recorded one word saw a stream that was never
sent. Each stream must also **begin at the buffer base and be contiguous** — a gap means
words the checker never saw would still reach the engine.

**The validators are written as literals and explicit positions, not by calling this module's
own packet builders.** A stream checked against the generator that produced it proves only
that the generator is self-consistent; the literals are UG470 Table 6-2's.

Two per-register policies remain, because they are genuinely about a single write: `CTRL`
and `STATUS` are **read-only** here (§5e), and `INT_STS` may be written **only** with the
exact clear mask `0x00F4F840`.

### 6b. The schedule — legal parts can still be an illegal run

Validating each transaction and each stream in isolation says nothing about the **order**
they execute in, and review assembled four whole plans out of individually legal parts:

| assembled from legal parts | what it would do |
|---|---|
| the main transfer's tuple replaced by a second `cleanup` | the readback never happens |
| an extra legal `cleanup` appended | a third transfer nobody accounted for |
| the cleanup stream written into the command buffer **before** the main DMA | both phases still look like `[43, 5]`, but the transfer that fires sends the wrong stream |
| a legal `INT_STS` clear slipped between the `DMA_DEST_LEN` trigger and the wait | erases the completion being waited for — a manufactured timeout on a transfer that succeeded |

So the whole run is checked as a schedule. It is **derived from the commands, never from
`step` names**, which a plan is free to lie about, and compared against one exact expected
sequence:

```
CACHE  READ_CTRL  READ_INT_STS  FILL_DST  READ_DST  CMD_STREAM(43)
  [ CLEAR  READ_INT_STS  SRC_ADDR DEST_ADDR SRC_LEN DEST_LEN  READ_INT_STS ]  x1 or x2
READ_DST  CMD_STREAM(5)
  [ CLEAR  READ_INT_STS  SRC_ADDR DEST_ADDR SRC_LEN DEST_LEN  READ_INT_STS ]
READ_INT_STS
```

The four register writes are contiguous by construction of that sequence, and **nothing may
sit between the `DMA_DEST_LEN` trigger and the wait** — that gap is exactly where a clear
would erase the completion. The transaction *sequence* is pinned by name as well:

| order | transactions, in order |
|---|---|
| `two-unidirectional` | `command`, `readback`, `cleanup` |
| `one-bidirectional` | `bidirectional`, `cleanup` |

**The sentinel is an operand, not an abstraction.** The destination prefill's token is
`("FILL_DST", value, 202)` and the schedule requires that value to equal the sentinel the
plan records. Abstracting every correctly-sized destination write to a bare `FILL_DST`
discarded the one thing §6c depends on: a plan could serialize a prefill of zero — making
*"the DMA never wrote"* and *"the engine returned zeros"* the same bytes, which is the
distinction §6c exists to preserve — or serialize one pattern while recording another, so
the verdict table would adjudicate against a pattern that was never written.

The sentinel must also be **`1 .. 0xFFFFFFFF`**, not merely non-zero. `mw.l` writes 32 bits,
so `0x100000000` truncates on the board to **exactly the excluded value**: a range check
that refuses only zero would have let the zero prefill back in through the other end.
`check_sentinel` is the single place that decides this, and both `build_plan` and
`expected_schedule` call it.

Consecutive command-buffer writes collapse into one `CMD_STREAM(n)` token counting the
**words actually written**, so a bulk `mw.l ... 43` cannot masquerade as a single word. A
command that is neither a scheduled read nor a scheduled write is an error, in both
directions — an earlier version tested only the read side, and making the write branch fail
open survived the whole suite. Deleting **any** single step of either plan is refused, which
the tests check exhaustively rather than by sampling.

## 7. Timeout — derived, not measured (§6b)

808 bytes at UG585's ≈145 MB/s is ≈**5.6 us**; at quarter rate (U2, unresolved) ≈**22 us**.
The pinned budget is **1 second** from the `DMA_DEST_LEN` write — more than 45,000x the
pessimistic derivation, chosen so that it can only ever be exceeded by something structural
rather than by a mis-estimated rate, and because the polling itself crosses a 115200 baud
link. Recorded as **derived, not measured** until an S1 record carries a real elapsed time.

## 8. §8a resolved; §8b still open, and not to be defaulted

### 8a. Whether a readback is one bidirectional DMA command or two — **RESOLVED: two**

**Resolved 2026-08-28, host-only. Independently reviewed: NO.** Every commit from
`d0ba146` to `77e29a5` was reviewed by the other of the two co-authors, and each round
found real defects in the other's work. That is cross-review, not the review this
specification asks for: §8 requires "the party that did not write it", and **no party
independent of both has reviewed the §8a delta as a whole**, because both wrote parts of
it. A PASS recorded on 2026-08-29 was withdrawn for exactly that reason.

The documents do **not** settle the question; what settles it is stated below, and the
losing reading is kept as a named alternative rather than deleted.

#### The evidence, exhausted

UG585 contradicts itself:

- *PL Bitstream Readback*: "**Two DMA accesses are required** to complete a PL configuration
  readback. The first access is used to issue the readback command to the PL configuration
  module. The second access is needed to read the PL bitstream from the PCAP."
- *Example: PL Bitstream Readback*, headed "This example shows **the first DMA access**",
  then lists all four registers across both directions: source = the command sequence,
  destination = "Desired location to store readback bitstream", source length = number of
  commands, destination length = "Number of readback words expected from the PL".

**The contradiction is in the source, not in the extraction.** The retrieved topic's raw
markup is a single `<ol>` of four `<li>` items under that one heading; there is no second
table or column that a text conversion could have flattened away. If the first access
already carried the readback destination and its length, the second access would have
nothing left to do.

**No other AMD *document* adjudicates it.** UG470 is silent on the PS-side DMA — it stops at
the SelectMAP/ICAP interface — and the documentation portal carries **no `devcfg`/`XDcfg`
driver documentation**: the three `UG643` collections and `UG821` were searched topic by
topic (4,107 topics) with no hit. **What does adjudicate it is not a document but AMD's
driver source**, which is a different warrant class and is treated as one below.

#### An argument for "two" that does NOT work, recorded because it looked decisive

*"A single command with `src = CMD_BUF` and `dst = DST_BUF` names no PCAP endpoint at all,
and `0xFFFFFFFF` is how a transfer says it involves the PCAP — so the bidirectional reading
cannot express a readback."*

**That argument fails.** PCAP loopback is a **mode bit**, `MCTRL[INT_PCAP_LPBK]`, which the
*Configure the PL via PCAP Bridge Example* explicitly clears before a transfer. Because the
mode is a bit and not an addressing convention, a DDR→DDR command with loopback disabled
could perfectly well mean "stream the source out through the PCAP and capture what comes
back". The `0xFFFFFFFF` marker does not carry the weight this argument put on it.

#### What does settle it — AMD's own driver

**Corrected 2026-08-28 after review.** An earlier version of this section argued from
UG585's *Configure the PL via PCAP Bridge Example*: one PCAP endpoint, source and
destination lengths both equal to the word count, and "candidate A is that shape twice".
**That argument was wrong, and its conclusion about the lengths was wrong with it.**
Configuration is a *write*; nothing licenses generalising its non-active-endpoint length to
a readback. The tuples it produced refused the vendor's own and permitted tuples no vendor
implementation issues.

What settles it is the vendor's implementation of this exact operation. `XDcfg_PcapReadback()`
in AMD's `embeddedsw`
([`xdevcfg.c`](https://github.com/Xilinx/embeddedsw/blob/cbc5280400e7f08e35203d0dbd6bf09922049361/XilinxProcessorIPLib/drivers/devcfg/src/xdevcfg.c),
commit `cbc5280`) issues **two** DMA commands and sets the **non-active endpoint's length to
zero**:

```c
XDcfg_InitiateDma(InstancePtr, SourcePtr, XDCFG_DMA_INVALID_ADDRESS, SrcWordLength, 0);
while (... & XDCFG_IXR_D_P_DONE_MASK) != XDCFG_IXR_D_P_DONE_MASK);   /* wait */
XDcfg_InitiateDma(InstancePtr, XDCFG_DMA_INVALID_ADDRESS, DestPtr, 0, DestWordLength);
```

`XDCFG_DMA_INVALID_ADDRESS` is `0xFFFFFFFF` (`xdevcfg_hw.h`). The register-readback example
([`xdevcfg_reg_readback_example.c`](https://github.com/Xilinx/embeddedsw/blob/cbc5280400e7f08e35203d0dbd6bf09922049361/XilinxProcessorIPLib/drivers/devcfg/examples/xdevcfg_reg_readback_example.c))
ends with a cleanup transfer of the same shape: `(&CmdBuf[0], XDCFG_DMA_INVALID_ADDRESS,
CmdIndex, 0)`.

Three things follow, and the third is a **retraction**:

1. **Two commands**, confirming the direction — and the driver waits on `D_P_DONE` between
   them, which is independently what §5 pins.
2. **The non-active length is 0**, so the tuples are as tabulated below.
3. **The bidirectional reading is not adopted by the vendor's readback API** — and that is
   the whole of what this evidence supports. **Corrected after review:** an earlier version
   said the driver "contradicts" it. It does not. *"AMD's readback API chooses two
   unidirectional transfers"* is not *"the hardware rejects a bidirectional tuple"*; a path
   a driver does not implement is not a path the silicon refuses.

   The same version also called `XDCFG_CONCURRENT_SECURE_READ_WRITE` and
   `XDCFG_CONCURRENT_NONSEC_READ_WRITE` "loopback" as a pair. **That is wrong too**, and the
   source says so plainly: the **non-secure** path *enables* `MCTRL[PCAP_LPBK]`, while the
   **secure** path *clears* it (and sets `CTRL[PCAP_RATE_EN]`, which independently
   corroborates §2a's reading of bit 25). They are concurrent read/write transfer types with
   different loopback handling, and neither is the readback path.

**Warrant class.** This is vendor **code**, not UG585 prose — a different class from §2a/§2b,
and it is labelled as such wherever it is relied on. It is nonetheless the strongest evidence
available for the vendor-supported readback transaction shape, because it is the vendor
implementation performing the operation in question, and UG585's own text cannot adjudicate
itself. It does not establish every transaction shape the engine might accept.

**Pinned:**

| | SRC_ADDR | DEST_ADDR | SRC_LEN | DEST_LEN |
|---|---|---|---|---|
| 1 command | `CMD_BUF\|tag` | `0xFFFFFFFF` | 43 | **0** |
| 2 readback | `0xFFFFFFFF` | `DST_BUF\|tag` | **0** | 202 |
| 3 cleanup | `CMD_BUF\|tag` | `0xFFFFFFFF` | 5 | **0** |

The `tag` is §8b's open question and is unchanged by this.

#### What a wrong pin would look like — candidate diagnoses, NOT a proof of detectability

**Narrowed 2026-08-28 after review.** An earlier version said a wrong pin would *necessarily*
show up as `DMA_CMD_ERR` or `P2D_LEN_ERR` and concluded that "neither reading can fail
silently". **That was an overclaim and it is withdrawn.** UG585's `INT_STS` table gives each
bit a general meaning; it does **not** establish that `src = 0xFFFFFFFF` with a wrong length
raises `DMA_CMD_ERR`, nor that unequal lengths in one command raise `P2D_LEN_ERR`. The causal
mapping was mine, not the document's.

What can be said, and no more:

| if the pin is wrong | plausible indication |
|---|---|
| the engine rejects the command | `INT_STS[15] DMA_CMD_ERR` — "Illegal DMA command" |
| lengths inconsistent with what PCAP returns | `INT_STS[11] P2D_LEN_ERR` — "Inconsistent PCAP to DMA transfer length error" |

Both remain **generic stops** already in the error mask, and both are recorded as **candidate
diagnoses**. They are not exclusive, not necessary, and **no claim is made that a wrong pin
cannot fail silently.** A wrong pin could equally produce a timeout, a `NO_MATCH`, or a
`BLANK` — all of which are already stops, which is the actual safety property here: every
outcome except a bit-exact match halts the probe.

**The alternative is retained, not deleted**, and it is the first thing a **new run** — never
a retry inside one (§7.4) — should vary. It may be adopted after **any** stop, not only after
a particular error bit; tying it to one bit would smuggle the withdrawn causal claim back in
through the procedure. Its standing is lower than when §8a was opened, because the vendor's
readback API does not use it — which is weaker than the silicon refusing it, and is stated
that way.

### 8b. The `2'b01` tag when one endpoint is `0xFFFF_FFFF` — **UNRESOLVED**

[N4] requires `SRC_ADDR[1:0]` **and** `DST_ADDR[1:0]` to be `2'b01` for `DMA_DONE` to be held
until PCAP is finished. Under candidate A's second command the source *is* the PCAP
pseudo-address, whose low bits are `11`, and UG585 does not say what happens to the
completion semantics then. The plan therefore tags **only the DDR-side address** and relies
on `D_P_DONE` (§5), which is documented without reference to the tag. This is consistent, but
it is a derivation, not a discharge, and it stands or falls with 8a.

## 9. Scope — this is S0a, and S0 is NOT complete

**The governing specification's S0 has four deliverables**: discharge §2b, derive and pin
§2c, **write the runner and its tests**, and reproduce the §4 target selection. Three are
done. **The runner is written at `4e2c032`** (`scripts/pcap_probe_runner.py`), together
with the single `BoardSession` carrying one identity and one epoch across loader and runner
(§5a step 3, §5d.1; `scripts/board_session.py`) — **not yet reviewed by a non-author**.

An earlier version of this document deferred those "to the board-authorised work" while the
rest of the repository described this stage as finished. That was a contradiction with the
specification it claims to implement, and review caught it. The stage is therefore named
honestly:

| gate | state |
|---|---|
| **S0a** | **PASS at `8cb544b`** |
| **§8a** | **technically resolved; independently reviewed: NO** |
| **S0b** | **written at 4e2c032; reviewed: NO** |
| **S0** | **NOT complete** |

| | |
|---|---|
| S0a scope | the host-only derivation |
| S0b scope | the runner, one `BoardSession` carrying one identity and one epoch, and their tests |
| why S0 is open | S0b does not exist |

`docs/pcap_probe_spec.md` §2 carries the same split, so the two documents agree.

**§8a was that precondition and it is now resolved** — the sequence is pinned rather than
left to the operator, and the losing reading is retained only as a named alternative for a
new run. The resolution is **technically settled but not independently reviewed**: every
commit was cross-reviewed by the other co-author, and neither co-author can supply the
independent review §8 requires. What remains between here and S0 is **S0b**, and an
independent review of §8a.
