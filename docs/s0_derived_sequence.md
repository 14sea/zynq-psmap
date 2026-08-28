# S0 — the derived sequence, pinned

**Host-only. Nothing here has been executed on a board, and this document authorises no
board action.** It discharges `pcap_probe_spec.md` §2c, which required the readback command
words, the DMA register fields, the completion indication, the overflow indication, the DDR
buffer addresses and U-Boot's cache handling to be *derived and pinned before any board
time*. Warrant classes follow [`s0_ug585_discharge.md`](s0_ug585_discharge.md).

Two items are pinned as **UNRESOLVED**. They are not oversights and they must not be
defaulted away by an implementation; see **§8**.

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

## 8. UNRESOLVED — pinned as open, and not to be defaulted

### 8a. Whether a readback is one bidirectional DMA command or two — **UNRESOLVED**

UG585 contradicts itself and S0 cannot settle it from the document:

- *PL Bitstream Readback*: "**Two DMA accesses are required** to complete a PL configuration
  readback. The first access is used to issue the readback command … The second access is
  needed to read the PL bitstream from the PCAP."
- *Example: PL Bitstream Readback*, describing "**the first DMA access**", then programs all
  four registers across both directions at once: "Source Address: Location of PL readback
  command sequence. Destination Address: Desired location to store readback bitstream. Source
  Length: Number of commands … Destination Length: Number of readback words expected from
  the PL."

If the first access already carries the readback destination and its length, the second
access has nothing left to do. The two passages cannot both be literally right.

**Candidate A — two unidirectional commands**

| | SRC_ADDR | DEST_ADDR | SRC_LEN | DEST_LEN |
|---|---|---|---|---|
| 1 | `0x10200001` | `0xFFFFFFFF` | 43 | 43 |
| 2 | `0xFFFFFFFF` | `0x10300001` | 202 | 202 |

**Candidate B — one bidirectional command**

| | SRC_ADDR | DEST_ADDR | SRC_LEN | DEST_LEN |
|---|---|---|---|---|
| 1 | `0x10200001` | `0x10300001` | 43 | 202 |

`scripts/pcap_probe_plan.py` implements both and **has no default**: the ordering must be
named explicitly or the planner refuses. Choosing one silently is the failure this project
keeps re-encountering, and a wrong choice here is not benign — C2 says a split readback
produces "data loss and unexpected DMA behavior", and an overflow is "unrecoverable".

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
done. **The runner is not written**, and neither is the single `BoardSession` carrying one
identity and one epoch across loader and runner (§5a step 3, §5d.1).

An earlier version of this document deferred those "to the board-authorised work" while the
rest of the repository described this stage as finished. That was a contradiction with the
specification it claims to implement, and review caught it. The stage is therefore named
honestly:

| | |
|---|---|
| **S0a — host-only derivation** | delivered here, **not yet reviewed** |
| **S0b — runner, `BoardSession`, identity/epoch, tests** | **not started** |
| **S0** | **NOT complete**, and cannot be until S0b exists and §8a is settled |

`docs/pcap_probe_spec.md` §2 carries the same split, so the two documents agree.

**Even with S0b written, S0 does not pass while §8a is open.** The specification requires the
exact sequence to be *pinned*; two mutually exclusive DMA shapes with the choice left to the
operator is a research draft, not a gate. Resolving §8a is a precondition for S0, not a
footnote to it.
