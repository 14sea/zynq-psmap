# PCAP readback probe — specification (zynq-psmap owner copy)

> **HOST-SIDE SPECIFICATION ONLY. No implementation, no allowlist entry, and NO BOARD RUN
> is authorised by this document.** Nothing here is evidence.

**This is the maintained specification for the PS/PCAP probe.** It supersedes
[`pcap_readback_probe_spec.md`](pcap_readback_probe_spec.md), which is retained
unmodified as the **archival imported snapshot** — see §M below. Where the two differ,
this document governs; where this document is silent, the snapshot's technical detail
still stands, read through §M's resolution table.

## M. Migration note — 2026-08-28

The snapshot was written inside `zynq-fabricmap` and reads that way: it says "this repo's
own evidence tree", and it cites documents, scripts and evidence records that do not exist
here and were deliberately not imported. Copying those files across would have dragged the
old authority model with them, which is the one thing this split exists to prevent. So the
snapshot is frozen, its hash is checked by `tests/test_import_manifest.py`, and every
reference in it that does not resolve locally resolves here instead, at the frozen source
commit `5ad36a1ca26b42022121f1889172dbe4380b4539`:

| referenced in the snapshot | where it actually resides |
|---|---|
| `docs/claimb_findings.md` | [https://github.com/14sea/zynq-fabricmap/blob/5ad36a1ca26b42022121f1889172dbe4380b4539/docs/claimb_findings.md](https://github.com/14sea/zynq-fabricmap/blob/5ad36a1ca26b42022121f1889172dbe4380b4539/docs/claimb_findings.md) |
| `docs/claimb_preregistration.md` | [https://github.com/14sea/zynq-fabricmap/blob/5ad36a1ca26b42022121f1889172dbe4380b4539/docs/claimb_preregistration.md](https://github.com/14sea/zynq-fabricmap/blob/5ad36a1ca26b42022121f1889172dbe4380b4539/docs/claimb_preregistration.md) |
| `docs/claimb_r4_protocol.md` | [https://github.com/14sea/zynq-fabricmap/blob/5ad36a1ca26b42022121f1889172dbe4380b4539/docs/claimb_r4_protocol.md](https://github.com/14sea/zynq-fabricmap/blob/5ad36a1ca26b42022121f1889172dbe4380b4539/docs/claimb_r4_protocol.md) |
| `docs/evidence_contract.md` | [https://github.com/14sea/zynq-fabricmap/blob/5ad36a1ca26b42022121f1889172dbe4380b4539/docs/evidence_contract.md](https://github.com/14sea/zynq-fabricmap/blob/5ad36a1ca26b42022121f1889172dbe4380b4539/docs/evidence_contract.md) |
| `docs/board_roles.md` | [https://github.com/14sea/zynq-fabricmap/blob/5ad36a1ca26b42022121f1889172dbe4380b4539/docs/board_roles.md](https://github.com/14sea/zynq-fabricmap/blob/5ad36a1ca26b42022121f1889172dbe4380b4539/docs/board_roles.md) |
| `docs/workflow.md` | [https://github.com/14sea/zynq-fabricmap/blob/5ad36a1ca26b42022121f1889172dbe4380b4539/docs/workflow.md](https://github.com/14sea/zynq-fabricmap/blob/5ad36a1ca26b42022121f1889172dbe4380b4539/docs/workflow.md) |
| `scripts/gate_board_identity.py` | [https://github.com/14sea/zynq-fabricmap/blob/5ad36a1ca26b42022121f1889172dbe4380b4539/scripts/gate_board_identity.py](https://github.com/14sea/zynq-fabricmap/blob/5ad36a1ca26b42022121f1889172dbe4380b4539/scripts/gate_board_identity.py) |
| `scripts/precheck_fresh_power.py` | [https://github.com/14sea/zynq-fabricmap/blob/5ad36a1ca26b42022121f1889172dbe4380b4539/scripts/precheck_fresh_power.py](https://github.com/14sea/zynq-fabricmap/blob/5ad36a1ca26b42022121f1889172dbe4380b4539/scripts/precheck_fresh_power.py) |
| `scripts/board_uboot_fpga_load.py` | [https://github.com/14sea/zynq-fabricmap/blob/5ad36a1ca26b42022121f1889172dbe4380b4539/scripts/board_uboot_fpga_load.py](https://github.com/14sea/zynq-fabricmap/blob/5ad36a1ca26b42022121f1889172dbe4380b4539/scripts/board_uboot_fpga_load.py) |
| `evidence/isolate_2026_08_12b/record.json` | [https://github.com/14sea/zynq-fabricmap/blob/5ad36a1ca26b42022121f1889172dbe4380b4539/evidence/isolate_2026_08_12b/record.json](https://github.com/14sea/zynq-fabricmap/blob/5ad36a1ca26b42022121f1889172dbe4380b4539/evidence/isolate_2026_08_12b/record.json) |
| `evidence/cell_fclk50_before_load_2026_08_12/record.json` | [https://github.com/14sea/zynq-fabricmap/blob/5ad36a1ca26b42022121f1889172dbe4380b4539/evidence/cell_fclk50_before_load_2026_08_12/record.json](https://github.com/14sea/zynq-fabricmap/blob/5ad36a1ca26b42022121f1889172dbe4380b4539/evidence/cell_fclk50_before_load_2026_08_12/record.json) |
| `evidence/calibration_noop_2026_08_14_erratum006/record.json` | [https://github.com/14sea/zynq-fabricmap/blob/5ad36a1ca26b42022121f1889172dbe4380b4539/evidence/calibration_noop_2026_08_14_erratum006/record.json](https://github.com/14sea/zynq-fabricmap/blob/5ad36a1ca26b42022121f1889172dbe4380b4539/evidence/calibration_noop_2026_08_14_erratum006/record.json) |
| `evidence/postfault_r4_step1_control_2026_08_16/reading.md` | [https://github.com/14sea/zynq-fabricmap/blob/5ad36a1ca26b42022121f1889172dbe4380b4539/evidence/postfault_r4_step1_control_2026_08_16/reading.md](https://github.com/14sea/zynq-fabricmap/blob/5ad36a1ca26b42022121f1889172dbe4380b4539/evidence/postfault_r4_step1_control_2026_08_16/reading.md) |

Two corrections of standing, not of content:

- Every "this repository" in the snapshot means **`zynq-fabricmap` at `5ad36a1`**, not
  this one. In particular "this repo's own evidence tree" is that repository's tree.
- The four scripts above are **not** to be imported here in order to make a reference
  resolve. They are the authority boundary this repository redesigns; see
  [`authority_requirements.md`](authority_requirements.md).

## 0. The one question

> On **EBAZ4203 `17A6`**, can the PS read one **known non-blank** configuration frame back
> through **PCAP** into DDR, such that the returned 101 words are **bit-exact** against an
> expectation pinned **before the run**?

A capability question about a path. Not a Claim B experiment; a result here in either
direction is not a result about map-guided navigation.

## 1. Control plane — the probe is U-Boot only

**S1–S3 run over a U-Boot control plane, exactly as the snapshot's §3 requires. The probe
runner does not need Linux and is not authorised to boot it.**

This is worth stating plainly because the repository split has an adjacent motivation that
must not be confused with it: a **future PS-guided architecture** will need a Linux control
plane, and `zynq-fabricmap`'s preregistration forbids one by design. That is a statement
about where this line is going, **not a requirement of this probe**. Any runner that boots
Linux to perform S1, S2 or S3 is out of specification.

Consequently the Linux identity/epoch requirement in
[`authority_requirements.md`](authority_requirements.md) is **forward-looking**. It binds
the future architecture. It does not license, and is not needed by, the probe.

## 2. Authorisation model — one conditional ruling over a single chain

**One whole-of-probe board ruling covers S1–S3. There is no ruling per stage**, and there
is no blanket authorisation either. The ruling is conditional on the chain holding:

- S2 and S3 run **only** if every prior stage passed.
- **Any failure at S1, S2 or S3 stops the chain immediately** and consumes the ruling.
  Resuming requires a fresh ruling, not a continuation of the old one.
- **S0 is separate and comes first.** It is host-only and carries no board authorisation
  whatsoever; the board ruling is applied for after S0 has been reviewed by a party that
  did not write it.

### 2a. S0 is split, and the split is stated here rather than assumed

The snapshot's S0 bundles four deliverables: discharge §2b, derive and pin §2c, **write the
runner and its tests**, and reproduce §4. The first review of the host-only work found the
repository calling S0 "delivered" while the runner and the single-`BoardSession`
identity/epoch were explicitly deferred — a contradiction with the specification being
implemented. The stage is therefore split **in this governing document**, not in a status
line:

| gate | state |
|---|---|
| **S0a** | **PASS at `8cb544b`** |
| **§8a** | **technically resolved; independently reviewed: NO** |
| **S0b** | **written at 4e2c032; reviewed: NO** |
| **S0** | **NOT complete** |

What each stage contains:

| stage | contents |
|---|---|
| S0a scope | discharge §2b; derive and pin §2c; reproduce §4 |
| §8a scope | the DMA command shape, resolved in `s0_derived_sequence.md` §8a |
| S0b scope | the runner, one `BoardSession` carrying one identity and one epoch across loader and runner (§5a step 3, §5d.1), and their tests |
| S0 scope | all of the above |

**S0 is complete only when S0b exists AND §8a of `s0_derived_sequence.md` is settled.** The
specification requires the exact sequence to be pinned; leaving two mutually exclusive DMA
shapes for the operator to choose is a research draft and cannot serve as a board gate. No
board ruling may be sought against S0a alone. **§8a is now resolved** and the sequence is
pinned, so what remains between S0a and S0 is **S0b**.

**§8a was resolved host-only on 2026-08-28 — two unidirectional DMA commands, with the
non-active endpoint's length 0. Independently reviewed: NO.** Every commit of that delta
was reviewed by the other co-author, but §8's gate asks for a party that did not write the
thing under test, and both co-authors wrote parts of it; a PASS recorded on 2026-08-29 was
withdrawn on that ground. It is
pinned in the planner rather than left to the operator, and the losing reading is retained
as a named alternative a new run may adopt after any stop. **No observation is claimed to
reveal a wrong pin**: `DMA_CMD_ERR` and `P2D_LEN_ERR` are recorded as candidate diagnoses
only. S0 still awaits **S0b**'s non-author review — the runner and `BoardSession` were
written at `4e2c032` — and, per `line_plan.md` §6 D2, a third-party review of completed S0.

An earlier draft of `stop_loss.md` said authorisation was "per-stage, not blanket". That
was wrong and contradicted the snapshot's §8; it has been corrected. Both documents now say
the same thing, and `tests/test_owner_spec.py` checks that they keep saying it.

## 3. The pinned positive control, re-derived here

Re-derived in this repository against the imported carrier
(`gate_runs/claimb_round1_carrier_2026_08_13_erratum006/carrier.bit`, sha256
`8c3369e8…f0b8a`) by `scripts/diag_pcap_target_select.py`:

| quantity | value |
|---|---|
| frames in the base | 5,144 |
| frame-table digest | `5039aab0c39411251fb3d405788fe5119236d2159528c85bd3bd280e65d6ad21` |
| target FAR | `0x00000b99` |
| target frame sha256 | `9029c9d032e0287453cb5c02cd18be42bc03acef38b17ef7295ee0d16beb6b1f` |
| min Hamming to the four neighbours | 822 |
| target hash globally unique | yes |
| distinct hashes / duplicate groups | 425 / 5 |
| FARs sharing the all-zero hash | 4,716 |

The last row is why a reverse lookup returns a **set**, never a name: a blank frame cannot
identify which blank FAR it came from. The snapshot's §4c and §7 verdict table govern how
that set is read, unchanged.

## 4. Stop conditions

Binding, and stated in [`stop_loss.md`](stop_loss.md) rather than duplicated here.
In summary: any of S1/S2/S3 failing ends the PS line, publishes a scoped negative result,
and only a **new mechanism** — never a new instrument — may reopen it.

## 5. What this document does not do

It does not authorise S0, does not describe the runner (which is host-only and refuses
without a ruling), and does not touch
`zynq-fabricmap`'s state: the Claim B readback leg remains paused and its published
negative result stands.
