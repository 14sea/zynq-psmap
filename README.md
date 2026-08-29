# zynq-psmap

A host-only question, asked separately from the repository it came out of:

> **does a PS/PCAP-side configuration read return the frame that was requested, on this
> die?**

## Status — S0a passed at `8cb544b`; §8a technically resolved, not independently reviewed; S0b written, not reviewed

| gate | state |
|---|---|
| **S0a** | **PASS at `8cb544b`** |
| **§8a** | **technically resolved; independently reviewed: NO** |
| **S0b** | **written at 4e2c032; reviewed: NO** |
| **S0** | **NOT complete** |

| | |
|---|---|
| board | **not touched, and not authorised** |
| S0a scope | §2b discharged against UG585; §2c derived and pinned against UG585 **and UG470**; planner + guards; §4 target selection reproduced |
| §8a content | resolved host-only 2026-08-28: two unidirectional DMA commands with the non-active endpoint's length 0, as AMD's `XDcfg_PcapReadback()` issues; the losing reading is retained as an alternative a new run may adopt after any stop |
| S0b scope | the runner, one `BoardSession` carrying one identity and one epoch across loader and runner, and their tests |
| what blocks S0 | S0b |
| S1–S3 (on silicon) | **not authorised** |
| tests | see the command below |

Nothing in this repository performs a board action without a whole-of-probe ruling.
The runner (`scripts/pcap_probe_runner.py`, written at `4e2c032`) refuses to open a port
unless a ruling file naming board `17A6` exists, and it consumes that ruling on any stop;
`tests/test_s0_pcap_plan.py` asserts by AST that the planner imports nothing that could
open a port. The imported specification describes stages that have not been authorised,
and no ruling has been issued.

**S0 is not complete and this repository does not claim it is.** The specification's S0
includes writing the runner and the single `BoardSession` that carries one identity and one
epoch across loader and runner; those are S0b, written at `4e2c032` under the host-only
authorisation in [`docs/line_plan.md`](docs/line_plan.md) §6 D4 and **not yet reviewed by a
non-author**. The split is
recorded in [`docs/pcap_probe_spec.md`](docs/pcap_probe_spec.md) §2a, in the governing
document rather than in a status line.

S0a's two documents are [`docs/s0_ug585_discharge.md`](docs/s0_ug585_discharge.md) — what
UG585 actually says, and the six constraints it imposes that the specification did not
carry — and [`docs/s0_derived_sequence.md`](docs/s0_derived_sequence.md), which pins the
command words, the DMA registers, the completion and overflow bits, the buffers and the
cache handling. **§8a is resolved** — a readback is two unidirectional DMA commands, which
is what AMD's own `XDcfg_PcapReadback()` issues — and the planner defaults to that pinned
reading. **§8b is still pinned UNRESOLVED** rather than defaulted.

## Why this is a separate repository

The work was split out of [`zynq-fabricmap`](https://github.com/14sea/zynq-fabricmap) for
one substantive reason, not for tidiness: **the two lines have incompatible authority
models.** `zynq-fabricmap`'s Claim B preregistration pins the control plane to U-Boot and
refuses a Linux control plane by design. The PS line will need Linux. Two mutually
exclusive authorisation rules sharing one script tree is how a fail-closed gate gets
driven around by accident.

Two consequences follow, and both are deliberate:

- The authority modules were **not** imported. See
  [`docs/authority_requirements.md`](docs/authority_requirements.md) — the boundary is
  redesigned here as U-Boot identity+epoch, Linux identity+epoch, and unconditional
  invalidation on crossing. Deleting the old refusal was not an option.
  **That split is forward-looking: the probe itself (S1–S3) is U-Boot-only** and needs no
  Linux identity. On the probe alone the two repositories' control planes agree; the
  divergence is in where this line is going, which is precisely what a preregistration
  forbidding Linux cannot accommodate.
- This line carries **its own stop-loss** from before it has any results. See
  [`docs/stop_loss.md`](docs/stop_loss.md). The readback leg it descends from was stopped
  because it kept adding instruments; a new instrument is not a new mechanism.

## What this does not block

The PL self-evolution work does **not** depend on this question. On-chip per-evaluation
evolution and a beats-random result on silicon were both obtained without a solved CRAM
readback. What a solved readback buys is **navigation** — map-guided versus random, which
is Claim B's actual claim. If the PS line fails, only navigation waits.

## Which specification is which

| file | standing |
|---|---|
| [`docs/pcap_probe_spec.md`](docs/pcap_probe_spec.md) | **the maintained specification.** Self-contained, owned here, carries the migration note and resolves every reference the snapshot cannot. |
| [`docs/pcap_readback_probe_spec.md`](docs/pcap_readback_probe_spec.md) | **archival imported snapshot**, byte-identical to the source and hash-checked. Read through the migration note; its "this repository" means `zynq-fabricmap` at `5ad36a1`. |

## Provenance

Every non-original file was copied byte-for-byte from `zynq-fabricmap` at commit
`5ad36a1ca26b42022121f1889172dbe4380b4539`, and the target derivation was re-run here and
reproduced 5,144 frames, digest `5039aab0…6ad21`, and target FAR `0x00000b99`. The full
record, including what was deliberately left behind, is
[`docs/import_manifest.md`](docs/import_manifest.md) — machine-checked by
`tests/test_import_manifest.py`.

```
python3 -m unittest discover -s tests
python3 scripts/pcap_probe_plan.py --dma-order two-unidirectional
python3 scripts/diag_pcap_target_select.py
```

## License

Original project content is licensed under the Apache License, Version 2.0; see
[`LICENSE`](LICENSE) and [`NOTICE`](NOTICE). The vendored Project X-Ray database subset in
`data/prjxray/` remains under its accompanying **CC0-1.0** terms — retained verbatim at
[`data/prjxray/LICENSE`](data/prjxray/LICENSE) — and is **not** relicensed by the top-level
Apache license. The Vivado-generated bitstream under `gate_runs/` is retained as an exact
reproducibility artifact; no rights are claimed in its vendor components, and Vivado itself
and the AMD documentation cited here are not redistributed.
