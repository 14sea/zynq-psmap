# zynq-psmap

A host-only question, asked separately from the repository it came out of:

> **does a PS/PCAP-side configuration read return the frame that was requested, on this
> die?**

## Status — M0, migration only

| | |
|---|---|
| stage | **M0 — migration layer complete** |
| board | **not touched, and not authorised** |
| S0 (runner, identity/session, DMA order) | **not authorised, not started, not implemented** |
| S1–S3 (on silicon) | **not authorised** |
| tests | 35 (17 imported + 18 M0 guards) |

Nothing in this repository performs a board action. There is no runner. The imported
specification describes stages that have not been authorised.

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
python3 -m unittest discover -s tests     # 35 tests
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
