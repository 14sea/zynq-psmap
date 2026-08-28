# Import manifest — M0

Everything in this repository that was not written here was copied, byte for byte, from
one frozen commit of one other repository. This file records exactly what, from where,
and with which hash, so that any later drift is detectable rather than arguable.

## Frozen source

| field | value |
|---|---|
| source repository | `github.com/14sea/zynq-fabricmap` (public, Apache-2.0) |
| source commit | `5ad36a1ca26b42022121f1889172dbe4380b4539` |
| source commit subject | `spec: the sentinel verdicts name an observation, not a mechanism` |
| source commit date | 2026-08-27 |
| import date | 2026-08-28 |

At import time that commit was the source repository's `origin/main` and its working tree
was clean.

## Imported files

Every file below is **byte-identical** to the source. No imported file was edited during
the import. Paths are unchanged as well — including
`gate_runs/claimb_round1_carrier_2026_08_13_erratum006/`, which reads oddly here but is
kept deliberately: `scripts/diag_pcap_target_select.py` hardcodes that path as
`DEFAULT_BIT`, so preserving it is what makes "zero edits" true, and the directory name
is itself provenance — it names the gate run that produced this carrier.

| path (identical in source and here) | sha256 | bytes |
|---|---|---|
| `docs/pcap_readback_probe_spec.md` | `ffbaf327c88bb9643e060822eab023f5b3849fbb268e51fed10e191099e3fcef` | 32460 |
| `scripts/diag_pcap_target_select.py` | `d9b7f0a5af18c2cc9ce0578d589e115fba67b3acc2f308e569d6b9523f9021ef` | 7754 |
| `scripts/bitstream_frames.py` | `a55246e68e082cbb7d15833e6da134388059ffdb0497c29634a9b740eb9091b3` | 14956 |
| `tests/test_pcap_probe_target.py` | `23babdc24c7c0456b35deb9cda55d031fa0ab4f277fece1ccbeb223465f706a2` | 10648 |
| `data/prjxray/zynq7/xc7z010/tilegrid.json` | `db16874f2827fc05248ad4a7ef5769deaa8e70158a60c8dd40194c48713479ee` | 4351137 |
| `data/prjxray/zynq7/xc7z010clg400-1/part.yaml` | `43a136f26603c51bd97e9489d223bbc80f278fcc234225ed9fde404402f22683` | 11766 |
| `gate_runs/claimb_round1_carrier_2026_08_13_erratum006/carrier.bit` | `8c3369e8e4755da5aceeb7844690d5e132b2e65647004c0a46c0e868e34f0b8a` | 2083863 |
| `LICENSE` | `75efa07c4d2afb14d8226cf00b7763dd2ec1c5585a9dfe919881a3a3fef2ddac` | 11357 |
| `data/prjxray/LICENSE` | `a2010f343487d3f7618affe54f789f5487602331c0a8d03f49e9a7c547cf0499` | 7048 |

`tests/test_import_manifest.py` re-hashes every file listed above against this table, so
the manifest is a machine-checked claim and not a comment.

### The carrier is stored here as an ordinary Git object, not LFS

In the source repository `carrier.bit` is tracked by **Git LFS**, so what its commit
stores is a 132-byte pointer whose `oid sha256` is the content hash
`8c3369e8…f0b8a`. Here the file is committed as an ordinary blob of the full 2,083,863
bytes, and that blob hashes to the same value.

This is a deliberate deviation and the only one in the import. A single 2 MB object is not
weight worth an LFS dependency, and a repository whose entire purpose is that a pinned
positive control can be re-derived should not require a second fetch mechanism to hand
over the file the control is measured against. Verifying the import against the source
therefore means comparing to the **LFS object**, not to the pointer the commit stores —
`git cat-file blob <commit>:<path>` returns the pointer and will appear to disagree.

### The Project X-Ray licence travels with its data

`data/prjxray/LICENSE` is the CC0-1.0 text that governs `data/prjxray/`. The source
repository states explicitly that the vendored database subset is **not** relicensed by
the top-level Apache licence, so importing the data without its licence would have
misrepresented the terms of everything under that directory. `NOTICE` and the README now
carry the same split, and the carrier bitstream carries the source repository's
qualification: an exact reproducibility artifact, with no rights claimed in its vendor
components.

### Three files added to the agreed list, and why

The migration decision named five artefacts plus the licence. Three more were required and
are included:

- `data/prjxray/zynq7/xc7z010/tilegrid.json`
- `data/prjxray/zynq7/xc7z010clg400-1/part.yaml`
- `data/prjxray/LICENSE` (see above)

`scripts/bitstream_frames.py` reads both — `part.yaml` for the device's configuration
column layout in FAR order, `tilegrid.json` for the containment cross-check. Without them
the target derivation cannot run at all, so importing the script without them would have
produced exactly the failure this manifest exists to prevent: pinned constants carried
across with no way to re-derive them.

## Re-derivation, performed in this repository

`python3 scripts/diag_pcap_target_select.py`, run here against the imported carrier,
reproduced every pinned value:

| quantity | required | obtained here |
|---|---|---|
| frames in the base | 5,144 | 5,144 |
| frame-table digest | `5039aab0c39411251fb3d405788fe5119236d2159528c85bd3bd280e65d6ad21` | identical |
| target FAR | `0x00000b99` | identical |
| target frame sha256 | `9029c9d032e0287453cb5c02cd18be42bc03acef38b17ef7295ee0d16beb6b1f` | identical |
| min Hamming to the four neighbours | 822 | 822 |
| target hash globally unique | true | true |
| distinct hashes / duplicate groups / all-zero coverage | 425 / 5 / 4,716 FARs | identical |
| `tests/test_pcap_probe_target.py` | 17 pass | 17 pass |

## Files original to this repository (M0)

The imported set above and the set below are **exhaustive between them**: every tracked
file in this repository appears in exactly one of the two.
`tests/test_import_manifest.py` enforces that as an equality against `git ls-files`, in
both directions, so a file cannot enter this repository undeclared — whatever directory it
is put in.

These are authored here, evolve here, and are therefore listed by path rather than by
hash; the imported set is the one that must never move. The last four are S0's
deliverables and arrived after M0; the section keeps its name because the closure rule,
not the stage label, is what it enforces.

| path |
|---|
| `.gitignore` |
| `NOTICE` |
| `README.md` |
| `requirements.txt` |
| `docs/authority_requirements.md` |
| `docs/import_manifest.md` |
| `docs/pcap_probe_spec.md` |
| `docs/stop_loss.md` |
| `tests/test_import_manifest.py` |
| `tests/test_owner_spec.py` |
| `docs/s0_ug585_discharge.md` |
| `docs/s0_derived_sequence.md` |
| `scripts/pcap_probe_plan.py` |
| `tests/test_s0_pcap_plan.py` |

## Deliberately NOT imported

These were named as things to leave behind, and they were left behind. They are not
absent by oversight; each is a boundary this repository has to redesign rather than
inherit.

| not imported | why |
|---|---|
| `scripts/gate_board_identity.py` | carries the source repository's U-Boot-only write authority. Importing it would drag in `board_uboot_axi.py` and the carrier guard, and would copy across the very authority model this split exists to separate. |
| `scripts/board_uboot_axi.py` | transitive dependency of the above. |
| `scripts/precheck_fresh_power.py` | part of the session/authority boundary S0 must design, not inherit. |
| `scripts/board_uboot_fpga_load.py` | same. |
| the four historical evidence records | referenced below by immutable URL. They are historical observations, not executable gates; this repository must make its own live observation before relying on any of them. |

### The `CTRL` observation, referenced rather than copied

The specification cites `CTRL == 0x4e00e07f` on board `17A6`. Those records stay in the
source repository and are cited as immutable blobs at the frozen commit:

- https://github.com/14sea/zynq-fabricmap/blob/5ad36a1ca26b42022121f1889172dbe4380b4539/evidence/isolate_2026_08_12b/record.json
- https://github.com/14sea/zynq-fabricmap/blob/5ad36a1ca26b42022121f1889172dbe4380b4539/evidence/cell_fclk50_before_load_2026_08_12/record.json
- https://github.com/14sea/zynq-fabricmap/blob/5ad36a1ca26b42022121f1889172dbe4380b4539/evidence/calibration_noop_2026_08_14_erratum006/record.json
- https://github.com/14sea/zynq-fabricmap/blob/5ad36a1ca26b42022121f1889172dbe4380b4539/evidence/postfault_r4_step1_control_2026_08_16/reading.md

A value read on another day, on hardware this repository has not yet touched, is a prior
and not a gate.
