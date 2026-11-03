# Prior art

Added 2026-11-03 after a full-text literature review and a check against AMD
documentation. This repo makes no novelty claim; this file records what it builds on.

| What this repo does | Prior work / vendor documentation | Status |
|---|---|---|
| PS-side PCAP readback of configuration frames | AMD UG585 (Device Configuration Interface) and the AMD driver's `XDcfg_PcapReadback()`, which this repo already cites for its §8a reading | **Vendor feature** |
| Readback as an integrity check of configuration memory | AMD readback CRC and the SEM IP (UG470 v1.17, *Readback CRC*); essential bits (XAPP538 v1.0, algorithm not published) | **Vendor practice**; SEM checks CRC/ECC, it does not report frame identity against a request |
| Frame location from an open database | prjxray (`data/prjxray/`, CC0) | Inherited |
| Verifying that a requested frame comes back bit-exact, and that the read does not perturb the running design (P1, P2), under preregistered gates | No published equivalent found in the 2026-11 search (provisional) | What this repo adds is the **evidence practice and instrument**, not a readback mechanism |

Related caveats found during the review (they apply to the sibling ICAP lines, not to
this repo's PCAP path): HWICAP read FIFO depth is selectable 128/256 (PG134), ICAPE2
max clock 100 MHz (DS187 v1.21), and UG470 ABORT rules for read/write turnaround.

References: AMD UG585 v1.15, UG470 v1.17, XAPP538 v1.0 (2012), PG134 v3.0, DS187 v1.21.
