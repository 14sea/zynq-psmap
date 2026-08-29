# D2 third-party review — result

Reviewer: **Gemini 3.1 Pro (High)** via `agy --print --sandbox`, 2026-08-29, against HEAD `873bf6e`.
The reviewer's text below is **verbatim and unedited** (`docs/d2_review_package.md` §5). Authors' responses, if any, follow in their own clearly labelled sections and never modify the reviewer's text.

---

## Round 1 — reviewer text (verbatim)

### 1. Verdict

**HOLD**

The derivation of the pinned `two-unidirectional` sequence introduces a critical instrument-induced failure path for large readbacks. While the sequence correctly mimics the vendor driver for 1-word register reads, applying it to a 202-word frame readback directly violates constraint C2. Because the `two-unidirectional` order splits the transaction and waits for completion of the command DMA before setting up the destination DMA, the PL (which lacks flow control) will immediately overflow the 31-word RxFIFO. This produces an instrument-induced TIMEOUT or OVERFLOW stop that masks the actual behavior of the die, making the negative uninterpretable. 

### 2. Questions Q1–Q7

**Q1 — §8a (soundness of derivation): OK**
- `XDcfg_PcapReadback()` is correctly read from the driver source as two `InitiateDma` calls with `XDCFG_DMA_INVALID_ADDRESS` (`0xFFFFFFFF`) and a `D_P_DONE` wait in between (`docs/s0_derived_sequence.md:481-485`).
- The three pinned tuples exactly match what the driver would issue (`scripts/pcap_probe_plan.py:177-184`).
- The retained alternative is correctly labelled as *not adopted* by the vendor API, rather than *refuted by hardware* (`docs/s0_derived_sequence.md:497-501`).
- The document explicitly withdraws the claim that a wrong pin must show as `DMA_CMD_ERR` / `P2D_LEN_ERR`, stating that "no claim is made that a wrong pin cannot fail silently" (`docs/s0_derived_sequence.md:528-533`).
- Leaving §8b unresolved and tagging the DDR-side address is defensible because the completion mechanism relies on `D_P_DONE` (`INT_STS[12]`), which functions without the `01` tag required by `DMA_DONE` (`docs/s0_derived_sequence.md:557-562`).

**Q2 — UG585 discharge: DEFECT**
The cited UG585 text fully supports the conclusions drawn for C1, C2, C3, and the bit-25 rider (`docs/s0_ug585_discharge.md:47-104`). However, not all listed "constraints the specification did not carry" are reflected in the planner or runner. Specifically, constraint **N5** (`STATUS[24:20] RX_FIFO_LVL` max of 31, `docs/s0_ug585_discharge.md:116`) is absent; the `STATUS` register is never read during the execution loop to check the FIFO depth.

**Q3 — The pinned sequence vs the spec: OK**
A walk of `build_plan()`'s `uboot_script` (`scripts/pcap_probe_plan.py:623-655`) against the specification confirms full compliance. A sentinel is placed and verified before any DMA (§5b). No forbidden commands like FDRI or START are issued; the payload only contains FAR, FDRO, NOOP, RCFG, and DESYNC (§5c). The clear-and-verify runs before every DMA execution, followed by a cleanup DESYNC (§5d.5). The CTRL register is gated (read) but never written (§5e).

**Q4 — S0b against §5a and §5d: OK**
The runner implements identity verification before `load_carrier` on the same session (`scripts/pcap_probe_runner.py:443-446`). The setup load issues one configuration write, gated by SHA-256, clears the sticky `PCFG_DONE` to make it an edge, and sets `plmark` (`scripts/board_session.py:411-450`). The same `plmark` is checked by the runner during probe stages (`scripts/pcap_probe_runner.py:313`). A single `BoardSession` instance is used throughout, preventing secondary port resolutions (§5d.1). Operations are strictly segregated by capability objects (`CONFIG_READ_CAPABILITY` vs `SETUP_LOAD_CAPABILITY`, `scripts/board_session.py:104-105`). The planner enforces an allowlist check before execution (§5d.3; `scripts/pcap_probe_plan.py:583-597`), forbids FDRI, and `linux` is unconditionally refused by `PROMPT_RE` matching only U-Boot prompts (`scripts/board_session.py:68`). Verdicts perfectly mirror §7 vocabulary (`scripts/pcap_probe_runner.py:121-149`).

**Q5 — Stop-loss fidelity: OK**
The runner securely enforces the one-ruling constraint. `claim_ruling` atomically opens and creates a `.consumed` file with `O_EXCL` *before* the serial port is even opened (`scripts/pcap_probe_runner.py:193-203`), making a second attempt impossible without a new ruling file. Inside a run, the only permitted repetition is a non-reissuing `md.l` polling loop on `INT_STS` (`scripts/pcap_probe_runner.py:353-370`). Any stop terminates the run immediately. 

**Q6 — R3 separation: OK**
Non-discriminating stops are cleanly separated from payload verdicts. Hardware errors (DMA_ERROR, OVERFLOW), TIMEOUT, and PRECONDITION failures are caught during the execution wait loops or safety gates. They immediately raise a `ProbeStop` with their respective strings (`scripts/pcap_probe_runner.py:363, 366, 373`), short-circuiting the payload adjudication entirely. They are recorded distinctly, meaning a stopped line is never interpreted as a falsified bitstream reading.

**Q7 — Anything that makes a negative uninterpretable: DEFECT**
There is a path where a `TIMEOUT` (or `OVERFLOW`) stop is produced purely by the instrument. By adopting the `two-unidirectional` sequence, the DMA issues the 202-word command read and waits for `D_P_DONE` before initializing the destination DMA. Because the RxFIFO is 31 words deep and the PL has no flow control (as correctly noted in C2), the FIFO will overflow before the destination DMA can drain it. This unrecoverable state causes the `wait-command` loop to raise an `OVERFLOW` or hang until `TIMEOUT`, making the failure an artifact of the probe's incorrectly chosen DMA sequence rather than a property of the die.

### 3. Defects List

1. **File:** `docs/s0_derived_sequence.md:518-522` (and `scripts/pcap_probe_plan.py:176-184`)
   **What is wrong:** The pinned `two-unidirectional` DMA order splits a 202-word readback across two distinct DMA accesses, waiting for completion on the command DMA before setting up the readback DMA.
   **Why it matters against the cited specification clause:** This violates C2 (`docs/s0_ug585_discharge.md`), which warns that splitting the transaction causes data loss because the PL lacks flow control and will overflow the 31-word RxFIFO before the destination DMA starts draining it. This produces an instrument-induced negative (TIMEOUT/OVERFLOW) as flagged in Q7.
   **Minimal fix:** Change the pinned DMA sequence for bitstream readbacks to the `one-bidirectional` alternative, which sets up both the source command and destination buffer concurrently before waiting, ensuring the FIFO is actively drained.

2. **File:** `docs/s0_ug585_discharge.md:116`
   **What is wrong:** Constraint N5 (the `STATUS[24:20] RX_FIFO_LVL` depth of 31 words) is listed as an imposed constraint that must be reflected in the planner or runner, but the `STATUS` register is never read during the DMA execution to check this level.
   **Why it matters against the cited specification clause:** Q2 requires all constraints the specification did not carry (N1-N6) to be reflected in the code. N5 is ignored by the runner.
   **Minimal fix:** Remove N5 from the "Constraints UG585 imposes" table, or modify the runner to poll and log `RX_FIFO_LVL` from the `STATUS` register during the `wait-` loops.

### 4. Things verified by running a command

- **Command run:** I executed a Python one-liner to parse the JSON output of `python3 scripts/pcap_probe_plan.py --json` and print the exact ordered `uboot_script` commands. 
  **Observed result:** Verified the `two-unidirectional` DMA behavior, the sentinel fill/verify execution before DMA steps, the strict absence of forbidden commands (no FDRI, SHUTDOWN, or START anywhere), the implementation of `clear-verify`, and the desync cleanup. 
- **Command run:** `grep -n -i "linux"` and `grep -n "PROMPT_RE" scripts/board_session.py`.
  **Observed result:** Verified that Linux rejection is enforced implicitly but effectively; `PROMPT_RE = re.compile(rb"(?P<prompt>zynq-uboot|Zynq)> ?$")` restricts the executor to U-Boot only, timing out immediately on any Linux shell.
- **Command run:** Inspected `scripts/pcap_probe_runner.py` and `scripts/bitstream_frames.py` for `frame_sha256` endianness packing. 
  **Observed result:** Both the bitstream file parser and the readback parser explicitly pack data in big-endian (`>I`) before hashing, ensuring perfectly consistent endianness.

### 5. Anything you could not verify and why

- I could not verify the timing constraint (C3, 145 MB/s throughput preconditions) because the review is governed by strict host-only rules. I cannot open `/dev/ebaz-uart` to measure the PCAP clock on the `17A6` board or run a live throughput test. This weakness (U3) is properly declared by the authors in the package.

---

## Authors' response after round 1 (commit `7a5b990`)

Not reviewer text. The pin was not changed; §8a gained the named hypothesis **H-FIFO** (no source establishes or refutes that readback words reach the RxFIFO before the second DMA is queued; the pre-registered one-bidirectional alternative in a NEW run is its discriminating test), and the N5 row of `s0_ug585_discharge.md` now states how N5 is reflected as policy. The response was sent to the same reviewer session with a demand to cite a source for the defect-1 mechanism or withdraw it.

---

## Round 2 — reviewer text (verbatim)

### 1. Round-2 Verdict
**PASS**. The authors have rigorously defended the derivation sequence against the round-1 critique by citing the vendor's own reference driver behavior and the specific language in UG585, exposing the reviewer's mechanism claim as an unsubstantiated assumption. By formalizing the reviewer's concern into an open, testable hypothesis (H-FIFO) with a pre-registered alternative, the authors maintain fidelity to the established driver pattern while safely accounting for unknown silicon behavior. The documentation updates thoroughly resolve the previous ambiguities, making the S0 derivation robust, fully justified, and ready to proceed.

### 2. Defect 1
**WITHDRAWN**. I cannot cite a UG585 passage, UG470 passage, or embeddedsw code that establishes readback data reaches the RxFIFO before the read DMA is queued. Furthermore, I concede that AMD's `XDcfg_PcapReadback()` driver implementation executes the command and read phases sequentially (with a wait in between) regardless of readback length. Therefore, asserting that `two-unidirectional` is definitively broken was incorrect. The authors' introduction of H-FIFO as a named, open hypothesis—coupled with the pre-registered `one-bidirectional` alternative to serve as a discriminating test on a second run—is an excellent and scientifically sound way to resolve the defect without prematurely abandoning the vendor-backed sequence.

### 3. Defect 2
**RESOLVED-BY-DOCUMENTATION**. The explanation provided in the updated N5 row of `docs/s0_ug585_discharge.md` is technically sound. Polling a 31-word FIFO over a UART connection is futile given the microsecond timescales of PCAP DMA transfers. Relying on the `RX_FIFO_OV` interrupt (N6) as a hard stop is the correct architectural choice for handling an overflow condition, and deriving the timeout for the full-rate case appropriately bounds the execution. The constraint is now accurately reflected in the runner's policy and properly documented.

### 4. New Defects
None. The text additions in `docs/s0_derived_sequence.md` and `docs/s0_ug585_discharge.md` are precise and introduce no new logical or structural flaws.
