# Stop-loss for the PS line

This repository exists because a different leg of the same question already ran past its
own evidence and had to be stopped. That leg — JTAG-side CRAM readback in
`zynq-fabricmap` — is paused, and its scoped negative result is published. The lesson
that came out of it is the reason this file is written before any runner exists rather
than after the first disappointing result:

> **when the readings stop discriminating, the answer is to publish, not to add more
> instrumentation.**

## What this line is allowed to be about

One question: **does a PS/PCAP-side configuration read return the frame that was
requested, on this die?**

That is an instrument-feasibility question. It is not a scientific claim, it does not
inherit the Claim B preregistration, and a result here — in either direction — is not a
result about map-guided navigation.

## Binding stop conditions

**Any one of S1, S2 or S3 failing ends the PS line.** On such a failure:

1. Stop. No further probe stages are designed, run, or "just checked".
2. Publish a scoped negative result naming what was observed, on which board, under
   which authority, and precisely what it does and does not exclude.
3. The line stays stopped.

There is exactly one thing that may reopen it: **a new mechanism** — a specific,
falsifiable account of why the read behaved as it did, that predicts something different.
**A new instrument is not a new mechanism.** More probes, finer timing, another buffer
strategy, a further register read: all of these are the failure mode, not the remedy.

## What may not be traded away to keep the line alive

- **Zero FDRI in any probe stage.** The one configuration write in a session is the
  canonical setup load; probe stages write no frame data, ever.
- **Fail-closed verdicts.** An undetermined reading is a stop, never a pass. A reading
  the instrument cannot distinguish from an instrument failure is an instrument failure.
- **The board is not touched** until a whole-of-probe authorisation is given. **One
  ruling covers S1-S3; there is no ruling per stage, and it is not a blanket.** It is
  conditional on the chain holding: S2 and S3 run only if every prior stage passed, and
  any failure stops the chain immediately and consumes the ruling. Resuming needs a fresh
  ruling. S0 is host-only and carries no board authorisation at all.

## The control plane this binds

S1-S3 run over a **U-Boot** control plane. The probe runner does not need Linux and is not
authorised to boot it. The Linux identity requirement in `authority_requirements.md` binds
a future PS-guided architecture, not this probe.

## Scope of this file

It binds the PS line only. It does not bind, unblock, or re-open anything in
`zynq-fabricmap`, and it has no bearing on the PL self-evolution work, which does not
depend on this question being answered — only map-guided navigation does.
