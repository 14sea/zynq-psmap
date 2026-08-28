# Authority and session model — requirements, NOT an implementation

**Nothing here is implemented. No code in this repository performs a board action, and
none may be added under M0.** This file exists so that the requirement below is on
record before a runner is designed, rather than being rediscovered by whoever writes it.

## Why the source repo's module was not imported

`zynq-fabricmap`'s `scripts/gate_board_identity.py` pins `CONTROL_PLANE = "uboot"` and its
`authorise_write()` refuses a `linux` control plane outright. That refusal is correct
*for that repository*: its preregistration says that booting Linux after verifying
identity invalidates the authorisation.

The PS line will need Linux **eventually — for the PS-guided architecture, not for this
probe.** The probe itself (S1-S3) is U-Boot-only, exactly as the specification requires,
so on the probe alone the two repositories' control planes agree; the divergence is in
where this line is going. The wrong way to get there is to import that module and
delete the refusal — that keeps the shape of a safety property while removing the
property. So the module was not imported at all, and the boundary is redesigned here.

## The required split — FORWARD-LOOKING, and not a requirement of the probe

**Read this first: none of the following is needed by S1-S3.** The PCAP probe runs
U-Boot-only. What follows binds the future PS-guided architecture, which is the reason
this repository could not live under a preregistration that forbids a Linux control plane.
A probe runner that establishes a Linux identity is out of specification, not compliant.

Authority is **per control plane**, not a single session identity that survives a
transition:

1. **U-Boot identity + epoch.** Established under U-Boot, valid for U-Boot operations
   only.
2. **Linux identity + epoch.** Established independently under Linux, valid for Linux
   operations only.
3. **Crossing a control plane unconditionally invalidates the previous authority.** It is
   not renewed, extended, or inherited. A new identity must be established on the far
   side before any operation is authorised there.

A Linux epoch is therefore never a continuation of a U-Boot epoch. Re-establishing
identity after the transition is the whole point; an implementation that carries a token
across the boundary has not implemented this requirement.

## Known open engineering, inherited from the specification

The specification's §5a requires identity to be established **before** the setup load,
and §5d requires loader and runner to share one session and epoch. In the source
repository they did not: the loader and the runner each opened their own serial session,
and the loader performed no identity check of any kind. **S0 owns resolving this or
pinning the boundary explicitly** — it is a change to be delivered, not a description of
anything that exists.
