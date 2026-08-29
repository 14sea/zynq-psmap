# P2 board run #2 under ruling `whole-of-probe P2` 2026-08-29-02 — console link reset at read 3

**Outcome: `REFUSED: no U-Boot prompt after 'md.l 0x10300000 0xca'`** on the sentinel-verify
readout of the third PCAP read (`P2_3_read_2`, never recorded). The reply stopped after
2,624 of the usual 3,335 bytes (41 of 51 lines, cut mid-line at `10300270 … \r\n10`); no
prompt followed within the read window. **Not a P2 verdict.** A missing prompt is a session
refusal by specification: the epoch ended, the identity was cleared, nothing was re-sent
(§2b re-reads only a *malformed* reply — this was a *missing* one), and the ruling is consumed.

## What the board did (all as specified)

| step | observed |
|---|---|
| session | precheck 5/5; identity; SHA gate; `PCFG_DONE` edge; `plmark`; epoch 0 until the cut |
| `P2_0_fclk` | 1600 / 8 / 4 = **50.000 MHz** |
| `P2_1_baseline`, `P2_2_control` (30 s) | `STATUS 0x00000080`, others 0; control stable |
| `P2_3_read_0‥1` | two PCAP reads of `0x00000B99`, both `PASS`, observable unchanged after each |
| `P2_3_read_2` | cut during the sentinel-verify `md.l` (before the read's DMA) |

## Cause: the host's USB path, not the board

`dmesg` at the failure time: `vhci_hcd: unlink->seqnum … urb->status -104` ×3 — the
usbip/vhci link (WSL ← Windows usbipd) reset in-flight URBs; the remaining bytes of the
burst were lost below pyserial and cannot be recovered on the host. The CH340 had
re-enumerated as USB device 19 at the power cycle (the documented brownout behaviour).
Run #1 (18:51) lost one line of a burst; run #2 (19:02) lost the tail of a burst; before
18:24's re-attach, 32 such bursts in three runs had no loss. Two rulings have now been
consumed by the console link.

## Disposition

No specification change is proposed here. §2b's re-read stays limited to malformed
replies; a missing prompt must remain a session refusal, because it is indistinguishable
from a reboot from the host's side. What should change is the link: re-attach / re-bind
the CH340 on the Windows side (a different USB port or cable if available), then prove the
link clean **before** the next ruling with a transport soak that touches no PL and no DMA —
that soak is itself a board interaction and needs the owner's explicit authorisation. The
board was left at the U-Boot prompt with the carrier configured and `0x00400A20` blank.
