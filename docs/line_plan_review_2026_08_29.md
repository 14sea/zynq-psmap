# Review of `line_plan.md` at `e039ebf`

Status: **plan direction accepted; execution order needs correction before the plan is used
to open S0b.** This is a review record, not a replacement specification, a board claim or an
authorisation. `pcap_probe_spec.md` and `stop_loss.md` continue to govern.

## 1. Sources checked

The section references in this review resolve against these immutable snapshots:

| repository / snapshot | commit |
|---|---|
| `zynq-psmap` plan under review | `e039ebfd6f5da7e5e59520c556ad4d1c7c88f0f2` |
| `zynq-fabricmap` | `71666b02d526a6f2c641f1e0aebc15dac0417d4f` |
| `zynq-autoehw` M2 planning sources | `888261329503d3a954fbdadd55bc69b6e17f988c` |
| `zynq-autoehw` `m1-complete` | `b81d37f47960648e5b51ba9ab0867fb91125c960` |
| `zynq-ehw` | `ded7c1cfebd61d32a6b5d9ef5f121b670cdc5e13` |

The three plan-level corrections in §1 are substantively right:

1. S1–S3 test setup-loaded content, not post-write readback.
2. EBAZ work is restricted to content-bit classes; autonomous routing work belongs on the
   sacrificial K7 line.
3. The far-goal research line belongs in a new repository; `zynq-psmap` remains an instrument
   and evidence producer.

The supporting wording should be narrowed on the next plan revision: `zynq-ehw` says future
research should *prefer* a new repository, while `zynq-autoehw` workflow hard rule 5 isolates
source projects from its working copies. The latter is an isolation model, not by itself a
rule that every restart creates a repository.

## 2. Required plan corrections

### R1 — D1 must not block S0b

`pcap_probe_spec.md` §1 and `stop_loss.md` already pin S0b and S1–S3 to U-Boot. S0b's
`BoardSession` implements that current probe contract; it is not the far goal's control-plane
abstraction. Making a future standalone/Linux choice a prerequisite would let P2/P3 reshape
P0 and contradict the repository boundary the plan is trying to preserve.

Correct disposition: defer standalone versus Linux until a concrete P2/P3 architecture exists.
Do not rewrite `authority_requirements.md` or `README.md` now. S0b remains U-Boot-only and may
start independently of D1.

### R2 — D2 is the completed-S0 gate, not residual risk for the board ruling

The governing specification says the board ruling is sought only after S0 has been reviewed by
a party that did not write it. Both current co-authors are ineligible to independently review
the joint §8a delta. Leaving `independently reviewed: NO` in place and transferring that risk
to the S1–S3 ruling would change the governing gate, despite the plan saying the specification
is unchanged.

Correct disposition: finish S0b, then obtain an eligible third-party review of completed S0 as
a whole, including §8a, before seeking any board ruling. If no eligible reviewer is available,
HOLD before board contact. More tests cannot substitute for that review.

### R3 — distinguish a stopped line from a falsified mechanism

`stop_loss.md` correctly stops the line on every S1–S3 failure, including indeterminate
instrument failures. That does not make every stop evidence that Claim P is false. An invalid
identity, unmet precondition, DMA/register error, stale completion or unchanged sentinel says
the observation is not discriminating.

Claim P should name the exact S0-pinned two-unidirectional-DMA sequence. Its falsifiers should
then be limited to attributable payload observations after identity, precondition, completion
and attribution gates pass. Other failures still KILL the P0 line under the existing stop-loss,
but do not establish a physical negative.

### R4 — P1 must place JTAG after both PCAP observations

The JTAG method used to prove landing includes `JSHUTDOWN` and whole-die transitions. It can be
a landing verifier for P1 only if the order is fixed as:

1. baseline PCAP read;
2. one pre-registered content-bit write;
3. post-write PCAP read 1;
4. post-write PCAP read 2;
5. seal and hash both raw buffers;
6. terminal JTAG landing confirmation.

JTAG may not precede or be interleaved with either post-write PCAP read. It is a terminal
after-the-observation verifier, not part of the claimed no-shutdown mechanism. If that check
cannot be kept terminal and separable, P1 is HELD. The phrase “success only with shutdown” must
refer to the PCAP acquisition, not to this terminal verifier.

### R5 — P2 needs an invariant, not literal equality

A live counter should advance; requiring every observable to remain unchanged would reject a
healthy design. P2 must preregister an observable-specific continuity rule: for example, a
counter advances within a pinned envelope, while a stable checksum remains equal. N, tolerances
and a matched no-read baseline/control must be fixed before the run. An unstable or
non-discriminating baseline is HOLD; a causally attributable continuity violation is KILL.

### R6 — replace the source-line ratio with a scope cap

“Tests no more than 2× runner lines” is not a stable control: formatting, file splitting,
generated code and production-code bloat all move the ratio without changing assurance. Keep
the useful part of the proposal instead:

- every S0b test must map to runner, `BoardSession`, identity, epoch, sequencing,
  fail-closed verdict or authority behaviour required by the governing specification;
- status-table/parser/test-aware-mutant guards remain frozen unless a real technical conclusion
  or actual gate state could otherwise be accepted incorrectly;
- three consecutive review deltas with no runner or `BoardSession` behaviour change put S0b on
  HOLD for an owner scope ruling.

## 3. Recommended owner rulings D1–D4

| decision | recommended ruling | effect now |
|---|---|---|
| D1 | **DEFER** standalone versus Linux to P2/P3 | does not block S0b |
| D2 | **THIRD-PARTY REVIEW OF COMPLETED S0 REQUIRED** | after S0b, before board ruling |
| D3 | **RATIFY** the three §1 consequences, with the source wording narrowed as above | accepts the plan boundary |
| D4 | **AUTHORISE HOST-ONLY S0b** under the current U-Boot-only spec and R6 scope cap | no board authority |

Proposed order: D3 owner ratification → host-only S0b under D4 → eligible third-party review
of completed S0 under D2 → application for the existing S1–S3 board ruling. D1 waits for P2/P3.

## 4. Push disposition

Do not treat `e039ebf` alone as the accepted execution order. It is safe to preserve and push
as the authored planning proposal **together with a reviewed correction that resolves R1–R6**;
there is no need to rewrite its history. No S1–S3 or other board work is authorised by either
document.
