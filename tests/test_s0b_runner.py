"""S0b — the runner and the single `BoardSession`, exercised against a fake U-Boot.

Scope cap (`docs/line_plan.md` §4 P0, R6): every test here names the specification
behaviour it checks — runner sequencing, `BoardSession` identity/epoch, the fail-closed
verdicts, or the authority entry point. No test touches a serial port; `FakeUBoot` models
the console, the memory the plan touches, and enough of devcfg to complete a DMA.
"""

from __future__ import annotations

import hashlib
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import board_session as bsn  # noqa: E402
import pcap_probe_plan as pp  # noqa: E402
import pcap_probe_runner as pr  # noqa: E402

TABLE = pr.load_frame_table()
FRAMES = TABLE["frames"]
INT_STS, CTRL, MCTRL = pp.REG["INT_STS"], pp.REG["CTRL"], pp.REG["MCTRL"]
DMA = {k: pp.REG[k] for k in pp.DMA_WRITE_ORDER}
PROMPT = b"\r\nZynq> "


class FakeUBoot:
    """A console with a memory map and a devcfg whose DMA delivers a frame to DDR.

    The readback model: when a DMA with dst = DST_BUF|1 and dst_len = 202 is queued, the
    fake writes 101 pad words (zero) followed by the frame at the FAR that the command
    stream in CMD_BUF named — unless `deliver` overrides what lands. `D_P_DONE` is set on
    every queued DMA; INT_STS is write-to-clear.
    """

    def __init__(self, *, boardid="17A6", role="verify", idcode=0x03722093,
                 ctrl=0x4E00E07F, mctrl=0x0, int_sts=0xA802000B, deliver=None,
                 complete=True, error_bits=0, prompt=b"Zynq> "):
        self.env = {"boardid": boardid, "role": role}
        self.mem: dict[int, int] = {CTRL: ctrl, MCTRL: mctrl, INT_STS: int_sts,
                                    0xF8007014: 0x40000A30, 0xF8000170: 0x00400800,
                                    bsn.SLCR_PSS_IDCODE: idcode}
        self.deliver = deliver          # callable(far) -> 202 words, or None
        self.complete, self.error_bits = complete, error_bits
        self.prompt = prompt
        self.sent: list[str] = []
        self.pending: list[int] = []
        self.banner_on: set[str] = set()
        self.loaded = False

    # -- helpers ------------------------------------------------------------------
    def word(self, addr):
        return self.mem.get(addr, 0)

    def far_in_cmd_buf(self):
        # the word after the FAR write header (0x30002001) is the FAR the stream named
        words = [self.mem.get(pp.CMD_BUF + 4 * i, 0) for i in range(pp.CMD_STREAM_WORDS)]
        return words[words.index(pp.W_FAR_WRITE1) + 1]

    def queue_dma(self, src, dst, src_len, dst_len):
        if dst == pp.DST_BUF | pp.DMA_HOLD_TAG and dst_len == pp.READBACK_WORDS:
            far = self.far_in_cmd_buf()
            words = (self.deliver(far) if self.deliver
                     else [0] * pp.FRAME_WORDS + FRAMES[far])
            for i, w in enumerate(words):
                self.mem[pp.DST_BUF + 4 * i] = w
        if self.complete:
            self.mem[INT_STS] |= pp.INT_STS_D_P_DONE | pp.INT_STS_DMA_DONE
        self.mem[INT_STS] |= self.error_bits

    # -- the console --------------------------------------------------------------
    def reply(self, line: str) -> bytes:
        self.sent.append(line)
        if line in self.banner_on:
            return b"\r\nU-Boot SPL 2026.04-rc5\r\n" + PROMPT
        parts = line.split()
        body = b""
        if parts[0] == "printenv":
            name = parts[1]
            body = (f"{name}={self.env[name]}".encode() if name in self.env
                    else f"## Error: \"{name}\" not defined".encode())
        elif parts[0] == "setenv":
            self.env[parts[1]] = parts[2]
        elif parts[0] == "echo":
            body = b""
        elif parts[0] == "dcache":
            body = b"Data (writethrough) Cache is OFF" if len(parts) == 1 else b""
        elif parts[0] == "md.l":
            addr, count = int(parts[1], 16), int(parts[2], 0)
            lines = []
            for base in range(addr, addr + 4 * count, 16):
                n = min(4, (addr + 4 * count - base) // 4)
                ws = " ".join(f"{self.word(base + 4 * i):08x}" for i in range(n))
                lines.append(f"{base:08x}: {ws}    ....".encode())
            body = b"\r\n".join(lines)
        elif parts[0] == "mw.l":
            addr, value, count = int(parts[1], 16), int(parts[2], 16), int(parts[3], 0)
            if addr == INT_STS:
                self.mem[INT_STS] &= ~value          # write-to-clear
            else:
                for i in range(count):
                    self.mem[addr + 4 * i] = value
                if addr in DMA.values():
                    self.pending.append(value)
                    if addr == DMA["DMA_DEST_LEN"]:
                        self.queue_dma(*self.pending)
                        self.pending = []
        elif parts[0] == "fpga":
            self.loaded = True
            self.mem[INT_STS] |= bsn.PCFG_DONE
        return line.encode() + b"\r\n" + body + b"\r\n" + self.prompt


class FakeTransport:
    def __init__(self, board: FakeUBoot):
        self.board = board

    def command(self, line, timeout):
        return self.board.reply(line)

    def wait_ready(self, timeout):
        return b"## Ready for binary (ymodem) download to 0x04000000 at 115200 bps...\r\nC"

    def ymodem_send(self, path, log, timeout):
        return b"## Total Size = 0x001fcb17 = 2083607 Bytes" + PROMPT

    def descriptor(self):
        return {"requested_port": "fake", "resolved_port": "fake", "device_id": "0:0"}


def session_for(board: FakeUBoot) -> bsn.BoardSession:
    return bsn.BoardSession(FakeTransport(board))


def ready_session(board: FakeUBoot) -> bsn.BoardSession:
    """Precheck, identity and setup load done — the state every stage starts from."""
    s = session_for(board)
    pr.precheck(s)
    s.verify_identity()
    s.load_carrier(bsn.SETUP_LOAD_CAPABILITY, pr.CARRIER_BIT, pr.CARRIER_SHA256,
                   log_path=Path(tempfile.mkdtemp()) / "sb.log")
    return s


def run_s1(board: FakeUBoot, far=pr.TARGET_FAR, expected=pr.TARGET_SHA256, after_load=None):
    """`after_load(board)` mutates state between the setup load and the stage — the place
    a register can legitimately differ from its fresh-power value."""
    s = ready_session(board)
    if after_load:
        after_load(board)
    plan = pp.build_plan(far, pp.PINNED_DMA_ORDER, pr.SENTINEL)
    return pr.execute_plan(bsn.CONFIG_READ_CAPABILITY, s, plan, TABLE, expected, "S1"), s


# ====================================================================== session


class SessionIdentityAndEpoch(unittest.TestCase):
    """Spec §5a.3, §5d.1, §5d.4: one session, one identity, one epoch, U-Boot only."""

    def test_identity_passes_on_the_pinned_board(self):
        s = session_for(FakeUBoot())
        ident = s.verify_identity()
        self.assertEqual(ident["parsed"]["boardid"], "17A6")
        self.assertEqual(ident["epoch"], 0)
        self.assertEqual(ident["control_plane"], "uboot")

    def test_wrong_boardid_role_or_idcode_is_refused(self):
        for kw in ({"boardid": "08EB"}, {"role": "sacrificial"}, {"idcode": 0x13631093}):
            with self.subTest(kw=kw):
                s = session_for(FakeUBoot(**kw))
                with self.assertRaises(bsn.SessionRefusal):
                    s.verify_identity()
                self.assertIsNone(s.identity)

    def test_missing_role_is_a_refusal_not_a_default(self):
        b = FakeUBoot()
        del b.env["role"]
        with self.assertRaises(bsn.SessionRefusal):
            session_for(b).verify_identity()

    def test_authorise_needs_identity_in_the_current_epoch(self):
        s = session_for(FakeUBoot())
        with self.assertRaises(bsn.SessionRefusal):
            s.authorise(bsn.CONFIG_READ_CAPABILITY)
        s.verify_identity()
        s.authorise(bsn.CONFIG_READ_CAPABILITY)
        s.note_disruption("uart_disconnect")
        self.assertEqual(s.epoch, 1)
        with self.assertRaises(bsn.SessionRefusal):
            s.authorise(bsn.CONFIG_READ_CAPABILITY)

    def test_linux_control_plane_is_refused_unconditionally(self):
        s = session_for(FakeUBoot())
        s.verify_identity()
        with self.assertRaises(bsn.SessionRefusal):
            s.authorise(bsn.CONFIG_READ_CAPABILITY, control_plane="linux")

    def test_a_capability_is_an_instance_not_a_name(self):
        s = session_for(FakeUBoot())
        s.verify_identity()
        with self.assertRaises(bsn.SessionRefusal):
            s.authorise("configuration-read")

    def test_a_boot_banner_ends_the_epoch_and_refuses(self):
        b = FakeUBoot()
        s = session_for(b)
        s.verify_identity()
        b.banner_on.add("printenv plmark")
        with self.assertRaises(bsn.SessionRefusal):
            s.command("printenv plmark")
        self.assertEqual(s.epoch, 1)
        self.assertEqual(s.disruptions[-1]["kind"], "soft_reset")
        self.assertIsNone(s.identity)

    def test_a_missing_prompt_ends_the_epoch(self):
        b = FakeUBoot(prompt=b"")
        s = session_for(b)
        with self.assertRaises(bsn.SessionRefusal):
            s.command("echo")
        self.assertEqual(s.disruptions[-1]["kind"], "timeout")

    def test_a_changed_prompt_is_a_control_plane_change(self):
        b = FakeUBoot()
        s = session_for(b)
        s.command("echo")
        b.prompt = b"zynq-uboot> "
        with self.assertRaises(bsn.SessionRefusal):
            s.command("echo")
        self.assertEqual(s.disruptions[-1]["kind"], "prompt_mode_change")

    def test_an_empty_line_is_never_sent(self):
        b = FakeUBoot()
        with self.assertRaises(bsn.SessionRefusal):
            session_for(b).command("   ")
        self.assertEqual(b.sent, [])

    def test_unknown_disruption_kinds_are_refused(self):
        with self.assertRaises(bsn.SessionRefusal):
            session_for(FakeUBoot()).note_disruption("something")

    def test_every_reply_is_preserved_losslessly(self):
        s = session_for(FakeUBoot())
        raw = s.command("printenv boardid")
        entry = s.log[-1]
        self.assertEqual(entry["sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(entry["byte_count"], len(raw))


class StrictParsing(unittest.TestCase):
    """Spec snapshot §5b.1 via the source module's rule: ambiguity never resolves to a value."""

    def test_md_requires_exactly_the_requested_words_at_the_requested_addresses(self):
        good = b"md.l 0x10300000 0x8\r\n10300000: 00000001 00000002 00000003 00000004    ....\r\n" \
               b"10300010: 00000005 00000006 00000007 00000008    ....\r\nZynq> "
        self.assertEqual(bsn.parse_md(good, 0x10300000, 8), list(range(1, 9)))
        with self.assertRaises(bsn.SessionRefusal):
            bsn.parse_md(good, 0x10300000, 9)
        with self.assertRaises(bsn.SessionRefusal):
            bsn.parse_md(good, 0x10300010, 8)

    def test_env_value_with_two_assignments_is_ambiguous(self):
        with self.assertRaises(bsn.SessionRefusal):
            bsn.parse_env_value(b"boardid=17A6\r\nboardid=08EB\r\nZynq> ", "boardid")


# ====================================================================== setup load


class SetupLoad(unittest.TestCase):
    """Spec §5a.4–5: sha gate, empty PL, PCFG_DONE edge, plmark — on the identified session."""

    def test_load_needs_the_setup_capability_and_an_identity(self):
        s = session_for(FakeUBoot())
        with self.assertRaises(bsn.SessionRefusal):
            s.load_carrier(bsn.CONFIG_READ_CAPABILITY, pr.CARRIER_BIT, pr.CARRIER_SHA256)
        with self.assertRaises(bsn.SessionRefusal):
            s.load_carrier(bsn.SETUP_LOAD_CAPABILITY, pr.CARRIER_BIT, pr.CARRIER_SHA256)

    def test_sha_gate_refuses_before_any_command_reaches_the_board(self):
        b = FakeUBoot()
        s = session_for(b)
        s.verify_identity()
        sent_before = list(b.sent)
        with self.assertRaises(bsn.SessionRefusal):
            s.load_carrier(bsn.SETUP_LOAD_CAPABILITY, pr.CARRIER_BIT, "00" * 32)
        self.assertEqual(b.sent, sent_before)

    def test_an_already_configured_pl_is_refused(self):
        b = FakeUBoot(int_sts=0xA802000B | bsn.PCFG_DONE)
        s = session_for(b)
        s.verify_identity()
        with self.assertRaises(bsn.SessionRefusal):
            s.load_carrier(bsn.SETUP_LOAD_CAPABILITY, pr.CARRIER_BIT, pr.CARRIER_SHA256)
        self.assertFalse(b.loaded)

    def test_a_successful_load_sets_plmark_and_records_the_edge(self):
        b = FakeUBoot()
        s = ready_session(b)
        self.assertTrue(b.loaded)
        self.assertEqual(b.env["plmark"], s.plmark)
        self.assertEqual(int(s.setup_load["int_sts_cleared"], 16) & bsn.PCFG_DONE, 0)
        self.assertTrue(int(s.setup_load["int_sts_after"], 16) & bsn.PCFG_DONE)
        self.assertEqual(s.setup_load["epoch"], s.epoch)

    def test_the_ymodem_transfer_uses_the_session_transport_not_a_new_port(self):
        """§5d.1: no second session, no re-resolved port. The fake has no other channel."""
        import inspect
        src = inspect.getsource(bsn.SerialTransport.ymodem_send)
        self.assertIn("fileno()", src)
        self.assertNotIn("serial.Serial(", src)


# ====================================================================== precheck


class Precheck(unittest.TestCase):
    """Spec §5a.2: read-only, refuses, never repairs."""

    def test_fresh_power_passes(self):
        rec = pr.precheck(session_for(FakeUBoot()))
        self.assertTrue(rec["passed"])

    def test_a_defined_plmark_or_a_configured_pl_refuses(self):
        b = FakeUBoot()
        b.env["plmark"] = "deadbeef"
        with self.assertRaises(bsn.SessionRefusal):
            pr.precheck(session_for(b))
        with self.assertRaises(bsn.SessionRefusal):
            pr.precheck(session_for(FakeUBoot(int_sts=0xA802000F)))

    def test_precheck_sends_no_write(self):
        b = FakeUBoot()
        pr.precheck(session_for(b))
        self.assertFalse(any(c.startswith(("mw", "fpga", "setenv")) for c in b.sent))


# ====================================================================== stages


class StageExecution(unittest.TestCase):
    """Spec §5b, §5d.5, §5e, §7: the gates in order, one shot, verdicts from the table."""

    def test_s1_pass_end_to_end(self):
        rec, s = run_s1(FakeUBoot())
        self.assertEqual(rec["verdict"], "PASS")
        self.assertEqual(rec["frame_sha256"], pr.TARGET_SHA256)
        self.assertEqual(len(rec["readout"]), pp.READBACK_WORDS)
        self.assertEqual(rec["plmark"], s.plmark)
        self.assertEqual(rec["observations"]["ctrl"], "0x4e00e07f")
        self.assertEqual(len(rec["waits"]), 3)               # command, readback, cleanup
        for w in rec["waits"]:
            self.assertEqual(w["elapsed_basis"], "measured")
        self.assertIn("dcache", rec["observations"])

    def test_execute_plan_needs_the_configuration_read_capability(self):
        s = ready_session(FakeUBoot())
        plan = pp.build_plan(pr.TARGET_FAR, pp.PINNED_DMA_ORDER, pr.SENTINEL)
        with self.assertRaises(bsn.SessionRefusal):
            pr.execute_plan(bsn.SETUP_LOAD_CAPABILITY, s, plan, TABLE, pr.TARGET_SHA256, "S1")

    def test_the_runner_sends_only_plan_commands_and_the_named_extras(self):
        b = FakeUBoot()
        rec, s = run_s1(b)
        plan_cmds = {st["cmd"] for st in
                     pp.build_plan(pr.TARGET_FAR, pp.PINNED_DMA_ORDER, pr.SENTINEL)["uboot_script"]}
        first_stage = b.sent.index("dcache off")
        extra = {c for c in b.sent[first_stage:] if c not in plan_cmds}
        self.assertTrue(extra <= pr.RUNNER_EXTRA_COMMANDS, extra - pr.RUNNER_EXTRA_COMMANDS)

    def test_plmark_is_checked_before_every_stage(self):
        b = FakeUBoot()
        s = ready_session(b)
        b.env["plmark"] = "0000000000000000"
        plan = pp.build_plan(pr.TARGET_FAR, pp.PINNED_DMA_ORDER, pr.SENTINEL)
        with self.assertRaises(bsn.SessionRefusal):
            pr.execute_plan(bsn.CONFIG_READ_CAPABILITY, s, plan, TABLE, pr.TARGET_SHA256, "S1")
        self.assertNotIn("dcache off", b.sent)
        self.assertEqual(s.disruptions[-1]["kind"], "power_cycle")

    def _expect_stop(self, board, verdict, after_load=None):
        with self.assertRaises(pr.ProbeStop) as cm:
            run_s1(board, after_load=after_load)
        self.assertEqual(cm.exception.verdict, verdict)
        return cm.exception, board

    def test_ctrl_masked_bit_wrong_stops_before_any_dma(self):
        stop, b = self._expect_stop(FakeUBoot(), pr.PRECONDITION,
                                    after_load=lambda b: b.mem.__setitem__(CTRL, 0x4E00E07F & ~(1 << 27)))
        self.assertEqual(stop.verdict, pr.PRECONDITION)
        self.assertIsNone(stop.record["verdict"])
        self.assertFalse(any(c.startswith(f"mw.l {DMA['DMA_SRC_ADDR']:#010x}") for c in b.sent))

    def test_ctrl_full_word_difference_with_mask_satisfied_is_recorded_only(self):
        rec, _ = run_s1(FakeUBoot(), after_load=lambda b: b.mem.__setitem__(CTRL, 0x0C00E07F))
        self.assertEqual(rec["verdict"], "PASS")
        self.assertFalse(rec["observations"]["ctrl_full_word_matches_historical"])

    def test_loopback_bit_stops_before_any_dma(self):
        stop, b = self._expect_stop(FakeUBoot(mctrl=0x10), pr.PRECONDITION)
        self.assertIn("PCAP_LPBK", stop.detail)
        self.assertFalse(any(c.startswith(f"mw.l {DMA['DMA_SRC_ADDR']:#010x}") for c in b.sent))

    def test_stale_status_that_does_not_clear_stops(self):
        b = FakeUBoot()
        real = b.reply

        def sticky(line):
            out = real(line)
            if line.startswith(f"mw.l {INT_STS:#010x}"):
                b.mem[INT_STS] |= pp.INT_STS_D_P_DONE     # refuses to clear
            return out
        b.reply = sticky
        stop, _ = self._expect_stop(b, pr.PRECONDITION)
        self.assertIn("did not clear", stop.detail)

    def test_sentinel_not_present_stops_before_the_read(self):
        b = FakeUBoot()
        real = b.reply

        def drop_fill(line):
            out = real(line)
            if line.startswith(f"mw.l {pp.DST_BUF:#010x}"):
                b.mem[pp.DST_BUF] = 0
            return out
        b.reply = drop_fill
        stop, b = self._expect_stop(b, pr.PRECONDITION)
        self.assertIn("sentinel", stop.detail)
        self.assertFalse(any(c.startswith(f"mw.l {pp.CMD_BUF:#010x}") for c in b.sent))

    def test_error_bits_during_a_wait_stop_as_overflow(self):
        stop, _ = self._expect_stop(FakeUBoot(error_bits=1 << 18), "OVERFLOW")
        self.assertEqual(stop.verdict, "OVERFLOW")

    def test_no_completion_stops_as_timeout_without_reissue(self):
        b = FakeUBoot(complete=False)
        pp_timeout = pp.TIMEOUT_S
        try:
            pp.TIMEOUT_S = 0.05
            # build_plan reads TIMEOUT_S at call time
            s = ready_session(b)
            plan = pp.build_plan(pr.TARGET_FAR, pp.PINNED_DMA_ORDER, pr.SENTINEL)
            with self.assertRaises(pr.ProbeStop) as cm:
                pr.execute_plan(bsn.CONFIG_READ_CAPABILITY, s, plan, TABLE, pr.TARGET_SHA256, "S1")
        finally:
            pp.TIMEOUT_S = pp_timeout
        self.assertEqual(cm.exception.verdict, "TIMEOUT")
        dest_len_writes = [c for c in b.sent if c.startswith(f"mw.l {DMA['DMA_DEST_LEN']:#010x}")]
        self.assertEqual(len(dest_len_writes), 1, "the first DMA was re-issued")

    def test_verdict_table_is_applied_to_the_frame_half(self):
        cases = {
            "BUFFER_UNCHANGED_FROM_PREFILL": lambda far: [pr.SENTINEL] * 202,
            "SENTINEL_REMAINS": lambda far: [0] * 101 + FRAMES[far][:-1] + [pr.SENTINEL],
            "BLANK": lambda far: [0] * 202,
            "MISADDRESS": lambda far: [0] * 101 + FRAMES[0xB98],
            "NO_MATCH": lambda far: [0] * 101 + [0x12345678] * 101,
        }
        for verdict, deliver in cases.items():
            with self.subTest(verdict=verdict):
                with self.assertRaises(pr.ProbeStop) as cm:
                    run_s1(FakeUBoot(deliver=deliver))
                self.assertEqual(cm.exception.verdict, verdict)
                self.assertEqual(cm.exception.record["verdict"], verdict)
        with self.assertRaises(pr.ProbeStop) as cm:
            run_s1(FakeUBoot(deliver=lambda far: [0] * 101 + FRAMES[0xB98]))
        self.assertEqual(cm.exception.record["matched_far"], "0x00000b98")

    def test_ambiguous_reverse_lookup_records_the_full_set_and_no_pick(self):
        dup = next(h for h, fars in TABLE["reverse"].items()
                   if len(fars) > 1 and any(FRAMES[fars[0]]))
        far = TABLE["reverse"][dup][0]
        with self.assertRaises(pr.ProbeStop) as cm:
            run_s1(FakeUBoot(deliver=lambda f: [0] * 101 + FRAMES[far]))
        rec = cm.exception.record
        self.assertEqual(rec["verdict"], "MISADDRESS_AMBIGUOUS")
        self.assertEqual(len(rec["candidate_fars"]), len(TABLE["reverse"][dup]))
        self.assertNotIn("matched_far", rec)

    def test_pad_half_never_adjudicates(self):
        """§4d: a correct frame with garbage in the pad is still PASS."""
        rec, _ = run_s1(FakeUBoot(deliver=lambda far: [0xDEADBEEF] * 101 + FRAMES[far]))
        self.assertEqual(rec["verdict"], "PASS")

    def test_adjudicate_is_pure_and_refuses_the_wrong_length(self):
        with self.assertRaises(ValueError):
            pr.adjudicate([0] * 201, pr.SENTINEL, pr.TARGET_SHA256, TABLE["reverse"])
        self.assertTrue(set(pr.VERDICTS) >= {
            pr.adjudicate([0] * 202, pr.SENTINEL, pr.TARGET_SHA256, TABLE["reverse"])["verdict"]})


# ====================================================================== the chain


class ProbeChain(unittest.TestCase):
    """Spec §2, §8: S2/S3 only after a pass; any failure stops the chain; records written."""

    def _run(self, board):
        out = Path(tempfile.mkdtemp())
        ruling = {"ruling": pr.RULING_TEXT, "boardid": "17A6", "granted_by": "test",
                  "date": "2026-08-29"}
        summary = pr.run_probe(session_for(board), out, ruling, TABLE)
        return summary, out

    def test_full_chain_passes_and_writes_every_record(self):
        summary, out = self._run(FakeUBoot())
        self.assertEqual(summary["outcome"], "PASS")
        names = sorted(p.stem for p in out.glob("*.json"))
        self.assertEqual(names, sorted(["summary", "S1", "S2_0", "S2_1"]
                                       + [f"S3_{i}" for i in range(10)]))
        self.assertEqual(set(summary["stages"].values()), {"PASS"})
        self.assertTrue(summary["uart_log"])
        self.assertEqual(summary["epoch_final"], 0)

    def test_s2_expects_each_neighbour_own_hash(self):
        summary, out = self._run(FakeUBoot())
        for i, far in enumerate(pr.S2_FARS):
            rec = json.loads((out / f"S2_{i}.json").read_text())
            self.assertEqual(rec["expected"]["frame_sha256"], pr.frame_sha256(FRAMES[far]))
            self.assertEqual(rec["frame_sha256"], pr.frame_sha256(FRAMES[far]))

    def test_s3_issues_ten_independent_transactions(self):
        b = FakeUBoot()
        self._run(b)
        fills = [c for c in b.sent if c.startswith(f"mw.l {pp.DST_BUF:#010x}")]
        self.assertEqual(len(fills), 1 + 2 + 10)

    def test_a_failure_at_s1_stops_the_chain_before_s2(self):
        b = FakeUBoot(deliver=lambda far: [0] * 202)
        summary, out = self._run(b)
        self.assertTrue(summary["outcome"].startswith("STOP BLANK"))
        self.assertEqual(sorted(p.stem for p in out.glob("*.json")), ["S1", "summary"])
        self.assertEqual(len([c for c in b.sent if c == "dcache off"]), 1)

    def test_a_stable_wrong_frame_at_s3_does_not_pass(self):
        calls = {"n": 0}

        def deliver(far):
            calls["n"] += 1
            return [0] * 101 + (FRAMES[far] if calls["n"] <= 3 else FRAMES[0xB98])
        summary, _ = self._run(FakeUBoot(deliver=deliver))
        self.assertTrue(summary["outcome"].startswith("STOP MISADDRESS"))

    def test_identity_refusal_prevents_the_setup_load(self):
        b = FakeUBoot(boardid="08EB")
        summary, _ = self._run(b)
        self.assertTrue(summary["outcome"].startswith("REFUSED"))
        self.assertFalse(b.loaded)

    def test_precheck_failure_prevents_identity_and_load(self):
        b = FakeUBoot(int_sts=0xA802000F)
        summary, _ = self._run(b)
        self.assertTrue(summary["outcome"].startswith("REFUSED"))
        self.assertNotIn("printenv boardid", b.sent)


# ====================================================================== ruling & CLI


class RulingAndEntryPoint(unittest.TestCase):
    """Spec §2: one whole-of-probe ruling; consumed on failure; nothing relaxes identity."""

    def _ruling(self, **override):
        d = Path(tempfile.mkdtemp())
        body = {"ruling": pr.RULING_TEXT, "boardid": "17A6", "granted_by": "owner",
                "date": "2026-08-29"}
        body.update(override)
        p = d / "ruling.json"
        p.write_text(json.dumps(body))
        return p

    def test_a_valid_ruling_is_accepted_and_hashed(self):
        r = pr.check_ruling(self._ruling())
        self.assertEqual(len(r["sha256"]), 64)

    def test_wrong_text_board_or_missing_fields_are_refused(self):
        for kw in ({"ruling": "S1 only"}, {"boardid": "08EB"}, {"granted_by": ""}):
            with self.subTest(kw=kw):
                with self.assertRaises(bsn.SessionRefusal):
                    pr.check_ruling(self._ruling(**kw))

    def test_a_consumed_ruling_is_refused(self):
        p = self._ruling()
        pr.consume_ruling(p, "STOP BLANK")
        with self.assertRaises(bsn.SessionRefusal):
            pr.check_ruling(p)

    def test_main_refuses_without_a_ruling_and_opens_no_port(self):
        opened = []
        original = bsn.SerialTransport
        bsn.SerialTransport = lambda *a, **k: opened.append(a) or (_ for _ in ()).throw(
            AssertionError("port opened"))
        try:
            rc = pr.main(["--ruling", "/nonexistent/ruling.json",
                          "--out", tempfile.mkdtemp() + "/out"])
        finally:
            bsn.SerialTransport = original
        self.assertEqual(rc, 2)
        self.assertEqual(opened, [])

    def test_main_refuses_an_existing_evidence_directory(self):
        rc = pr.main(["--ruling", str(self._ruling()), "--out", tempfile.mkdtemp()])
        self.assertEqual(rc, 2)

    def test_main_consumes_the_ruling_on_a_stop(self):
        ruling = self._ruling()
        out = Path(tempfile.mkdtemp()) / "out"
        board = FakeUBoot(deliver=lambda far: [0] * 202)

        class T(FakeTransport):
            def __init__(self, port):
                super().__init__(board)

            def close(self):
                pass
        original = bsn.SerialTransport
        bsn.SerialTransport = T
        try:
            rc = pr.main(["--ruling", str(ruling), "--out", str(out)])
        finally:
            bsn.SerialTransport = original
        self.assertEqual(rc, 1)
        self.assertTrue(ruling.with_name("ruling.json.consumed").exists())

    def test_the_parser_exposes_nothing_that_relaxes_a_requirement(self):
        import argparse
        captured = {}
        real = argparse.ArgumentParser.parse_args

        def spy(self, argv=None):
            captured["flags"] = {a.dest for a in self._actions}
            return real(self, argv)
        argparse.ArgumentParser.parse_args = spy
        try:
            pr.main(["--ruling", "/nonexistent", "--out", tempfile.mkdtemp() + "/x"])
        finally:
            argparse.ArgumentParser.parse_args = real
        self.assertEqual(captured["flags"], {"help", "ruling", "out", "port"})

    def test_the_planner_still_imports_no_transport(self):
        """The AST guard in test_s0_pcap_plan covers the planner; the runner must not
        re-export a way around it: board_session imports pyserial only inside a method."""
        import ast
        tree = ast.parse((REPO_ROOT / "scripts/board_session.py").read_text())
        top_level = {n.names[0].name.split(".")[0] for n in tree.body
                     if isinstance(n, (ast.Import, ast.ImportFrom))}
        self.assertNotIn("serial", top_level)


if __name__ == "__main__":
    unittest.main()
