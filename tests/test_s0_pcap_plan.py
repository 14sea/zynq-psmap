"""S0's guards: the planner must agree with the pinned document, and refuse what the
specification refuses.

The tests are written to fail when the *document* and the *code* drift apart in either
direction, because a pinned constant that lives in only one of the two is not pinned.
"""
from __future__ import annotations

import ast
import re
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import pcap_probe_plan as P  # noqa: E402

SEQ_DOC = (REPO_ROOT / "docs/s0_derived_sequence.md").read_text()
DISCHARGE_DOC = (REPO_ROOT / "docs/s0_ug585_discharge.md").read_text()


class PinnedWordsMatchTheDocument(unittest.TestCase):

    def test_the_four_packet_headers_are_re_derivable(self):
        w = P.readback_commands(0x00000B99)
        self.assertEqual(w[4], 0x30008001, "Type-1 write CMD")
        self.assertEqual(w[7], 0x30002001, "Type-1 write FAR")
        self.assertEqual(w[9], 0x28006000, "Type-1 read FDRO")
        self.assertEqual(w[10], 0x480000CA, "Type-2 read, 202 words")

    def test_rcfg_precedes_far_as_ug470_orders_it(self):
        """UG470 Table 6-2: CMD/RCFG, NOOP, FAR.  The first version had it backwards."""
        w = P.readback_commands(0x00000B99)
        cmd_i = w.index(0x30008001)
        far_i = w.index(0x30002001)
        self.assertLess(cmd_i, far_i, "RCFG must be written before the FAR")
        self.assertEqual(w[cmd_i + 1], 0x00000004, "CMD payload is RCFG")
        self.assertEqual(w[cmd_i + 2], 0x20000000, "UG470 step 6 ends with one NOOP")
        self.assertEqual(far_i, cmd_i + 3, "the FAR immediately follows that NOOP")
        self.assertLess(far_i, w.index(0x28006000), "FDRO read comes last")

    def test_the_measured_alternative_order_is_recorded_not_erased(self):
        """Structural: §3c must exist and its warrant table must carry both orders.

        The first version of this guard searched the whole document for a loose pattern
        and survived §3c being deleted outright -- the section it was supposed to protect.
        """
        self.assertIn("### 3c.", SEQ_DOC, "§3c (the order divergence) is missing")
        start = SEQ_DOC.index("### 3c.")
        end = SEQ_DOC.index("**Word order.**", start)
        section = SEQ_DOC[start:end]
        rows = re.findall(r"^\| `?([A-Z0-9`, ]+?)`? \| \*\*\[(UG470|MEASURED)\]\*\*",
                          section, re.M)
        warrants = {w for _, w in rows}
        self.assertEqual(warrants, {"UG470", "MEASURED"},
                         f"§3c must carry both warranted orders, found {rows}")
        self.assertRegex(section, r"named alternative",
                         "the measured order must be kept as a named alternative")
        self.assertRegex(section, r"never a retry inside one",
                         "§7.4 forbids retries inside a run; §3c must say so")

    def test_every_header_in_the_document_is_produced_by_the_code(self):
        """Parse the decode table out of the document; do not trust a substring."""
        rows = re.findall(r"^\| `([0-9A-F]{8})` \| Type-([12]), (read|write)"
                          r"(?:, register (\d+) \(`(\w+)`\))?, count (?:`?)(\d+|`0xCA` = \*\*202\*\*)",
                          SEQ_DOC, re.M)
        self.assertGreaterEqual(len(rows), 4, "decode table not parsed; test is vacuous")
        produced = set(P.readback_commands(0x00000B99))
        for word, *_ in rows:
            with self.subTest(word=word):
                self.assertIn(int(word, 16), produced,
                              f"{word} is decoded in the document but never produced")

    def test_the_word_count_and_the_type2_count_agree(self):
        w = P.readback_commands(0x00000B99)
        self.assertEqual(w[10] & 0x07FFFFFF, P.READBACK_WORDS)
        self.assertEqual(P.READBACK_WORDS, 2 * P.FRAME_WORDS)
        self.assertEqual(len(w), 43)

    def test_the_target_far_appears_verbatim_in_the_stream(self):
        self.assertIn(0x00000B99, P.readback_commands(0x00000B99))

    def test_the_payload_words_are_pinned_to_literals(self):
        """M3 survived a mutation of CMD_RCFG because nothing pinned its value.

        Every constant below is written as a literal rather than as the module's own
        symbol: a test that compares a constant to itself cannot detect the constant
        changing.
        """
        w = P.readback_commands(0x00000B99)
        self.assertEqual(w[0], 0xFFFFFFFF, "dummy")
        self.assertEqual(w[1], 0xAA995566, "sync, SelectMAP order, NOT br8-reversed")
        self.assertEqual(w[2], 0x20000000, "NOOP")
        self.assertEqual(w[8], 0x00000B99, "the FAR payload")
        self.assertEqual(w[5], 0x00000004, "CMD payload = RCFG")
        self.assertEqual(P.CMD_RCFG, 4)
        self.assertEqual(w[-1], 0x20000000, "the flush is NOOPs")
        self.assertEqual(len(w) - 11, 32, "32-word flush")


class TheProbeWritesNoConfiguration(unittest.TestCase):

    def test_a_write_to_fdri_is_refused(self):
        with self.assertRaises(ValueError) as cm:
            P.type1(P.OP_WRITE, 2, 1)
        self.assertIn("FDRI", str(cm.exception))

    def test_no_produced_word_is_an_fdri_write(self):
        fdri = (P.TYPE1 << 29) | (P.OP_WRITE << 27) | (2 << 13)
        for w in P.readback_commands(0x00000B99):
            with self.subTest(word=f"{w:08X}"):
                is_type1_write = (w >> 29) == P.TYPE1 and ((w >> 27) & 0b11) == P.OP_WRITE
                if is_type1_write:
                    self.assertNotEqual((w >> 13) & 0x3FFF, 2,
                                        "an FDRI write reached the stream")
                self.assertNotEqual(w & 0xFFFFF800, fdri & 0xFFFFF800)

    def test_only_allowlisted_addresses_appear_in_a_plan(self):
        for order in ("two-unidirectional", "one-bidirectional"):
            plan = P.build_plan(0x00000B99, order, 0xA5A5A5A5)
            for step in plan["uboot_script"]:
                for addr in P.addresses_in(step["cmd"]):
                    with self.subTest(order=order, addr=f"{addr:#010x}"):
                        self.assertTrue(
                            any(b <= addr < b + n for b, n in P.ALLOWED_REGIONS),
                            f"{addr:#010x} is outside every allowed region")

    def test_an_off_allowlist_address_is_caught(self):
        plan = P.build_plan(0x00000B99, "one-bidirectional", 0xA5A5A5A5)
        plan["uboot_script"].append({"step": "x", "cmd": "mw.l 0x43c00000 1 1",
                                     "why": "", "addresses": [0x43C00000]})
        with self.assertRaises(ValueError):
            P.check_allowlist(plan)

    def test_the_review_bypass_is_closed(self):
        """The exact attack review used: rewrite the command, leave the metadata alone.

        The first guard read `step["addresses"]` and never looked at `cmd`, so a plan whose
        mw.l wrote 0x43C00000 while its metadata still said CMD_BUF passed the check and
        the whole suite.  Metadata is a claim; the command is what a board executes.
        """
        plan = P.build_plan(0x00000B99, "two-unidirectional", 0xA5A5A5A5)
        for step in plan["uboot_script"]:
            if step["step"] == "cmd-word":
                step["cmd"] = step["cmd"].replace("0x10200", "0x43c00", 1)
                break
        with self.assertRaises(ValueError) as cm:
            P.check_allowlist(plan)
        self.assertIn("0x43c00", str(cm.exception).lower())

    def test_metadata_must_agree_with_the_command(self):
        plan = P.build_plan(0x00000B99, "one-bidirectional", 0xA5A5A5A5)
        words = [s for s in plan["uboot_script"] if s["step"] == "cmd-word"]
        self.assertGreater(len(words), 1)
        # word 0 legitimately writes CMD_BUF, so lie about a later one
        words[5]["addresses"] = [P.CMD_BUF]
        with self.assertRaises(ValueError) as cm:
            P.check_allowlist(plan)
        self.assertIn("disagrees", str(cm.exception))

    def test_the_address_parser_actually_parses(self):
        self.assertEqual(P.addresses_in("mw.l 0x10200004 0xdeadbeef 1"), [0x10200004])
        self.assertEqual(P.addresses_in("md.l 0xf800700c 1"), [0xF800700C])
        self.assertEqual(P.addresses_in("dcache off"), [])

    def test_the_grammar_is_closed_and_fails_shut(self):
        """An allowlist whose parser fails open is not an allowlist."""
        for bad in ("mw.b 0x43c00000 0xff 1", "mw.w 0x10300000 1 1", "fatload mmc 0 0x1 x",
                    "go 0x10200000", "md 0x10300000 1", "mw.l 0x10300000 1 0",
                    "mw.l 0x10300000 1 1; go 0", ""):
            with self.subTest(cmd=bad):
                with self.assertRaises(ValueError):
                    P.parse_command(bad)

    def test_the_whole_span_must_be_contained_not_just_the_start(self):
        """review's case: mw.l 0x103003fc ... 2 starts inside and ends outside."""
        last = P.DST_BUF + 4 * P.READBACK_WORDS - 4
        plan = P.build_plan(0x00000B99, "one-bidirectional", 0xA5A5A5A5)
        plan["uboot_script"].append(
            {"step": "x", "cmd": f"mw.l {last:#010x} 0xdeadbeef 2", "why": "",
             "addresses": [last]})
        with self.assertRaises(ValueError) as cm:
            P.check_allowlist(plan)
        self.assertIn("not contained", str(cm.exception))

    def test_a_span_that_fits_exactly_is_allowed(self):
        """Discriminating power: the containment check must not reject the legal case."""
        last = P.DST_BUF + 4 * P.READBACK_WORDS - 4
        form, start, span = P.parse_command(f"mw.l {last:#010x} 0xdeadbeef 1")
        self.assertEqual((start, span), (last, 4))


class UnresolvedThingsStayUnresolved(unittest.TestCase):

    def test_dma_order_has_no_default(self):
        """A silent default is how an open question becomes an invisible assumption."""
        with self.assertRaises(SystemExit):
            P.main(["--far", "0x00000b99"])

    def test_both_readings_are_implemented(self):
        two = P.dma_commands("two-unidirectional", 43, 202)
        one = P.dma_commands("one-bidirectional", 43, 202)
        self.assertEqual(len(two), 2)
        self.assertEqual(len(one), 1)
        self.assertEqual(two[0]["DMA_DEST_ADDR"], P.PCAP_ENDPOINT)
        self.assertEqual(two[1]["DMA_SRC_ADDR"], P.PCAP_ENDPOINT)
        self.assertEqual(one[0]["DMA_SRC_LEN"], 43)
        self.assertEqual(one[0]["DMA_DEST_LEN"], 202)

    def test_the_plan_reports_its_unresolved_items(self):
        plan = P.build_plan(0x00000B99, "two-unidirectional", 0xA5A5A5A5)
        self.assertTrue(plan["unresolved"])
        self.assertRegex(" ".join(plan["unresolved"]), r"8a")
        self.assertRegex(" ".join(plan["unresolved"]), r"8b")

    def test_the_document_marks_both_as_unresolved(self):
        flat = " ".join(SEQ_DOC.replace("*", "").split())
        self.assertRegex(flat, r"8a\..{0,120}UNRESOLVED")
        self.assertRegex(flat, r"8b\..{0,140}UNRESOLVED")

    def test_u1_is_recorded_as_retracted_not_quietly_deleted(self):
        flat = " ".join(DISCHARGE_DOC.replace("*", "").split())
        self.assertRegex(flat, r"U1 .{0,40}RETRACTED",
                         "a withdrawn conclusion must stay visible as withdrawn")
        self.assertRegex(flat, r"FOs3lXmlcWxBhTIFxVKyGA",
                         "the document id that settles it must be recorded")


class VendorConstraintsAreHonoured(unittest.TestCase):

    def test_buffers_are_64_byte_aligned(self):
        for addr in (P.CMD_BUF, P.DST_BUF):
            with self.subTest(addr=f"{addr:#010x}"):
                self.assertEqual(addr % P.DMA_ALIGN, 0)

    def test_an_unaligned_buffer_is_refused(self):
        with self.assertRaises(ValueError):
            P._tagged(P.DST_BUF + 4)

    def test_neither_transfer_crosses_a_4k_boundary(self):
        for base, words in ((P.CMD_BUF, 43), (P.DST_BUF, P.READBACK_WORDS)):
            with self.subTest(base=f"{base:#010x}"):
                self.assertEqual(base // 4096, (base + 4 * words - 1) // 4096)

    def test_ddr_addresses_carry_the_hold_tag(self):
        """Pinned to the literal 0b01 UG585 requires.

        This compared `addr & 0b11` against `P.DMA_HOLD_TAG`, so setting that constant to
        0 mutated the expectation along with the behaviour and the test still passed --
        the failure mode this project keeps meeting.  UG585's requirement is a literal, so
        the test states the literal.
        """
        self.assertEqual(P.DMA_HOLD_TAG, 0b01,
                         "UG585: SRC_ADDR[1:0] and DST_ADDR[1:0] = 2'b01")
        for order in ("two-unidirectional", "one-bidirectional"):
            for cmd in P.dma_commands(order, 43, 202):
                for key in ("DMA_SRC_ADDR", "DMA_DEST_ADDR"):
                    if cmd[key] != 0xFFFFFFFF:
                        with self.subTest(order=order, cmd=cmd["name"], key=key):
                            self.assertEqual(cmd[key] & 0b11, 0b01)

    def test_the_pcap_endpoint_is_the_literal_vendor_value(self):
        self.assertEqual(P.PCAP_ENDPOINT, 0xFFFFFFFF)
        two = P.dma_commands("two-unidirectional", 43, 202)
        self.assertEqual(two[0]["DMA_DEST_ADDR"], 0xFFFFFFFF)
        self.assertEqual(two[1]["DMA_SRC_ADDR"], 0xFFFFFFFF)

    def test_alignment_and_completion_bits_are_pinned_to_literals(self):
        self.assertEqual(P.DMA_ALIGN, 64)
        self.assertEqual(P.INT_STS_D_P_DONE, 0x1000)
        self.assertEqual(P.INT_STS_PCFG_DONE, 0x4)
        self.assertEqual(P.CTRL_MASK, 0x0C000000)
        self.assertEqual(P.CTRL_REQUIRED, 0x0C000000)
        self.assertEqual(P.READBACK_WORDS, 202)
        self.assertEqual(P.FRAME_WORDS, 101)

    def test_dma_registers_are_written_in_the_normative_order(self):
        self.assertEqual(P.DMA_WRITE_ORDER,
                         ("DMA_SRC_ADDR", "DMA_DEST_ADDR", "DMA_SRC_LEN", "DMA_DEST_LEN"))
        plan = P.build_plan(0x00000B99, "two-unidirectional", 0xA5A5A5A5)
        seen = [s["cmd"] for s in plan["uboot_script"] if s["step"].startswith("dma-")]
        offsets = [int(re.search(r"0x[0-9a-f]+", c).group(0), 16) for c in seen]
        want = [P.REG[r] for r in P.DMA_WRITE_ORDER]
        self.assertEqual(offsets[:4], want)
        self.assertEqual(offsets[-1], P.REG["DMA_DEST_LEN"],
                         "the queuing write must be last")

    def test_completion_is_d_p_done_not_dma_done(self):
        self.assertEqual(P.INT_STS_D_P_DONE, 1 << 12)
        self.assertEqual(P.INT_STS_DMA_DONE, 1 << 13)
        plan = P.build_plan(0x00000B99, "two-unidirectional", 0xA5A5A5A5)
        waits = [s for s in plan["uboot_script"] if s["step"].startswith("wait-")]
        self.assertTrue(waits)
        for w in waits:
            self.assertIn(f"{P.INT_STS_D_P_DONE:#x}", w["why"])

    def test_the_error_mask_names_every_bit_the_vendor_lists(self):
        for bit in (23, 22, 21, 20, 18, 15, 14, 11, 6):
            with self.subTest(bit=bit):
                self.assertTrue(P.INT_STS_ERROR_MASK & (1 << bit))
        self.assertEqual(P.INT_STS_ERROR_MASK, 0x00F4C840)

    def test_ctrl_is_a_masked_gate_that_excludes_the_rate_bit(self):
        self.assertEqual(P.CTRL_MASK, 0x0C000000)
        self.assertFalse(P.CTRL_MASK & (1 << 25),
                         "PCAP_RATE_EN must not be required; §5e forbids adjusting CTRL")
        self.assertEqual(P.CTRL_HISTORICAL_17A6 & P.CTRL_MASK, P.CTRL_REQUIRED)

    def test_pcfg_done_precondition_is_present(self):
        plan = P.build_plan(0x00000B99, "one-bidirectional", 0xA5A5A5A5)
        steps = [s for s in plan["uboot_script"] if s["step"] == "pcfg-done"]
        self.assertEqual(len(steps), 1)
        self.assertIn(f"{P.INT_STS_PCFG_DONE:#x}", steps[0]["why"])


class TheSentinelAndTheCache(unittest.TestCase):

    def test_a_zero_sentinel_is_refused(self):
        with self.assertRaises(ValueError):
            P.build_plan(0x00000B99, "one-bidirectional", 0)

    def test_the_sentinel_is_filled_and_verified_before_any_dma_register_write(self):
        plan = P.build_plan(0x00000B99, "two-unidirectional", 0xA5A5A5A5)
        steps = [s["step"] for s in plan["uboot_script"]]
        self.assertLess(steps.index("sentinel-verify"),
                        min(i for i, s in enumerate(steps) if s.startswith("dma-")),
                        "the sentinel must be verified before the DMA can write the buffer")

    def test_the_cache_is_disabled_before_the_prefill(self):
        plan = P.build_plan(0x00000B99, "one-bidirectional", 0xA5A5A5A5)
        steps = [s["step"] for s in plan["uboot_script"]]
        self.assertLess(steps.index("cache"), steps.index("sentinel-fill"))

    def test_the_adjudicated_slice_is_the_second_frame_only(self):
        plan = P.build_plan(0x00000B99, "one-bidirectional", 0xA5A5A5A5)
        self.assertEqual(plan["adjudicated_slice"], [101, 202])


class ThePlannerNeverTouchesABoard(unittest.TestCase):

    FORBIDDEN_MODULES = {"serial", "subprocess", "socket", "pexpect", "telnetlib",
                         "os", "shutil", "requests", "urllib"}

    def test_the_planner_imports_nothing_that_could_reach_a_board(self):
        """AST, not a substring scan.

        The first version of this guard searched the source text for "serial" and failed
        on the docstring sentence saying the planner opens no serial port -- a guard that
        cannot tell prose from code is not a guard.  Imports are structure, so read the
        structure.
        """
        tree = ast.parse((REPO_ROOT / "scripts/pcap_probe_plan.py").read_text())
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        offending = imported & self.FORBIDDEN_MODULES
        self.assertEqual(offending, set(),
                         f"the planner must not be able to reach a board: {offending}")

    def test_the_guard_above_would_notice_an_import(self):
        """Discriminating-power check: the same walk on a module that does import one."""
        tree = ast.parse("import serial\nfrom subprocess import run\n")
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        self.assertEqual(imported & self.FORBIDDEN_MODULES, {"serial", "subprocess"})

    def test_no_shell_or_eval_escape_hatch(self):
        tree = ast.parse((REPO_ROOT / "scripts/pcap_probe_plan.py").read_text())
        called = {n.func.id for n in ast.walk(tree)
                  if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
        self.assertEqual(called & {"eval", "exec", "compile", "__import__"}, set())

    def test_running_it_produces_a_plan_and_says_it_did_nothing(self):
        out = subprocess.run(
            [sys.executable, "scripts/pcap_probe_plan.py",
             "--dma-order", "one-bidirectional", "--json"],
            cwd=REPO_ROOT, capture_output=True, text=True, check=True).stdout
        self.assertIn('"board_action": "NONE', out)




class UG470StepsAreAccountedFor(unittest.TestCase):
    """Every step of the vendor procedure is either performed or refused with a reason."""

    SEQ = (REPO_ROOT / "docs/s0_derived_sequence.md").read_text()

    def section_3a(self) -> str:
        start = self.SEQ.index("### 3a.")
        end = self.SEQ.index("### 3b.")
        return self.SEQ[start:end]

    def test_the_step_table_covers_all_fifteen_steps(self):
        """Scoped to §3a's table; the document has other tables whose rows start with
        digits, and a whole-file scan picked those up instead."""
        rows = re.findall(r"^\| (?:\*\*)?(\d+)[ a-zA-Z]", self.section_3a(), re.M)
        self.assertEqual(sorted(int(r) for r in rows), list(range(1, 16)),
                         "the UG470 step table must account for steps 1..15")

    def test_shutdown_and_start_are_refused_not_merely_absent(self):
        flat = " ".join(self.SEQ.replace("*", "").split())
        for step in ("3 SHUTDOWN + NOOP | NO", "12 START + NOOP | NO"):
            with self.subTest(step=step):
                self.assertIn(step, flat)
        self.assertRegex(flat, r"DONE goes Low during the shutdown sequence")

    def test_no_produced_word_is_shutdown_start_or_rcrc(self):
        produced = set(P.readback_commands(0x00000B99)) | set(P.cleanup_commands())
        for name, code in (("SHUTDOWN", 0x0000000B), ("START", 0x00000005),
                           ("RCRC", 0x00000007)):
            with self.subTest(cmd=name):
                self.assertNotIn(code, produced,
                                 f"{name} reached the stream; §5c forbids it")

    def test_desync_is_issued_in_the_cleanup(self):
        self.assertIn(0x0000000D, P.cleanup_commands())
        self.assertEqual(P.cleanup_commands()[0], 0x20000000)

    def test_the_cost_of_deviating_is_recorded(self):
        flat = " ".join(self.SEQ.replace("*", "").split())
        self.assertRegex(flat, r"UG470 documents no non-shutdown configuration-memory "
                               r"readback")
        self.assertRegex(flat, r"cannot exclude it")


class StaleStatusIsClearedAndVerified(unittest.TestCase):

    def test_the_clear_mask_covers_completion_and_errors(self):
        self.assertEqual(P.INT_STS_CLEAR_MASK, 0x00F4F840)
        self.assertTrue(P.INT_STS_CLEAR_MASK & 0x1000, "D_P_DONE must be cleared")
        self.assertTrue(P.INT_STS_CLEAR_MASK & 0x2000, "DMA_DONE must be cleared")
        self.assertEqual(P.INT_STS_CLEAR_MASK & P.INT_STS_ERROR_MASK,
                         P.INT_STS_ERROR_MASK)

    def test_pcfg_done_is_never_cleared(self):
        self.assertFalse(P.INT_STS_CLEAR_MASK & 0x4,
                         "clearing PCFG_DONE destroys the precondition for the readback")

    def test_every_dma_command_clears_verifies_and_waits_in_that_order(self):
        """Per command, not once per plan.

        The first version cleared once before the first DMA, so under two-unidirectional
        the command transfer's D_P_DONE satisfied the readback transfer's wait
        immediately and the buffer would have been read out before the readback happened.
        """
        for order in ("two-unidirectional", "one-bidirectional"):
            plan = P.build_plan(0x00000B99, order, 0xA5A5A5A5)
            steps = [s["step"] for s in plan["uboot_script"]]
            names = [s.split("dma-", 1)[1] for s in steps if s.startswith("dma-")]
            for name in dict.fromkeys(names):
                with self.subTest(order=order, dma=name):
                    i_clear = steps.index(f"clear-{name}")
                    i_verify = steps.index(f"clear-verify-{name}")
                    i_prog = steps.index(f"dma-{name}")
                    i_wait = steps.index(f"wait-{name}")
                    self.assertLess(i_clear, i_verify)
                    self.assertLess(i_verify, i_prog)
                    self.assertLess(i_prog, i_wait)

    def test_the_cleanup_dma_is_not_exempt(self):
        for order in ("two-unidirectional", "one-bidirectional"):
            plan = P.build_plan(0x00000B99, order, 0xA5A5A5A5)
            steps = [s["step"] for s in plan["uboot_script"]]
            with self.subTest(order=order):
                self.assertIn("clear-cleanup", steps)
                self.assertIn("clear-verify-cleanup", steps)
                self.assertIn("wait-cleanup", steps,
                              "without a wait, DESYNC is never known to be delivered")

    def test_the_clear_count_matches_the_dma_count(self):
        two = P.build_plan(0x00000B99, "two-unidirectional", 0xA5A5A5A5)["uboot_script"]
        one = P.build_plan(0x00000B99, "one-bidirectional", 0xA5A5A5A5)["uboot_script"]
        for plan, expect in ((two, 3), (one, 2)):
            clears = [s for s in plan if s["step"].startswith("clear-verify-")]
            waits = [s for s in plan if s["step"].startswith("wait-")]
            self.assertEqual(len(clears), expect)
            self.assertEqual(len(waits), expect)

    def test_every_clear_is_a_write_naming_the_mask(self):
        plan = P.build_plan(0x00000B99, "two-unidirectional", 0xA5A5A5A5)
        clears = [s for s in plan["uboot_script"] if s["step"].startswith("clear-")
                  and not s["step"].startswith("clear-verify-")]
        self.assertTrue(clears)
        for c in clears:
            self.assertTrue(c["cmd"].startswith("mw.l"), "write-to-clear needs a write")
            self.assertIn(f"{P.INT_STS_CLEAR_MASK:#010x}", c["cmd"])

    def test_cleanup_runs_after_the_readout(self):
        plan = P.build_plan(0x00000B99, "one-bidirectional", 0xA5A5A5A5)
        steps = [s["step"] for s in plan["uboot_script"]]
        self.assertLess(steps.index("readout"), steps.index("cleanup-word"))
        self.assertIn("dma-cleanup", steps)
        self.assertEqual(steps[-1], "status-final")


class ScopeIsStatedHonestly(unittest.TestCase):

    SEQ = (REPO_ROOT / "docs/s0_derived_sequence.md").read_text()
    OWNER = (REPO_ROOT / "docs/pcap_probe_spec.md").read_text()
    README = (REPO_ROOT / "README.md").read_text()

    def test_no_document_claims_s0_is_complete(self):
        for name, text in (("s0_derived_sequence.md", self.SEQ),
                           ("pcap_probe_spec.md", self.OWNER),
                           ("README.md", self.README)):
            with self.subTest(doc=name):
                # Pipes are stripped too: a status row "| S0 | delivered |" is an
                # affirmative claim, and leaving the pipes in let it slip past.
                flat = " ".join(text.replace("*", "").replace("|", " ").split())
                # An affirmative claim only: "S0 is complete only when ..." and
                # "S0 is NOT complete" are the statements this repo must be making.
                for m in re.finditer(r"S0 (?:is |as a whole )?(?:complete|delivered|"
                                     r"passed)\b", flat):
                    tail = flat[m.end():m.end() + 30]
                    head = flat[max(0, m.start() - 30):m.start()]
                    self.assertTrue(
                        tail.lstrip().startswith("only when") or "NOT" in head
                        or "not" in head,
                        f"{name} asserts S0 completion: ...{flat[m.start()-40:m.end()+40]}...")

    def test_the_split_is_in_the_governing_document(self):
        flat = " ".join(self.OWNER.replace("*", "").split())
        self.assertRegex(flat, r"S0a")
        self.assertRegex(flat, r"S0b")
        self.assertRegex(flat, r"not started")

    def test_the_readme_heading_matches_the_stage(self):
        """The status block said S0a while the heading above it still said M0."""
        heading = re.search(r"^## Status — (.+)$", self.README, re.M)
        self.assertIsNotNone(heading, "README has no status heading")
        self.assertNotIn("M0", heading.group(1),
                         f"the heading still announces M0: {heading.group(1)!r}")
        self.assertIn("S0a", heading.group(1))

    def test_the_runner_is_named_as_missing(self):
        flat = " ".join(self.SEQ.replace("*", "").split())
        self.assertRegex(flat, r"runner is not written")

    def test_the_stage_table_says_s0_is_not_complete(self):
        """Parse the row rather than scan the prose: the row is the load-bearing claim."""
        row = re.search(r"^\|\s*\*\*S0\*\*\s*\|\s*(.+?)\s*\|\s*$",
                        self.SEQ, re.M)
        self.assertIsNotNone(row, "the stage table has no S0 row")
        self.assertRegex(row.group(1), r"NOT complete",
                         f"the S0 row claims {row.group(1)!r}")

    def test_the_stage_table_lists_s0b_as_not_started(self):
        row = re.search(r"^\|\s*\*\*S0b[^|]*\|\s*(.+?)\s*\|\s*$", self.SEQ, re.M)
        self.assertIsNotNone(row, "the stage table has no S0b row")
        self.assertRegex(row.group(1), r"not started")

    def test_settling_8a_is_a_precondition_for_s0(self):
        flat = " ".join(self.OWNER.replace("*", "").split())
        self.assertRegex(flat, r"S0 is complete only when S0b exists AND .{0,40}8a")



class TransactionsAndStreamsAreAdjudicatedWhole(unittest.TestCase):
    """Field-by-field legality is not enough.

    Every case below was demonstrated by review against a checker whose individual
    field checks all passed.  Legal values can combine into an illegal operation.
    """

    def _plan(self, order="one-bidirectional"):
        return P.build_plan(0x00000B99, order, 0xA5A5A5A5)

    def _reject(self, plan) -> str:
        P.check_allowlist(plan)
        with self.assertRaises(ValueError, msg="the plan was accepted") as cm:
            P.check_value_policy(plan)
        return str(cm.exception)

    # --- whole DMA transactions ---------------------------------------------------

    def test_swapping_source_and_destination_is_refused(self):
        """Each field legal, the tuple catastrophic: the readback would overwrite the
        command buffer and read 202 words out of a 43-word source."""
        plan = self._plan()
        for reg, val in ((0xF8007018, P.DST_BUF | 1), (0xF800701C, P.CMD_BUF | 1),
                         (0xF8007020, 202), (0xF8007024, 202)):
            plan["uboot_script"].append(
                {"step": "x", "cmd": f"mw.l {reg:#010x} {val:#x} 1", "why": "",
                 "addresses": [reg]})
        self.assertIn("not a permitted DMA transaction", self._reject(plan))

    def test_only_the_four_tuples_are_legal(self):
        self.assertEqual(len(P.LEGAL_DMA_TRANSACTIONS), 4)
        self.assertEqual(
            P.LEGAL_DMA_TRANSACTIONS,
            {"command":       (P.CMD_BUF | 1, 0xFFFFFFFF, 43, 43),
             "readback":      (0xFFFFFFFF, P.DST_BUF | 1, 202, 202),
             "bidirectional": (P.CMD_BUF | 1, P.DST_BUF | 1, 43, 202),
             "cleanup":       (P.CMD_BUF | 1, 0xFFFFFFFF, 5, 5)})

    def test_the_plans_only_issue_those_tuples(self):
        legal = set(P.LEGAL_DMA_TRANSACTIONS.values())
        for order, expect in (("two-unidirectional", 3), ("one-bidirectional", 2)):
            with self.subTest(order=order):
                txs = P.dma_transactions(self._plan(order))
                self.assertEqual(len(txs), expect)
                for tx in txs:
                    self.assertIn(tx, legal)

    def test_registers_written_out_of_order_are_refused(self):
        plan = self._plan()
        plan["uboot_script"].append(
            {"step": "x", "cmd": "mw.l 0xf8007024 43 1", "why": "",
             "addresses": [0xF8007024]})
        self.assertIn("out of order", self._reject(plan))

    def test_an_unqueued_partial_transaction_is_refused(self):
        plan = self._plan()
        plan["uboot_script"].append(
            {"step": "x", "cmd": f"mw.l 0xf8007018 {P.CMD_BUF | 1:#x} 1", "why": "",
             "addresses": [0xF8007018]})
        self.assertIn("incomplete", self._reject(plan))

    # --- the exact streams --------------------------------------------------------

    def test_the_repeat_count_is_expanded(self):
        """`mw.l CMD_BUF 0x20000000 43` really writes 43 NOOPs; the checker must see 43."""
        plan = self._plan()
        plan["uboot_script"] = [s for s in plan["uboot_script"]
                                if s["step"] != "cmd-word"]
        plan["uboot_script"].insert(
            3, {"step": "cmd-word", "cmd": f"mw.l {P.CMD_BUF:#010x} 0x20000000 43",
                "why": "", "addresses": [P.CMD_BUF]})
        self.assertIn("expected 0xffffffff", self._reject(plan))

    def test_a_gap_in_the_stream_is_refused(self):
        plan = self._plan()
        plan["uboot_script"] = [s for s in plan["uboot_script"]
                                if not (s["step"] == "cmd-word"
                                        and "0x10200008" in s["cmd"])]
        self.assertIn("gap", self._reject(plan))

    def test_a_stream_not_starting_at_the_buffer_base_is_refused(self):
        plan = self._plan()
        plan["uboot_script"] = [s for s in plan["uboot_script"]
                                if not (s["step"] == "cmd-word"
                                        and s["cmd"].split()[1] == f"{P.CMD_BUF:#010x}")]
        self.assertIn("buffer base", self._reject(plan))

    def test_the_target_far_is_pinned_in_the_stream(self):
        plan = self._plan()
        for s in plan["uboot_script"]:
            if s["step"] == "cmd-word" and s["cmd"].split()[1] == "0x10200020":
                s["cmd"] = "mw.l 0x10200020 0x00000a20 1"
        self.assertIn("expected 0x00000b99", self._reject(plan))

    def test_structurally_broken_streams_are_refused(self):
        good = P.readback_commands(0x00000B99)
        cases = {
            "FAR write with no payload": good[:8],
            "Type-2 count 1": good[:10] + [0x48000001] + good[11:],
            "Type-1 read CMD instead of FDRO": good[:9] + [0x28008000] + good[10:],
            "FAR write count 2": good[:7] + [0x30002002] + good[8:],
            "a flush word that is not a NOOP": good[:42] + [0xDEADBEEF],
            "SHUTDOWN spliced in": good[:5] + [0x0000000B] + good[6:],
        }
        for name, words in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(ValueError):
                    P.validate_readback_stream(words, 0x00000B99)

    def test_a_stream_of_the_wrong_length_is_refused_in_both_directions(self):
        """R10: a length check relaxed to a lower bound survived, because every case
        tested was shorter than the bound.  Test one word too many as well."""
        good = P.readback_commands(0x00000B99)
        for name, words in (("one short", good[:-1]),
                            ("one long", good + [0x20000000]),
                            ("empty", [])):
            with self.subTest(case=name):
                with self.assertRaises(ValueError) as cm:
                    P.validate_readback_stream(words, 0x00000B99)
                self.assertIn("not 43", str(cm.exception))

    def test_a_corrupted_cleanup_stream_is_caught_through_a_plan(self):
        """R12: calling the validator directly passed while nothing wired it in."""
        plan = self._plan()
        for step in plan["uboot_script"]:
            if step["step"] == "cleanup-word" and step["cmd"].split()[1] == "0x10200008":
                step["cmd"] = "mw.l 0x10200008 0x00000005 1"      # START, not DESYNC
        self.assertIn("expected 0x0000000d", self._reject(plan))

    def test_a_cleanup_stream_of_the_wrong_length_is_caught_through_a_plan(self):
        plan = self._plan()
        plan["uboot_script"] = [s for s in plan["uboot_script"]
                                if not (s["step"] == "cleanup-word"
                                        and s["cmd"].split()[1] == "0x10200010")]
        self.assertIn("not 5", self._reject(plan))

    def test_the_cleanup_stream_is_pinned_exactly(self):
        P.validate_cleanup_stream(P.cleanup_commands())
        for bad in ([0x20000000] * 5, P.cleanup_commands()[:4],
                    [0x20000000, 0x30008001, 0x00000005, 0x20000000, 0x20000000]):
            with self.subTest(bad=[f"{w:#x}" for w in bad]):
                with self.assertRaises(ValueError):
                    P.validate_cleanup_stream(bad)

    def test_exactly_two_streams_are_expected(self):
        plan = self._plan()
        plan["uboot_script"] = [s for s in plan["uboot_script"]
                                if s["step"] != "cleanup-word"]
        self.assertIn("exactly two", self._reject(plan))

    # --- the per-register policies that remain ------------------------------------

    def test_ctrl_and_status_are_read_only(self):
        for reg in (0xF8007000, 0xF8007014):
            with self.subTest(reg=hex(reg)):
                plan = self._plan()
                plan["uboot_script"].append(
                    {"step": "x", "cmd": f"mw.l {reg:#010x} 0x0 1", "why": "",
                     "addresses": [reg]})
                self.assertIn("read-only", self._reject(plan))

    def test_int_sts_accepts_only_the_exact_clear_mask(self):
        plan = self._plan()
        plan["uboot_script"].append(
            {"step": "x", "cmd": "mw.l 0xf800700c 0xffffffff 1", "why": "",
             "addresses": [0xF800700C]})
        self.assertIn("clear mask", self._reject(plan))

    def test_the_legitimate_plans_pass(self):
        """Discriminating power: the policy must not reject what it guards."""
        for order in ("two-unidirectional", "one-bidirectional"):
            with self.subTest(order=order):
                plan = self._plan(order)
                P.check_allowlist(plan)
                P.check_value_policy(plan)

    def test_the_stream_validators_do_not_call_the_generator(self):
        """A stream checked against its own generator proves only self-consistency."""
        src = (REPO_ROOT / "scripts/pcap_probe_plan.py").read_text()
        tree = ast.parse(src)
        for name in ("validate_readback_stream", "validate_cleanup_stream"):
            fn = next(n for n in ast.walk(tree)
                      if isinstance(n, ast.FunctionDef) and n.name == name)
            called = {n.func.id for n in ast.walk(fn)
                      if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
            with self.subTest(fn=name):
                self.assertEqual(
                    called & {"readback_commands", "cleanup_commands", "type1", "type2"},
                    set(), f"{name} validates against the generator")

    def test_build_plan_runs_every_check(self):
        src = (REPO_ROOT / "scripts/pcap_probe_plan.py").read_text()
        fn = next(n for n in ast.walk(ast.parse(src))
                  if isinstance(n, ast.FunctionDef) and n.name == "build_plan")
        called = {n.func.id for n in ast.walk(fn)
                  if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
        self.assertIn("check_allowlist", called)
        self.assertIn("check_value_policy", called)


class TheWholeScheduleIsValidated(unittest.TestCase):
    """Legal parts in an illegal order.

    Every case below was assembled by review out of transactions and streams that each
    pass their own check.  The schedule is derived from the commands, never from `step`
    names, which a plan is free to lie about.
    """

    def _plan(self, order="one-bidirectional"):
        return P.build_plan(0x00000B99, order, 0xA5A5A5A5)

    def _reject(self, plan) -> str:
        P.check_allowlist(plan)
        with self.assertRaises(ValueError, msg="the plan was accepted") as cm:
            P.check_value_policy(plan)
        return str(cm.exception)

    def test_the_real_transfer_replaced_by_a_second_cleanup(self):
        plan = self._plan()
        for step in plan["uboot_script"]:
            c = step["cmd"]
            if c.startswith("mw.l 0xf8007020"):
                step["cmd"] = "mw.l 0xf8007020 5 1"
            elif c.startswith("mw.l 0xf8007024"):
                step["cmd"] = "mw.l 0xf8007024 5 1"
            elif c.startswith("mw.l 0xf800701c"):
                step["cmd"] = "mw.l 0xf800701c 0xffffffff 1"
        self.assertIn("transaction sequence", self._reject(plan))

    def test_an_extra_legal_cleanup_is_refused(self):
        plan = self._plan()
        tail = [dict(s) for s in plan["uboot_script"][-7:]]
        plan["uboot_script"].extend(tail)
        self.assertIn("schedule", self._reject(plan))

    def test_the_cleanup_stream_cannot_be_written_before_the_main_transfer(self):
        """Both phases stay legal and [43, 5] is still seen, but the transfer that fires
        would send the cleanup stream."""
        plan = self._plan()
        cleanup = [s for s in plan["uboot_script"] if s["step"] == "cleanup-word"]
        for s in cleanup:
            plan["uboot_script"].remove(s)
        first_clear = min(i for i, s in enumerate(plan["uboot_script"])
                          if s["cmd"].startswith(f"mw.l {P.REG['INT_STS']:#010x}"))
        plan["uboot_script"][first_clear:first_clear] = cleanup
        self.assertIn("diverges", self._reject(plan))

    def test_a_clear_between_the_trigger_and_the_wait_is_refused(self):
        """It would erase the completion the wait is looking for: a manufactured
        timeout on a transfer that actually succeeded."""
        plan = self._plan()
        trigger = next(i for i, s in enumerate(plan["uboot_script"])
                       if s["cmd"].startswith(f"mw.l {P.REG['DMA_DEST_LEN']:#010x}"))
        plan["uboot_script"].insert(
            trigger + 1,
            {"step": "x",
             "cmd": f"mw.l {P.REG['INT_STS']:#010x} {P.INT_STS_CLEAR_MASK:#010x} 1",
             "why": "", "addresses": [P.REG["INT_STS"]]})
        self.assertIn("diverges", self._reject(plan))

    def test_removing_any_single_step_is_refused(self):
        """Deletion, not only insertion."""
        for order in ("two-unidirectional", "one-bidirectional"):
            n = len(self._plan(order)["uboot_script"])
            for i in range(n):
                plan = self._plan(order)
                dropped = plan["uboot_script"].pop(i)
                with self.subTest(order=order, i=i, cmd=dropped["cmd"]):
                    P.check_allowlist(plan)
                    with self.assertRaises(ValueError):
                        P.check_value_policy(plan)

    def test_the_expected_transaction_sequences_are_pinned(self):
        self.assertEqual(P.EXPECTED_TRANSACTIONS,
                         {"two-unidirectional": ["command", "readback", "cleanup"],
                          "one-bidirectional": ["bidirectional", "cleanup"]})
        for order, want in P.EXPECTED_TRANSACTIONS.items():
            with self.subTest(order=order):
                by_tuple = {v: k for k, v in P.LEGAL_DMA_TRANSACTIONS.items()}
                got = [by_tuple[tx] for tx in P.dma_transactions(self._plan(order))]
                self.assertEqual(got, want)

    def test_the_four_register_writes_are_contiguous(self):
        """Nothing may sit between them, and nothing between the trigger and the wait."""
        for order in ("two-unidirectional", "one-bidirectional"):
            toks = P.schedule_tokens(self._plan(order))
            for i, tok in enumerate(toks):
                if tok == "DMA_SRC_ADDR":
                    with self.subTest(order=order, at=i):
                        self.assertEqual(
                            toks[i:i + 5],
                            ["DMA_SRC_ADDR", "DMA_DEST_ADDR", "DMA_SRC_LEN",
                             "DMA_DEST_LEN", "READ_INT_STS"])
                        self.assertEqual(toks[i - 2:i], ["CLEAR", "READ_INT_STS"])

    def test_the_schedule_is_derived_from_commands_not_step_names(self):
        """Renaming every step must change nothing."""
        for order in ("two-unidirectional", "one-bidirectional"):
            plan = self._plan(order)
            before = P.schedule_tokens(plan)
            for s in plan["uboot_script"]:
                s["step"] = "lie"
            with self.subTest(order=order):
                self.assertEqual(P.schedule_tokens(plan), before)
                P.check_schedule(plan)

    def test_an_unscheduled_command_is_refused(self):
        """Reads and writes both.  The first version tested only a read, so making the
        write branch fail open survived the whole suite."""
        cases = {
            "read of STATUS": f"md.l {P.REG['STATUS']:#010x} 1",
            "short read of the destination": f"md.l {P.DST_BUF:#010x} 1",
            "stray write into the destination": f"mw.l {P.DST_BUF:#010x} 0x1 1",
            "partial destination fill": f"mw.l {P.DST_BUF:#010x} 0xa5a5a5a5 0x10",
        }
        for name, cmd in cases.items():
            with self.subTest(case=name):
                plan = self._plan()
                plan["uboot_script"].append(
                    {"step": "x", "cmd": cmd, "why": "",
                     "addresses": P.addresses_in(cmd)})
                self.assertRegex(self._reject(plan), r"unscheduled|schedule")

    def test_the_legitimate_plans_pass_the_schedule(self):
        for order in ("two-unidirectional", "one-bidirectional"):
            with self.subTest(order=order):
                P.check_schedule(self._plan(order))


class TheSentinelIsAnOperandNotAnAbstraction(unittest.TestCase):
    """§6c only works if the pattern actually written is the pattern adjudicated.

    The schedule abstracted every correctly-sized destination write to "FILL_DST" and
    discarded the value, so a plan could serialize one prefill and record another.
    """

    def _plan(self, sentinel=0xA5A5A5A5, order="one-bidirectional"):
        return P.build_plan(0x00000B99, order, sentinel)

    def _set_fill(self, plan, value: int) -> None:
        for step in plan["uboot_script"]:
            parts = step["cmd"].split()
            if (parts[0] == "mw.l" and int(parts[1], 16) == P.DST_BUF
                    and int(parts[3], 0) == P.READBACK_WORDS):
                step["cmd"] = f"mw.l {P.DST_BUF:#010x} {value:#010x} {P.READBACK_WORDS:#x}"

    def _reject(self, plan) -> str:
        P.check_allowlist(plan)
        with self.assertRaises(ValueError, msg="the plan was accepted") as cm:
            P.check_value_policy(plan)
        return str(cm.exception)

    def test_a_serialized_zero_prefill_is_refused(self):
        """Zero makes 'the DMA never wrote' and 'the engine returned zeros' identical."""
        plan = self._plan()
        self._set_fill(plan, 0)
        self.assertIn("diverges", self._reject(plan))

    def test_a_prefill_that_disagrees_with_the_record_is_refused(self):
        plan = self._plan()
        self._set_fill(plan, 0xDEADBEEF)
        msg = self._reject(plan)
        self.assertIn("diverges", msg)
        self.assertIn("deadbeef", msg.lower())

    def test_a_recorded_sentinel_of_zero_is_refused(self):
        plan = self._plan()
        plan["sentinel"] = 0
        self.assertIn("non-zero 32-bit", self._reject(plan))

    def test_a_sentinel_wider_than_32_bits_is_refused_at_construction(self):
        """mw.l writes 32 bits; 0x100000000 truncates to exactly the excluded value."""
        for bad in (0x100000000, 0x1FFFFFFFF, 1 << 40):
            with self.subTest(sentinel=hex(bad)):
                with self.assertRaises(ValueError) as cm:
                    self._plan(sentinel=bad)
                self.assertIn("32-bit", str(cm.exception))

    def test_zero_and_negative_are_refused_at_construction(self):
        for bad in (0, -1):
            with self.subTest(sentinel=bad):
                with self.assertRaises(ValueError):
                    self._plan(sentinel=bad)

    def test_the_boundary_values_are_accepted(self):
        """Discriminating power: the range must not reject its own endpoints."""
        for good in (1, 0xFFFFFFFF, 0xA5A5A5A5):
            with self.subTest(sentinel=hex(good)):
                plan = self._plan(sentinel=good)
                P.check_allowlist(plan)
                P.check_value_policy(plan)

    def test_the_token_carries_the_value_and_the_count(self):
        toks = P.schedule_tokens(self._plan(sentinel=0x12345678))
        fill = [t for t in toks if isinstance(t, tuple) and t[0] == "FILL_DST"]
        self.assertEqual(fill, [("FILL_DST", 0x12345678, P.READBACK_WORDS)])

    def test_the_expected_schedule_depends_on_the_sentinel(self):
        a = P.expected_schedule("one-bidirectional", 0xA5A5A5A5)
        b = P.expected_schedule("one-bidirectional", 0x5A5A5A5A)
        self.assertNotEqual(a, b, "the expectation must move with the sentinel")

    def test_the_sentinel_is_checked_before_any_plan_is_built(self):
        """Defence in depth, pinned structurally because it is not observable.

        Removing `check_sentinel` from `build_plan` is an equivalent mutant behaviourally:
        `expected_schedule` calls it too, so the plan is still refused, just later and
        after an out-of-range value has been formatted into a command string. The early
        refusal is deliberate, so it is asserted where it can be seen -- in the call
        graph.
        """
        tree = ast.parse((REPO_ROOT / "scripts/pcap_probe_plan.py").read_text())
        for fname in ("build_plan", "expected_schedule"):
            fn = next(n for n in ast.walk(tree)
                      if isinstance(n, ast.FunctionDef) and n.name == fname)
            called = {n.func.id for n in ast.walk(fn)
                      if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
            with self.subTest(fn=fname):
                self.assertIn("check_sentinel", called,
                              f"{fname} must refuse an illegal sentinel itself")

    def test_only_one_definition_decides_what_a_legal_sentinel_is(self):
        """Two range checks drift apart; there must be exactly one.

        Written against the AST: a substring count of "0xFFFFFFFF" also matched the
        unrelated FAR range check, which made this a guard that failed on correct code.
        """
        tree = ast.parse((REPO_ROOT / "scripts/pcap_probe_plan.py").read_text())
        comparisons = [
            n for n in ast.walk(tree)
            if isinstance(n, ast.Compare)
            and any(isinstance(x, ast.Name) and x.id == "sentinel"
                    for x in [n.left] + list(n.comparators))
        ]
        self.assertEqual(
            len(comparisons), 1,
            f"the sentinel range is compared in {len(comparisons)} places; it must be "
            f"stated once, in check_sentinel")
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef) and n.name == "check_sentinel")
        self.assertIn(comparisons[0], list(ast.walk(fn)),
                      "the one comparison must live in check_sentinel")

    def test_the_cli_refuses_an_out_of_range_sentinel(self):
        with self.assertRaises(ValueError):
            P.main(["--dma-order", "one-bidirectional", "--sentinel", "0x100000000"])


class TheMeasuredOrderIsNotSaidToAgree(unittest.TestCase):

    def test_no_sentence_claims_the_measured_order_agrees_with_ug470(self):
        flat = " ".join(SEQ_DOC.replace("*", "").replace("`", "").split())
        self.assertNotRegex(
            flat, r"FAR . RCFG[^.]{0,80}agrees with UG470",
            "the measured order diverges from UG470; §3c adjudicates it")
        self.assertRegex(flat, r"diverges from. UG470|diverges from UG470")

if __name__ == "__main__":
    unittest.main()
