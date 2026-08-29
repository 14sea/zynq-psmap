"""S0's guards: the planner must agree with the pinned document, and refuse what the
specification refuses.

The tests are written to fail when the *document* and the *code* drift apart in either
direction, because a pinned constant that lives in only one of the two is not pinned.
"""
from __future__ import annotations

import ast
import os
import re
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

from markdown_it import MarkdownIt

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

    def test_the_pinned_dma_order_is_the_default_now_that_8a_is_resolved(self):
        """While §8a was open there was deliberately no default.  It is resolved, so the
        default is the pinned reading -- and the pin must be the unidirectional one."""
        self.assertEqual(P.PINNED_DMA_ORDER, "two-unidirectional")
        self.assertEqual(P.ALTERNATIVE_DMA_ORDER, "one-bidirectional")
        plan = P.build_plan(0x00000B99, P.PINNED_DMA_ORDER, 0xA5A5A5A5)
        self.assertEqual(plan["pinned_dma_order"], "two-unidirectional")
        self.assertEqual(P.EXPECTED_TRANSACTIONS[P.PINNED_DMA_ORDER],
                         ["command", "readback", "cleanup"])

    def test_8a_is_no_longer_listed_as_unresolved(self):
        plan = P.build_plan(0x00000B99, P.PINNED_DMA_ORDER, 0xA5A5A5A5)
        self.assertNotIn("8a", " ".join(plan["unresolved"]))
        self.assertRegex(" ".join(plan["unresolved"]), r"8b")

    def test_the_candidate_diagnoses_are_not_named_as_a_causal_mapping(self):
        """The plan may list generic error stops; it may not claim they reveal a wrong pin.

        The earlier fields were `discriminating_stop.pinned_reading_wrong` and
        `*_ALTERNATIVE_WRONG` -- names that assert exactly the causal mapping UG585's
        INT_STS table does not establish.
        """
        plan = P.build_plan(0x00000B99, P.PINNED_DMA_ORDER, 0xA5A5A5A5)
        self.assertNotIn("discriminating_stop", plan)
        self.assertIn("candidate_diagnoses", plan)
        self.assertRegex(plan["candidate_diagnoses_note"],
                         r"not exclusive, not necessary")
        self.assertRegex(plan["candidate_diagnoses_note"],
                         r"cannot fail silently")
        for name in ("DMA_CMD_ERR", "P2D_LEN_ERR"):
            with self.subTest(bit=name):
                self.assertIn(name, plan["candidate_diagnoses"])
                self.assertTrue(P.INT_STS_ERROR_MASK & P.CANDIDATE_DIAGNOSIS_BITS[name],
                                "a candidate diagnosis must already be a stop")
        self.assertEqual(P.CANDIDATE_DIAGNOSIS_BITS,
                         {"DMA_CMD_ERR": 1 << 15, "P2D_LEN_ERR": 1 << 11})

    BANNED_NAMES = ("PINNED_WRONG", "ALTERNATIVE_WRONG", "discriminating_stop",
                    "pinned_reading_wrong", "alternative_wrong")

    def test_no_symbol_or_field_names_a_wrong_pin(self):
        """Identifiers and dict keys, via the AST.

        A substring scan fails on the comment that records the withdrawn names as
        history -- the same class of error as the guard that tripped on "S0 is NOT
        complete". What must not come back is a *name*, not a mention.
        """
        tree = ast.parse((REPO_ROOT / "scripts/pcap_probe_plan.py").read_text())
        used = set()
        for n in ast.walk(tree):
            if isinstance(n, ast.Name):
                used.add(n.id)
            elif isinstance(n, ast.Attribute):
                used.add(n.attr)
            elif isinstance(n, ast.Constant) and isinstance(n.value, str):
                used.add(n.value)
        for banned in self.BANNED_NAMES:
            with self.subTest(name=banned):
                self.assertFalse(
                    any(banned in u for u in used),
                    f"{banned} is used as an identifier or key again")

    def test_the_withdrawn_names_are_still_recorded_as_withdrawn(self):
        """The comment that a substring scan tripped on is load-bearing: keep it."""
        src = (REPO_ROOT / "scripts/pcap_probe_plan.py").read_text()
        self.assertIn("PINNED_WRONG", src, "the retraction comment must stay")
        # the comment wraps, so the continuation "#" sits between the words
        self.assertRegex(src, r"establishes no such causal[\s#]+mapping")

    def test_the_alternative_is_not_tied_to_one_error_bit(self):
        """Flattened, including Python string continuations.

        The first version used a bounded gap between "alternative" and "after a
        DMA_CMD_ERR"; in the source those words are separated by a quote, a newline and
        25 spaces of indentation, so the mutation that re-tied the alternative to one bit
        survived.
        """
        # "not only after" was in this list and sits in the legitimate sentence itself,
        # so it excused the very mutation the guard exists to catch. Retraction markers
        # must be words that only a retraction would use.
        history = ("was tied", "An earlier", "earlier version", "withdrawn causal",
                   "no longer gated")
        for name, path in (("s0_derived_sequence.md",
                            REPO_ROOT / "docs/s0_derived_sequence.md"),
                           ("pcap_probe_plan.py",
                            REPO_ROOT / "scripts/pcap_probe_plan.py"),
                           ("pcap_probe_spec.md",
                            REPO_ROOT / "docs/pcap_probe_spec.md"),
                           ("README.md", REPO_ROOT / "README.md")):
            flat = " ".join(path.read_text().replace('"', " ").replace("*", "").split())
            for m in re.finditer(r"after (?:a|an) \w*_?ERR", flat):
                window = flat[max(0, m.start() - 100):m.end() + 60]
                with self.subTest(doc=name, at=m.group(0)):
                    self.assertTrue(
                        any(h in window for h in history),
                        f"{name} gates the alternative on one bit: ...{window}...")

    def test_the_alternative_is_retained_and_still_fully_checked(self):
        plan = P.build_plan(0x00000B99, P.ALTERNATIVE_DMA_ORDER, 0xA5A5A5A5)
        P.check_allowlist(plan)
        P.check_value_policy(plan)

    def test_both_readings_are_implemented(self):
        two = P.dma_commands("two-unidirectional", 43, 202)
        one = P.dma_commands("one-bidirectional", 43, 202)
        self.assertEqual(len(two), 2)
        self.assertEqual(len(one), 1)
        self.assertEqual(two[0]["DMA_DEST_ADDR"], P.PCAP_ENDPOINT)
        self.assertEqual(two[1]["DMA_SRC_ADDR"], P.PCAP_ENDPOINT)
        self.assertEqual(one[0]["DMA_SRC_LEN"], 43)
        self.assertEqual(one[0]["DMA_DEST_LEN"], 202)

    def test_the_plan_reports_its_remaining_unresolved_items(self):
        """§8a is resolved; §8b is not, and the plan must keep saying so."""
        plan = P.build_plan(0x00000B99, "two-unidirectional", 0xA5A5A5A5)
        self.assertTrue(plan["unresolved"])
        self.assertRegex(" ".join(plan["unresolved"]), r"8b")
        self.assertNotRegex(" ".join(plan["unresolved"]), r"8a")

    def test_the_document_records_8a_as_resolved_and_8b_as_open(self):
        flat = " ".join(SEQ_DOC.replace("*", "").split())
        self.assertRegex(flat, r"8a\..{0,120}RESOLVED: two")
        self.assertRegex(flat, r"8b\..{0,140}UNRESOLVED")

    def test_the_resolution_keeps_the_losing_reading_and_its_failed_argument(self):
        """Both are load-bearing: an alternative that is deleted cannot be tried, and a
        failed argument that is deleted gets reinvented."""
        start = SEQ_DOC.index("### 8a.")
        section = " ".join(SEQ_DOC[start:SEQ_DOC.index("### 8b.")].split())
        self.assertRegex(section, r"does NOT work",
                         "the argument that looked decisive and failed must stay")
        self.assertRegex(section, r"INT_PCAP_LPBK",
                         "the reason it fails must stay with it")
        self.assertRegex(section, r"retained, not deleted")
        self.assertRegex(section, r"never a retry inside one")
        self.assertRegex(section, r"is not adopted by the vendor's readback API",
                         "the driver shows non-adoption, not hardware refusal")
        self.assertNotRegex(
            section, r"bidirectional reading is now contradicted",
            "a path a driver does not implement is not a path the silicon refuses")
        self.assertRegex(section, r"non-secure.{0,40}enables|enables `MCTRL",
                         "the concurrent transfer types differ in loopback handling")
        self.assertRegex(section, r"DMA_CMD_ERR")
        self.assertRegex(section, r"P2D_LEN_ERR")

    def test_the_discrimination_claim_stays_narrow(self):
        """V5/V6: the overclaim must not come back.

        The earlier wording said a wrong pin would necessarily raise DMA_CMD_ERR or
        P2D_LEN_ERR and therefore "neither reading can fail silently". UG585's INT_STS
        table does not establish that causal mapping.
        """
        section = " ".join(SEQ_DOC[SEQ_DOC.index("### 8a."):
                                   SEQ_DOC.index("### 8b.")].split())
        self.assertIn("candidate diagnoses", section)
        self.assertRegex(section, r"not exclusive, not necessary")
        for overclaim in (r"neither reading can fail silently",
                          r"cannot fail silently"):
            for m in re.finditer(overclaim, section):
                window = section[max(0, m.start() - 80):m.end() + 20]
                with self.subTest(claim=overclaim):
                    self.assertRegex(
                        window, r"no claim is made|withdrawn|earlier version|That was",
                        f"the exclusivity overclaim is asserted again: ...{window}...")

    def test_the_correction_record_stays_with_the_conclusion(self):
        """V13: deleting 'this is what I had wrong' leaves a conclusion with no history."""
        section = " ".join(SEQ_DOC[SEQ_DOC.index("### 8a."):
                                   SEQ_DOC.index("### 8b.")].split())
        self.assertRegex(section, r"Corrected 2026-08-28 after review")
        self.assertRegex(section, r"That argument was wrong")
        self.assertRegex(section, r"Narrowed 2026-08-28 after review")

    def test_the_8b_heading_does_not_claim_resolution(self):
        """V10: 'UNRESOLVED' appearing later in the line is not enough."""
        heading = re.search(r"^### 8b\..*$", SEQ_DOC, re.M)
        self.assertIsNotNone(heading)
        # (?<!UN) matters: a bare "RESOLVED" also matches inside "UNRESOLVED".
        self.assertNotRegex(heading.group(0), r"(?<!UN)RESOLVED(?!\w)|[Ss]ettled")
        self.assertRegex(heading.group(0), r"\*\*UNRESOLVED\*\*$")

    def test_the_8a_heading_claims_exactly_the_pinned_reading(self):
        heading = re.search(r"^### 8a\..*$", SEQ_DOC, re.M)
        self.assertIsNotNone(heading)
        self.assertRegex(heading.group(0), r"RESOLVED: two")

    def test_the_documents_are_recorded_as_exhausted(self):
        section = " ".join(
            SEQ_DOC[SEQ_DOC.index("### 8a."):SEQ_DOC.index("### 8b.")].split())
        self.assertRegex(section, r"UG470 is silent")
        self.assertRegex(section, r"no .{0,12}devcfg.{0,40}driver documentation|"
                                  r"no `devcfg`/`XDcfg` driver")
        self.assertRegex(section, r"raw markup is a single `<ol>`|"
                                  r"contradiction is in the source")

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
        """Any completion word near "S0" must be negated, conditional, or reported speech.

        Two earlier versions of this guard were wrong in opposite directions: one matched
        only "S0 is complete" and so missed "S0 is now complete"; the widened one then
        fired on "S0 is NOT complete", because the negation sits inside the match rather
        than before it. The window therefore spans the match.
        """
        allowed = ("not", "NOT", "only when", "cannot", "calling", "described", "awaits")
        pattern = re.compile(
            r"\bS0\b(?![ab])(?:\W+\w+){0,3}?\W+"
            r"(?:complete|completed|delivered|passed)\b")
        for name, text in (("s0_derived_sequence.md", self.SEQ),
                           ("pcap_probe_spec.md", self.OWNER),
                           ("README.md", self.README)):
            flat = " ".join(text.replace("*", "").replace("|", " ").split())
            for m in pattern.finditer(flat):
                window = flat[max(0, m.start() - 60):m.end() + 40]
                with self.subTest(doc=name, at=m.group(0)):
                    self.assertTrue(
                        any(a in window for a in allowed),
                        f"{name} asserts S0 completion: ...{window}...")

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
        """The non-active endpoint's length is 0, as AMD's XDcfg_PcapReadback() issues."""
        self.assertEqual(len(P.LEGAL_DMA_TRANSACTIONS), 4)
        self.assertEqual(
            P.LEGAL_DMA_TRANSACTIONS,
            {"command":       (P.CMD_BUF | 1, 0xFFFFFFFF, 43, 0),
             "readback":      (0xFFFFFFFF, P.DST_BUF | 1, 0, 202),
             "cleanup":       (P.CMD_BUF | 1, 0xFFFFFFFF, 5, 0),
             "bidirectional": (P.CMD_BUF | 1, P.DST_BUF | 1, 43, 202)})

    def test_the_mirrored_lengths_are_refused(self):
        """The shape this repo pinned before review, now a negative case.

        Mirroring the active length onto the PCAP side was generalised from UG585's
        *configuration* example -- a write -- and the vendor's readback does not do it.
        """
        for name, tx in (("command 43/43", (P.CMD_BUF | 1, 0xFFFFFFFF, 43, 43)),
                         ("readback 202/202", (0xFFFFFFFF, P.DST_BUF | 1, 202, 202)),
                         ("cleanup 5/5", (P.CMD_BUF | 1, 0xFFFFFFFF, 5, 5))):
            with self.subTest(case=name):
                self.assertNotIn(tx, set(P.LEGAL_DMA_TRANSACTIONS.values()))

    def test_a_plan_with_mirrored_lengths_is_rejected_end_to_end(self):
        plan = self._plan("two-unidirectional")
        for step in plan["uboot_script"]:
            if step["cmd"] == f"mw.l {P.REG['DMA_DEST_LEN']:#010x} 0x00000000 1":
                step["cmd"] = f"mw.l {P.REG['DMA_DEST_LEN']:#010x} 0x0000002b 1"
                break
        else:
            self.fail("no zero-length DEST_LEN write to mutate")
        self.assertIn("not a permitted DMA transaction", self._reject(plan))

    def test_the_pcap_side_length_is_zero_in_every_issued_tuple(self):
        for order in ("two-unidirectional", "one-bidirectional"):
            for tx in P.dma_transactions(self._plan(order)):
                src, dst, src_len, dst_len = tx
                with self.subTest(order=order, tx=tx):
                    if src == 0xFFFFFFFF:
                        self.assertEqual(src_len, 0, "PCAP source length must be 0")
                    if dst == 0xFFFFFFFF:
                        self.assertEqual(dst_len, 0, "PCAP destination length must be 0")

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
        self.assertRegex(self._reject(plan),
                         r"transaction sequence|not a permitted DMA transaction")

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



class TheRecordedStatusIsInternallyConsistent(unittest.TestCase):
    """The class of defect that slipped through: five statements said §8a was open and
    that the planner had no default, while the resolution said otherwise, and every test
    passed. A status claim made in one file must not be contradicted in another."""

    FILES = {
        "README.md": REPO_ROOT / "README.md",
        "pcap_probe_spec.md": REPO_ROOT / "docs/pcap_probe_spec.md",
        "s0_derived_sequence.md": REPO_ROOT / "docs/s0_derived_sequence.md",
        "pcap_probe_plan.py": REPO_ROOT / "scripts/pcap_probe_plan.py",
    }
    # A stale claim is one that says the thing is open/undecided WITHOUT marking itself as
    # history. Retractions are allowed and are how this repository records its mistakes.
    HISTORY = ("was open", "was right then", "An earlier", "earlier version", "was wrong",
               "had been", "before review", "previously", "no longer")

    def _stale(self, text: str, pattern: str) -> list[str]:
        flat = " ".join(text.replace("*", "").replace("|", " ").split())
        out = []
        for m in re.finditer(pattern, flat):
            window = flat[max(0, m.start() - 90):m.end() + 90]
            if not any(h in window for h in self.HISTORY):
                out.append(window)
        return out

    def test_nothing_still_says_the_dma_order_has_no_default(self):
        for name, path in self.FILES.items():
            with self.subTest(doc=name):
                stale = self._stale(path.read_text(),
                                    r"no default|refuses to run without|"
                                    r"deliberately no default")
                self.assertEqual(stale, [], f"{name}: {stale}")

    def test_nothing_still_says_8a_is_open(self):
        for name, path in self.FILES.items():
            with self.subTest(doc=name):
                stale = self._stale(
                    path.read_text(),
                    r"8a[^.]{0,60}(?:UNRESOLVED|is open|unresolved)|"
                    r"[Tt]wo (?:items|questions) [^.]{0,30}UNRESOLVED")
                self.assertEqual(stale, [], f"{name}: {stale}")

    def test_the_planner_and_the_documents_agree_on_the_default(self):
        """Not prose: the argparse default itself."""
        tree = ast.parse((REPO_ROOT / "scripts/pcap_probe_plan.py").read_text())
        defaults = [
            kw.value for call in ast.walk(tree)
            if isinstance(call, ast.Call)
            and any(isinstance(a, ast.Constant) and a.value == "--dma-order"
                    for a in call.args)
            for kw in call.keywords if kw.arg == "default"
        ]
        self.assertEqual(len(defaults), 1, "--dma-order must declare exactly one default")
        self.assertIsInstance(defaults[0], ast.Name)
        self.assertEqual(defaults[0].id, "PINNED_DMA_ORDER")

    def test_8b_is_still_recorded_as_open_everywhere_it_is_mentioned(self):
        seq = (REPO_ROOT / "docs/s0_derived_sequence.md").read_text()
        self.assertRegex(seq, r"### 8b\..{0,140}UNRESOLVED")
        plan = P.build_plan(0x00000B99, P.PINNED_DMA_ORDER, 0xA5A5A5A5)
        self.assertRegex(" ".join(plan["unresolved"]), r"8b")

    def test_the_vendor_driver_citation_is_immutable(self):
        seq = (REPO_ROOT / "docs/s0_derived_sequence.md").read_text()
        self.assertIn("cbc5280400e7f08e35203d0dbd6bf09922049361", seq,
                      "the driver must be cited at a pinned commit, not at master")
        self.assertNotRegex(seq, r"embeddedsw/blob/master",
                            "a master URL is not a citation")


# --- the gate-status table: one canonical table, compared for equality ---------------
#
# Two earlier versions were fail-open and review broke both by ADDING contradictions
# rather than removing facts.  The first accepted a contrary row as long as some other row
# was right.  The second matched the expected wording and then enumerated known antonyms
# -- so "reviewed", "pending non-author review" and "active" walked straight through,
# because an antonym list is a guess about natural language and there is always another
# word.
#
# There is no list any more.  The status table is a CLOSED artefact: four rows, two
# columns, fixed keys, fixed values, fixed order, identical in all three documents.  It is
# parsed and compared for equality.  Anything added, removed, reordered, re-worded or
# appended to a cell is a difference, without the guard having to know what it means.

CANONICAL_STATUS_TABLE = (
    ("gate", "state"),
    ("S0a", "PASS at 8cb544b"),
    ("§8a", "awaiting non-author review"),
    ("S0b", "not started"),
    ("S0", "NOT complete"),
)
STATUS_KEYS = tuple(k for k, _ in CANONICAL_STATUS_TABLE[1:])


def _norm(cell: str) -> str:
    return " ".join(cell.replace("**", " ").replace("`", " ").split())


# The table is located with a real GFM parser, not by scanning for lines starting with a
# pipe.  Review broke the hand-rolled scanner twice over, both times without touching the
# canonical rows:
#   * `S0a | awaiting non-author review` omits the outer pipes, which GFM permits, so it
#     renders as a fourth body row -- and the scanner, which required a leading "|",
#     ended the block there and never saw it;
#   * wrapping the whole table in a fenced code block makes it render as code and not as a
#     table at all, while the scanner still counted its lines as one.
# Markdown block context is not something to re-derive from first principles, so it is not
# re-derived here.  A blockquoted table is likewise not a top-level table and does not
# count -- which makes a fenced or quoted canonical table a *missing* table, fail-closed.
_MD = MarkdownIt("commonmark").enable("table")   # commonmark + GFM tables, no linkify
P_TESTMOD = sys.modules[__name__]                # for patching _MD in a test


def top_level_tables(
        text: str) -> list[tuple[list[list[str]], tuple[int, int]]]:
    """Every top-level table, paired with its exact source-line span."""
    tables: list[tuple[int, list[list[str]], tuple[int, int] | None]] = []
    current: list[list[str]] | None = None
    depth = 0
    for tok in _MD.parse(text):
        if tok.type in ("blockquote_open", "bullet_list_open", "ordered_list_open"):
            depth += 1
        elif tok.type in ("blockquote_close", "bullet_list_close",
                          "ordered_list_close"):
            depth -= 1
        elif tok.type == "table_open":
            current = []
            span = (tok.map[0], tok.map[1]) if tok.map is not None else None
            tables.append((depth, current, span))
        elif tok.type == "table_close":
            current = None
        elif tok.type == "tr_open" and current is not None:
            current.append([])
        elif tok.type == "inline" and current is not None and current:
            current[-1].append(_norm(tok.content))
    # A table without a source map cannot be tied back to the artefact being checked.
    # Excluding it makes the later uniqueness check fail closed.
    return [(rows, span) for d, rows, span in tables if d == 0 and span is not None]


def status_table_artifact(
        text: str) -> tuple[list[tuple[str, ...]], tuple[int, int]] | None:
    """The one top-level gate table and the source span that produced those rows."""
    keyed = [(rows, span) for rows, span in top_level_tables(text)
             if rows and rows[0] and rows[0][0] == "gate"]
    if len(keyed) != 1:
        return None
    rows, span = keyed[0]
    return [tuple(row) for row in rows], span


def status_table(text: str) -> list[tuple[str, ...]] | None:
    """The one top-level table keyed `gate`, or None if there is not exactly one."""
    artifact = status_table_artifact(text)
    return artifact[0] if artifact is not None else None


CANONICAL_SOURCE_BLOCK = (
    "| gate | state |\n"
    "|---|---|\n"
    "| **S0a** | **PASS at `8cb544b`** |\n"
    "| **§8a** | **awaiting non-author review** |\n"
    "| **S0b** | **not started** |\n"
    "| **S0** | **NOT complete** |\n"
)


def status_problems(text: str) -> list[str]:
    """Empty iff the document carries exactly the canonical status table.

    Two independent checks, because they close different holes.  The parser check is
    what a reader of the *rendered* document sees.  The literal check is what a reader of
    the *source* sees: GFM silently discards a cell beyond the header's column count, so
    `| **S0** | **NOT complete** | see below |` renders as canonical while the source says
    something else.
    """
    problems: list[str] = []
    artifact = status_table_artifact(text)
    if artifact is None:
        problems.append("no single top-level GFM table keyed `gate` was found")
        return problems
    table, (start, end) = artifact
    # Bind the literal check to the SAME parsed table.  A whole-document count allowed a
    # malformed top-level table to satisfy the parser while a canonical decoy inside a
    # fence satisfied the literal check.
    source = "".join(text.splitlines(keepends=True)[start:end])
    if source != CANONICAL_SOURCE_BLOCK:
        expected_lines = CANONICAL_SOURCE_BLOCK.splitlines()
        actual_lines = source.splitlines()
        line_diffs = [
            f"source row {i}: expected "
            f"{expected_lines[i] if i < len(expected_lines) else None!r}, found "
            f"{actual_lines[i] if i < len(actual_lines) else None!r}"
            for i in range(max(len(expected_lines), len(actual_lines)))
            if (expected_lines[i] if i < len(expected_lines) else None)
            != (actual_lines[i] if i < len(actual_lines) else None)
        ]
        problems += line_diffs
        if not line_diffs:
            # `splitlines()` drops the terminators, so a difference living only in them
            # -- CRLF, a lone CR, a missing final newline -- produced an empty diff and
            # `status_problems` returned []: the branch detected a difference and then
            # reported none.  Entering this branch must never be silent.
            problems.append(
                "the status table's source differs from the canonical block outside "
                f"the line text (terminators or final newline): {source!r}")
    want = [tuple(r) for r in CANONICAL_STATUS_TABLE]
    # Both checks are reported, never short-circuited: the row-level diff is the useful
    # diagnostic and a literal mismatch must not hide it.
    problems += [f"row {i}: expected {want[i] if i < len(want) else None!r}, "
                 f"found {table[i] if i < len(table) else None!r}"
                 for i in range(max(len(want), len(table)))
                 if (want[i] if i < len(want) else None)
                 != (table[i] if i < len(table) else None)]
    return problems


def status_problems_from_path(path: Path) -> list[str]:
    """Check a document without universal-newline translation hiding its source."""
    return status_problems(path.read_bytes().decode("utf-8"))


class TheGateStatusIsPinnedAcrossEveryDocument(unittest.TestCase):
    """One canonical table, byte-for-byte after normalisation, in all three documents."""

    DOCS = {
        "README.md": REPO_ROOT / "README.md",
        "pcap_probe_spec.md": REPO_ROOT / "docs/pcap_probe_spec.md",
        "s0_derived_sequence.md": REPO_ROOT / "docs/s0_derived_sequence.md",
    }

    def test_every_document_carries_the_canonical_table(self):
        for name, path in self.DOCS.items():
            with self.subTest(doc=name):
                self.assertEqual(status_problems_from_path(path), [])

    def test_the_three_documents_agree_with_each_other(self):
        tables = {n: status_table(p.read_bytes().decode("utf-8"))
                  for n, p in self.DOCS.items()}
        first = next(iter(tables.values()))
        for name, table in tables.items():
            with self.subTest(doc=name):
                self.assertEqual(table, first)

    def test_no_antonym_list_survives(self):
        """The mechanism is pinned by the AST, not by a substring.

        A substring check for the old name fails on itself -- the literal is in the
        assertion. Look for a module-level binding instead.
        """
        tree = ast.parse(Path(__file__).read_text())
        assigned = {t.id for n in tree.body if isinstance(n, ast.Assign)
                    for t in n.targets if isinstance(t, ast.Name)}
        self.assertNotIn("CONTRARY_STATUS", assigned,
                         "the antonym list is back; equality is what closes this")
        self.assertIn("CANONICAL_STATUS_TABLE", assigned)

    # --- adversarial: contradictions ADDED, not facts removed ----------------------

    GOOD = ("| gate | state |\n|---|---|\n"
            "| **S0a** | **PASS at `8cb544b`** |\n"
            "| **§8a** | **awaiting non-author review** |\n"
            "| **S0b** | **not started** |\n"
            "| **S0** | **NOT complete** |\n")

    def test_the_control_table_is_accepted(self):
        self.assertEqual(status_problems(self.GOOD), [])

    def test_every_appended_contradiction_is_refused(self):
        """Both review rounds' injections, and the synonyms an antonym list would miss."""
        appended = {
            "S0a + awaiting non-author review": ("S0a", "; awaiting non-author review"),
            "S0a + pending non-author review": ("S0a", "; pending non-author review"),
            "S0a + delivered": ("S0a", "; delivered"),
            "§8a + reviewed": ("§8a", "; reviewed"),
            "§8a + review passed": ("§8a", "; review passed"),
            "§8a + signed off": ("§8a", "; signed off"),
            "S0b + active": ("S0b", "; active"),
            "S0b + implementation complete": ("S0b", "; implementation complete"),
            "S0b + in flight": ("S0b", "; in flight"),
            "S0 + done": ("S0", "; done"),
            "S0 + shipped": ("S0", "; shipped"),
        }
        for name, (key, suffix) in appended.items():
            # Locate the row by its normalised key rather than rebuilding it: the table
            # carries markup (backticks) that a reconstruction drops, so the first
            # version of this test silently injected nothing into the S0a row.
            row = next(l for l in self.GOOD.splitlines()
                       if _norm(l.strip("|").split("|")[0]) == key)
            bad = self.GOOD.replace(row, row.rstrip()[:-1].rstrip() + suffix + " |")
            with self.subTest(case=name):
                self.assertNotEqual(bad, self.GOOD, "the injection did not apply")
                self.assertTrue(status_problems(bad), f"{name} was accepted")

    def test_all_of_one_rounds_injections_at_once_are_refused(self):
        bad = (self.GOOD
               .replace("| **S0a** | **PASS at `8cb544b`** |",
                        "| **S0a** | **PASS at `8cb544b`**; pending non-author review |")
               .replace("| **§8a** | **awaiting non-author review** |",
                        "| **§8a** | **awaiting non-author review**; reviewed |")
               .replace("| **S0b** | **not started** |",
                        "| **S0b** | **not started**; active |"))
        problems = status_problems(bad)
        self.assertGreaterEqual(len(problems), 3, f"only caught {problems}")

    def test_a_prefix_is_refused_too(self):
        bad = self.GOOD.replace("| **S0b** | **not started** |",
                                "| **S0b** | probably **not started** |")
        self.assertTrue(status_problems(bad))

    def test_reordering_removing_duplicating_and_extending_are_refused(self):
        rows = self.GOOD.splitlines(keepends=True)
        cases = {
            "reordered": rows[:2] + [rows[3], rows[2]] + rows[4:],
            "row removed": rows[:4] + rows[5:],
            "row duplicated": rows + [rows[2]],
            "extra row": rows + ["| **S0c** | **done** |\n"],
        }
        for name, lines in cases.items():
            with self.subTest(case=name):
                self.assertTrue(status_problems("".join(lines)), f"{name} was accepted")

    def test_an_extra_column_is_refused(self):
        """GFM discards the third cell, so the parser alone cannot see this.

        The rendered table is canonical; the source is not. The literal check is what
        refuses it, and this test is why that check exists.
        """
        bad = self.GOOD.replace("| **S0** | **NOT complete** |",
                                "| **S0** | **NOT complete** | see below |")
        self.assertIsNotNone(status_table(bad), "GFM truncates: the parser sees no change")
        self.assertEqual(status_table(bad), [tuple(r) for r in CANONICAL_STATUS_TABLE])
        self.assertTrue(status_problems(bad), "the source-literal check must refuse it")

    def test_two_status_tables_are_refused(self):
        self.assertTrue(status_problems(self.GOOD + "\n" + self.GOOD))

    def test_a_second_gate_table_with_different_rows_is_refused(self):
        """Isolates the "exactly one" check from the source-literal check.

        Two copies of the canonical table also trip the literal count, so that case
        cannot tell whether the uniqueness check still works. This one keeps the literal
        appearing exactly once and makes the second table say something else.
        """
        decoy = ("| gate | state |\n|---|---|\n"
                 "| **S0** | **complete** |\n")
        text = self.GOOD + "\n" + decoy
        self.assertEqual(text.count(CANONICAL_SOURCE_BLOCK), 1)
        problems = status_problems(text)
        self.assertTrue(problems, "a second gate-keyed table was accepted")
        self.assertIn("no single top-level", " ".join(problems))

    def test_the_parser_dependency_is_declared(self):
        """The token schema and source-map behaviour are part of this guard's contract."""
        req = (REPO_ROOT / "requirements.txt").read_text()
        lines = [l.strip() for l in req.splitlines()
                 if l.strip() and not l.strip().startswith("#")]
        self.assertIn("markdown-it-py==3.0.0", lines,
                      f"markdown-it-py 3.0.0 is not pinned; requirements list {lines}")

    def test_no_status_table_is_refused(self):
        self.assertTrue(status_problems("no tables here"))

    # --- the Markdown parser boundary ----------------------------------------------

    def test_a_row_without_outer_pipes_is_seen(self):
        """GFM permits omitting the outer pipes; the row still joins the table."""
        bad = self.GOOD + "S0a | awaiting non-author review\n"
        problems = status_problems(bad)
        self.assertTrue(problems, "a pipe-less appended row was ignored")
        self.assertIn("row 5", " ".join(problems))

    def test_a_pipe_less_row_replacing_a_status_is_seen(self):
        bad = self.GOOD + "S0 | complete\n"
        self.assertTrue(status_problems(bad))

    def test_a_fenced_canonical_table_is_not_a_table(self):
        """Inside a fence it renders as code, so the document has no status table."""
        for fence in ("```text", "```", "~~~"):
            close = "~~~" if fence.startswith("~") else "```"
            with self.subTest(fence=fence):
                problems = status_problems(f"{fence}\n{self.GOOD}{close}\n")
                self.assertTrue(problems)
                self.assertIn("no single top-level", " ".join(problems))

    def test_a_blockquoted_canonical_table_is_not_top_level(self):
        quoted = "\n".join("> " + l for l in self.GOOD.splitlines()) + "\n"
        problems = status_problems(quoted)
        self.assertTrue(problems)
        self.assertIn("no single top-level", " ".join(problems))

    def test_a_canonical_table_inside_a_list_is_not_top_level(self):
        listed = "- item\n\n" + "\n".join("  " + l for l in self.GOOD.splitlines())
        self.assertTrue(status_problems(listed))

    def test_a_real_table_plus_a_fenced_decoy_still_passes(self):
        """Discriminating power: a fenced example must not break the real table."""
        text = self.GOOD + "\n```text\n" + self.GOOD + "```\n"
        self.assertEqual(status_problems(text), [])

    def test_literal_and_parser_must_describe_the_same_table(self):
        """A fenced literal may not vouch for a different malformed top-level table.

        GFM drops a third body cell because the header declares two columns.  The parsed
        top-level table therefore looks canonical.  A whole-document literal count was
        independently satisfied by the canonical block in the fence, so both checks passed
        while neither described the same artefact.
        """
        malformed = self.GOOD.replace(
            "| **S0** | **NOT complete** |",
            "| **S0** | **NOT complete** | actually done |")
        bad = malformed + "\n~~~text\n" + self.GOOD + "~~~\n"
        self.assertEqual(bad.count(CANONICAL_SOURCE_BLOCK), 1,
                         "the fenced decoy must isolate the old whole-document count hole")
        self.assertEqual(status_table(bad), [tuple(r) for r in CANONICAL_STATUS_TABLE],
                         "GFM truncation must keep the parsed rows canonical")
        problems = status_problems(bad)
        self.assertTrue(problems, "parser and literal evidence came from different tables")
        self.assertIn("source row 5", " ".join(problems))

    def test_a_table_without_a_source_map_is_discarded(self):
        """The `span is not None` filter, exercised rather than assumed.

        With markdown-it 3.0.0 every real table carries a map, so nothing reached that
        branch and removing it changed no test.  A table whose source span is unknown
        cannot be tied back to the artefact being checked, so it must not count -- and
        that has to be shown, not asserted in a comment.
        """
        from markdown_it.token import Token

        def _token(t, tag, nesting, content=""):
            tok = Token(t, tag, nesting)
            tok.content = content
            tok.map = None
            return tok

        stub_tokens = [
            _token("table_open", "table", 1),
            _token("tr_open", "tr", 1),
            _token("inline", "", 0, "gate"),
            _token("inline", "", 0, "state"),
            _token("tr_close", "tr", -1),
            _token("table_close", "table", -1),
        ]

        class _StubMd:
            @staticmethod
            def parse(_text):
                return stub_tokens

        with unittest.mock.patch.object(P_TESTMOD, "_MD", _StubMd):
            self.assertEqual(top_level_tables("irrelevant"), [],
                             "a map-less table must not be counted")
            self.assertIsNone(status_table_artifact("irrelevant"))
            self.assertIn("no single top-level",
                          " ".join(status_problems("irrelevant")))

    def test_a_terminator_only_difference_is_still_reported(self):
        """Entering the "source differs" branch must never produce an empty report.

        `splitlines()` strips terminators, so CRLF, a lone CR and a missing final
        newline each made `source != CANONICAL_SOURCE_BLOCK` true while the row diff came
        out empty -- and an empty problem list is a pass.
        """
        cases = {
            "CRLF": self.GOOD.replace("\n", "\r\n"),
            "lone CR": self.GOOD.replace("\n", "\r"),
            "no final newline": self.GOOD.rstrip("\n"),
        }
        for name, text in cases.items():
            with self.subTest(case=name):
                self.assertNotEqual(text, self.GOOD, "the variant did not apply")
                problems = status_problems(text)
                self.assertTrue(problems, f"{name} was accepted")
                self.assertIn("outside the line text", " ".join(problems))

    def test_real_document_ingress_preserves_terminator_differences(self):
        """The path-based guard must not normalise CRLF/CR before checking.

        `Path.read_text()` uses universal-newline translation, so the earlier helper-only
        regression passed while a real CRLF document reached `status_problems()` as LF and
        was accepted.  Drive the same entry point used for the three repository documents.
        """
        cases = {
            "CRLF": self.GOOD.replace("\n", "\r\n"),
            "lone CR": self.GOOD.replace("\n", "\r"),
            "no final newline": self.GOOD.rstrip("\n"),
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "status.md"
            for name, source in cases.items():
                with self.subTest(case=name):
                    path.write_bytes(source.encode("utf-8"))
                    problems = status_problems_from_path(path)
                    self.assertTrue(problems, f"real {name} document was accepted")
                    self.assertIn("outside the line text", " ".join(problems))

    def test_the_documents_are_read_without_newline_translation(self):
        """Structural: the status tests may not touch a document through `read_text()`.

        `dab0d5b` converted the two call sites that read the repository documents, and
        nothing then held them there -- reverting either one to `read_text()` broke no
        test, because the terminator regressions all drive the helper on a temp file
        rather than the call site. Universal-newline translation is invisible at the
        assertion, so it is refused at the AST instead.
        """
        tree = ast.parse(Path(__file__).read_text())
        cls = next(n for n in ast.walk(tree)
                   if isinstance(n, ast.ClassDef)
                   and n.name == "TheGateStatusIsPinnedAcrossEveryDocument")
        # Scoped to the methods that consume the repository documents.  A first version
        # flagged every read_text() in the class, including the AST tests that read this
        # file and requirements.txt -- where universal newlines are correct, not a bug.
        # `self.DOCS` as an attribute access, not the string "DOCS" anywhere in the
        # method -- the first scoped version matched its own literal and flagged itself,
        # which is the third time a guard in this file has done that.
        def reads_docs(fn) -> bool:
            return any(isinstance(n, ast.Attribute) and n.attr == "DOCS"
                       for n in ast.walk(fn))

        consumers = [fn for fn in cls.body
                     if isinstance(fn, ast.FunctionDef) and reads_docs(fn)]
        # Named, not merely non-empty: emptying the list would otherwise disarm the
        # check below by leaving it nothing to inspect.
        self.assertEqual(
            sorted(fn.name for fn in consumers),
            ["test_every_document_carries_the_canonical_table",
             "test_the_real_documents_are_checked_byte_for_byte",
             "test_the_three_documents_agree_with_each_other"],
            "the set of methods reading the repository documents has changed")
        offenders = sorted({
            f"{fn.name}:{node.lineno}"
            for fn in consumers for node in ast.walk(fn)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr in ("read_text", "write_text")
        })
        self.assertEqual(offenders, [],
                         f"newline-translating I/O on the documents: {offenders}")

    def test_the_ingress_regression_writes_bytes(self):
        """`write_text` translates newlines on some platforms; the fixture must not."""
        tree = ast.parse(Path(__file__).read_text())
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef)
                  and n.name == "test_real_document_ingress_preserves_terminator_differences")
        attrs = {n.func.attr for n in ast.walk(fn)
                 if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
        self.assertIn("write_bytes", attrs)
        self.assertNotIn("write_text", attrs)

    def test_the_document_entry_point_reads_bytes(self):
        tree = ast.parse(Path(__file__).read_text())
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef)
                  and n.name == "status_problems_from_path")
        attrs = {n.func.attr for n in ast.walk(fn)
                 if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
        self.assertIn("read_bytes", attrs)
        self.assertNotIn("read_text", attrs)

    def test_the_repository_documents_go_through_that_entry_point(self):
        """Structural companion: the byte-preserving helper must be present."""
        tree = ast.parse(Path(__file__).read_text())
        cls = next(n for n in ast.walk(tree)
                   if isinstance(n, ast.ClassDef)
                   and n.name == "TheGateStatusIsPinnedAcrossEveryDocument")
        fn = next(n for n in cls.body if isinstance(n, ast.FunctionDef)
                  and n.name == "test_every_document_carries_the_canonical_table")
        called = {n.func.id for n in ast.walk(fn)
                  if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
        self.assertIn("status_problems_from_path", called)

    def test_the_repository_document_assertion_consumes_raw_bytes(self):
        """Drive the real document test; a helper call may not be dead evidence.

        The AST presence check can be satisfied by calling `status_problems_from_path`
        and discarding its result, then feeding the assertion text read through a
        newline-translating alias.  Replace the real test instance's document set with a
        controlled file so the assertion's actual data flow, not a function name, decides.
        """
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "status.md"
            case = type(self)("test_every_document_carries_the_canonical_table")
            # Set the instance dictionary directly so this guard is not itself mistaken
            # for another method that consumes `self.DOCS` by the structural companion.
            case.__dict__["DOCS"] = {"controlled.md": path}

            path.write_bytes(self.GOOD.encode("utf-8"))
            case.test_every_document_carries_the_canonical_table()

            path.write_bytes(self.GOOD.replace("\n", "\r\n").encode("utf-8"))
            with self.assertRaisesRegex(AssertionError, "outside the line text"):
                case.test_every_document_carries_the_canonical_table()

    # The documents the real test iterates over, replicated into a throwaway repo so a
    # perturbed copy can be checked without touching the working tree.
    _INGRESS_FIXTURE = ("README.md", "docs/pcap_probe_spec.md",
                        "docs/s0_derived_sequence.md", "docs/s0_ug585_discharge.md",
                        "scripts/pcap_probe_plan.py", "requirements.txt",
                        "tests/test_s0_pcap_plan.py")

    def _run_document_test_in(self, root: Path) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "tests/test_s0_pcap_plan.py",
             "TheGateStatusIsPinnedAcrossEveryDocument."
             "test_every_document_carries_the_canonical_table"],
            cwd=root, capture_output=True, text=True, timeout=120,
            env={**os.environ, "PSMAP_SUITE_COUNT_CHILD": "1"})

    def test_the_real_documents_are_checked_byte_for_byte(self):
        """End-to-end on the real `DOCS` mapping, in a throwaway copy of the repository.

        Substituting the test instance's documents proves the assertion consumes bytes
        for *that* fixture, and an edit can branch on the fixture: keying on
        `len(self.DOCS)` or on whether the path lies under `REPO_ROOT` sends the
        controlled file down the byte-preserving path and the real documents down a
        newline-translating alias, and both escape a substitution-based guard.  Nothing
        escapes perturbing the real documents themselves.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for rel in self._INGRESS_FIXTURE:
                dst = root / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_bytes((REPO_ROOT / rel).read_bytes())

            control = self._run_document_test_in(root)
            self.assertEqual(control.returncode, 0,
                             f"the unperturbed copy must pass:\n{control.stderr[-600:]}")

            # Named, not inlined: emptying the loop would otherwise disarm the check
            # while every assertion inside it still looked present.
            perturbed = ("README.md", "docs/pcap_probe_spec.md",
                         "docs/s0_derived_sequence.md")
            self.assertEqual(
                sorted(perturbed),
                sorted(str(path.relative_to(REPO_ROOT)) for path in self.DOCS.values()),
                "every document the real test reads must be perturbed here")
            # Recorded as they happen: pinning the inputs does not prove either loop ran,
            # and an empty iterable leaves every assertion inside it apparently present.
            variant_names = ("CRLF", "tab separators", "trailing spaces")
            checked: list[tuple[str, str]] = []
            for rel in perturbed:
                target = root / rel
                original = target.read_bytes()
                row = b"| **S0** | **NOT complete** |\n"
                self.assertEqual(original.count(row), 1,
                                 f"the canonical S0 row is not unique in {rel}")
                variants = {
                    "CRLF": original.replace(b"\n", b"\r\n"),
                    "tab separators": original.replace(
                        row, b"| **S0**\t|\t**NOT complete** |\n"),
                    "trailing spaces": original.replace(
                        row, b"| **S0** | **NOT complete** |  \n"),
                }
                self.assertEqual(tuple(variants), variant_names,
                                 "the byte-level perturbation set has changed")
                for variant, changed in variants.items():
                    checked.append((rel, variant))
                    with self.subTest(document=rel, variant=variant):
                        self.assertNotEqual(changed, original,
                                            "the perturbation did not change the file")
                        try:
                            target.write_bytes(changed)
                            result = self._run_document_test_in(root)
                            diagnostic = ("outside the line text" if variant == "CRLF"
                                          else "source row")
                            self.assertNotEqual(
                                result.returncode, 0,
                                f"{variant} in {rel} was accepted by the real document test")
                            self.assertIn(diagnostic, result.stderr)
                        finally:
                            target.write_bytes(original)
            expected = [(rel, variant) for rel in perturbed for variant in variant_names]
            self.assertEqual(checked, expected,
                             "the perturbation matrix did not check every case")

    def test_the_difference_branch_cannot_report_nothing(self):
        """Structural: no path through the branch may leave `problems` unchanged."""
        tree = ast.parse(Path(__file__).read_text())
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef) and n.name == "status_problems")
        branch = next(
            n for n in ast.walk(fn)
            if isinstance(n, ast.If) and "CANONICAL_SOURCE_BLOCK" in ast.unparse(n.test))
        guarded = [n for n in ast.walk(branch)
                   if isinstance(n, ast.If) and "line_diffs" in ast.unparse(n.test)]
        self.assertTrue(guarded,
                        "the branch must have a fallback when no row diff is produced")

    def test_the_parser_is_a_gfm_parser_not_a_line_scanner(self):
        """AST again: a substring ban matches its own assertion (second time)."""
        tree = ast.parse(Path(__file__).read_text())
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef) and n.name == "top_level_tables")
        names = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name)}
        self.assertIn("_MD", names, "the table must be located by the GFM parser")
        assigned = {t.id for n in tree.body if isinstance(n, ast.Assign)
                    for t in n.targets if isinstance(t, ast.Name)}
        self.assertIn("_MD", assigned)


class TheLoopbackGateIsPresentAndReadOnly(unittest.TestCase):
    """MCTRL[PCAP_LPBK]: loopback is not the PL frame-readback data path."""

    def _plan(self, order="two-unidirectional"):
        return P.build_plan(0x00000B99, order, 0xA5A5A5A5)

    def _reject(self, plan) -> str:
        P.check_allowlist(plan)
        with self.assertRaises(ValueError, msg="the plan was accepted") as cm:
            P.check_value_policy(plan)
        return str(cm.exception)

    def test_the_register_and_mask_are_the_vendor_constants(self):
        self.assertEqual(P.REG["MCTRL"], 0xF8007080)
        self.assertEqual(P.MCTRL_PCAP_LPBK, 0x10)

    def test_mctrl_is_read_before_any_dma_in_both_orders(self):
        for order in ("two-unidirectional", "one-bidirectional"):
            toks = P.schedule_tokens(self._plan(order))
            with self.subTest(order=order):
                self.assertIn("READ_MCTRL", toks)
                first_dma = min(i for i, t in enumerate(toks)
                                if t in ("DMA_SRC_ADDR",))
                self.assertLess(toks.index("READ_MCTRL"), first_dma)

    def test_the_gate_names_the_mask_it_requires(self):
        step = [s for s in self._plan()["uboot_script"]
                if s["cmd"] == f"md.l {P.REG['MCTRL']:#010x} 1"]
        self.assertEqual(len(step), 1)
        self.assertIn(f"{P.MCTRL_PCAP_LPBK:#x}", step[0]["why"])

    def test_mctrl_is_read_only(self):
        plan = self._plan()
        plan["uboot_script"].append(
            {"step": "x", "cmd": f"mw.l {P.REG['MCTRL']:#010x} 0x00000000 1", "why": "",
             "addresses": [P.REG["MCTRL"]]})
        self.assertIn("read-only", self._reject(plan))

    def test_removing_the_gate_is_refused(self):
        plan = self._plan()
        plan["uboot_script"] = [s for s in plan["uboot_script"]
                                if s["cmd"] != f"md.l {P.REG['MCTRL']:#010x} 1"]
        self.assertIn("diverges", self._reject(plan))

    def test_reading_the_wrong_width_is_refused(self):
        plan = self._plan()
        for step in plan["uboot_script"]:
            if step["cmd"] == f"md.l {P.REG['MCTRL']:#010x} 1":
                step["cmd"] = f"md.l {P.REG['MCTRL']:#010x} 2"
        with self.assertRaises(ValueError) as cm:
            P.check_allowlist(plan)      # a 2-word read runs off the 4-byte region
            P.check_value_policy(plan)
        self.assertRegex(str(cm.exception), r"unscheduled|not contained|diverges")

    def test_the_document_records_the_gate_and_why_reset_is_not_enough(self):
        seq = " ".join((REPO_ROOT / "docs/s0_derived_sequence.md")
                       .read_text().replace("*", "").split())
        self.assertRegex(seq, r"0xF8007080")
        self.assertRegex(seq, r"reset value being 0 does not substitute for the live read")
        self.assertRegex(seq, r"enabling it for `XDCFG_CONCURRENT_NONSEC_READ_WRITE`")


class TheSuiteCannotSilentlyShrink(unittest.TestCase):
    """`unittest.main()` must be the last statement in the file.

    It had drifted above five classes, so running the file directly exercised 117 of its
    122 tests while discovery ran all of them -- the shortfall being exactly the newest
    guards, which is the worst possible five to lose.
    """

    @staticmethod
    def _is_main_guard(node) -> bool:
        # ast.unparse normalises quotes, so compare structure rather than text.
        if not isinstance(node, ast.If) or not isinstance(node.test, ast.Compare):
            return False
        left, comps = node.test.left, node.test.comparators
        return (isinstance(left, ast.Name) and left.id == "__name__"
                and len(comps) == 1 and isinstance(comps[0], ast.Constant)
                and comps[0].value == "__main__")

    def test_the_main_guard_is_the_last_statement(self):
        tree = ast.parse(Path(__file__).read_text())
        self.assertTrue(self._is_main_guard(tree.body[-1]),
                        "the file must end with the __main__ guard")

    def test_every_test_class_is_defined_before_it(self):
        tree = ast.parse(Path(__file__).read_text())
        guards = [n for n in tree.body if self._is_main_guard(n)]
        self.assertEqual(len(guards), 1, "exactly one __main__ guard")
        after = [n.name for n in tree.body
                 if isinstance(n, ast.ClassDef) and n.lineno > guards[0].lineno]
        self.assertEqual(after, [], f"classes defined after the guard: {after}")

    def test_direct_execution_and_discovery_agree(self):
        """Measured, not merely asserted structurally: run this file both ways.

        Guarded against self-recursion.  The first version spawned children that ran this
        same file -- including this test -- and forked without bound; a guard that hangs
        the suite is worse than the drift it exists to catch.
        """
        if os.environ.get("PSMAP_SUITE_COUNT_CHILD"):
            self.skipTest("child process: counting only")
        env = {**os.environ, "PSMAP_SUITE_COUNT_CHILD": "1"}
        direct = subprocess.run([sys.executable, str(Path(__file__))],
                                cwd=REPO_ROOT, capture_output=True, text=True,
                                env=env, timeout=120)
        found = subprocess.run(
            [sys.executable, "-m", "unittest", "discover", "-s", "tests",
             "-p", Path(__file__).name],
            cwd=REPO_ROOT, capture_output=True, text=True, env=env, timeout=120)
        n_direct = re.search(r"^Ran (\d+) tests", direct.stderr, re.M)
        n_found = re.search(r"^Ran (\d+) tests", found.stderr, re.M)
        self.assertIsNotNone(n_direct, direct.stderr[-400:])
        self.assertIsNotNone(n_found, found.stderr[-400:])
        self.assertEqual(n_direct.group(1), n_found.group(1),
                         "running this file directly must exercise every test in it")


if __name__ == "__main__":
    unittest.main()
