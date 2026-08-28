"""The owner specification must actually own the line.

Two things go wrong when a specification is moved between repositories, and both were
found by review on this one: the new copy silently keeps references that only resolved
in the old tree, and the new documents drift into contradicting the specification they
claim to carry forward.  These tests are the mechanical form of those two objections.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
OWNER = REPO_ROOT / "docs/pcap_probe_spec.md"
SNAPSHOT = REPO_ROOT / "docs/pcap_readback_probe_spec.md"
STOP_LOSS = REPO_ROOT / "docs/stop_loss.md"
AUTHORITY = REPO_ROOT / "docs/authority_requirements.md"

FROZEN = "5ad36a1ca26b42022121f1889172dbe4380b4539"
BLOB = f"https://github.com/14sea/zynq-fabricmap/blob/{FROZEN}"

LOCAL_REF = re.compile(r"`((?:docs|scripts|tests|evidence|gate_runs)/[A-Za-z0-9_./-]+)`")


class OwnerSpecResolvesTheSnapshot(unittest.TestCase):

    def test_every_dangling_snapshot_reference_is_resolved_by_the_owner_spec(self):
        """Not 'a table exists' — every actually-broken path must appear in it."""
        owner = OWNER.read_text()
        dangling = sorted({p for p in LOCAL_REF.findall(SNAPSHOT.read_text())
                           if not (REPO_ROOT / p).exists()})
        self.assertGreater(len(dangling), 0, "regex stopped matching; test is vacuous")
        for path in dangling:
            with self.subTest(path=path):
                self.assertIn(f"{BLOB}/{path}", owner,
                              f"{path} does not resolve locally and the owner spec "
                              f"gives no immutable location for it")

    def test_the_owner_spec_has_no_dangling_references_of_its_own(self):
        """A citation is resolved if its own line carries the immutable location.

        The resolution table names the old paths in its left column by design, so a
        whole-file scan would flag the very mechanism under test.  The check is
        per-line: a local path with no blob URL beside it must exist here.
        """
        unresolved = set()
        for line in OWNER.read_text().splitlines():
            if BLOB in line:
                continue
            unresolved |= {q for q in LOCAL_REF.findall(line)
                           if not (REPO_ROOT / q).exists()}
        self.assertEqual(unresolved, set(),
                         f"owner spec cites paths that neither exist here nor carry an "
                         f"immutable location: {sorted(unresolved)}")

    def test_the_snapshot_is_named_as_archival_and_superseded(self):
        owner = OWNER.read_text()
        self.assertIn("pcap_readback_probe_spec.md", owner)
        self.assertRegex(owner, r"archival imported snapshot")
        self.assertRegex(owner, r"[Ss]upersedes")

    def test_the_authority_modules_are_not_imported_to_fix_a_reference(self):
        for name in ("gate_board_identity.py", "precheck_fresh_power.py",
                     "board_uboot_fpga_load.py", "board_uboot_axi.py"):
            with self.subTest(name=name):
                self.assertFalse((REPO_ROOT / "scripts" / name).exists())


class AuthorisationModelIsConsistent(unittest.TestCase):
    """stop_loss.md once said 'per-stage'; the specification says the opposite."""

    def test_no_document_claims_per_stage_authorisation(self):
        for f in (OWNER, STOP_LOSS, AUTHORITY):
            with self.subTest(file=f.name):
                text = f.read_text()
                for para in text.split("\n\n"):
                    if not re.search(r"per-stage, not blanket|"
                                     r"authorisation is per-stage", para):
                        continue
                    self.assertRegex(
                        para, r"was wrong|has been corrected|An earlier draft",
                        f"{f.name} asserts per-stage authorisation, contradicting the "
                        f"specification's single whole-of-probe ruling")

    def test_both_documents_state_the_single_ruling(self):
        for f in (OWNER, STOP_LOSS):
            with self.subTest(file=f.name):
                flat = " ".join(f.read_text().replace("*", "").split())
                self.assertRegex(flat, r"[Oo]ne[^.]{0,40}ruling covers S1[-\u2013]S3",
                                 f"{f.name} must state that one ruling covers S1-S3")
                self.assertRegex(flat, r"no ruling per stage",
                                 f"{f.name} must deny a per-stage ruling")
                self.assertRegex(flat, r"not a blanket|is not a blanket|no blanket",
                                 f"{f.name} must deny a blanket ruling")

    def test_the_snapshot_still_says_what_we_claim_it_says(self):
        """If the snapshot's clause ever moved, the consistency above is meaningless."""
        self.assertIn("One whole-of-probe board ruling covers", SNAPSHOT.read_text())


class LinuxIsScopedToTheFutureArchitecture(unittest.TestCase):

    def test_the_probe_is_declared_uboot_only(self):
        flat = " ".join(OWNER.read_text().replace("*", "").split())
        self.assertRegex(flat, r"S1[-\u2013]S3 run over a U-Boot control plane")
        self.assertRegex(flat, r"not authorised to boot it")

    def test_the_linux_requirement_is_marked_forward_looking_everywhere(self):
        for f in (OWNER, AUTHORITY, STOP_LOSS):
            with self.subTest(file=f.name):
                text = f.read_text()
                if "Linux" not in text:
                    continue
                self.assertRegex(
                    text, r"forward-looking|FORWARD-LOOKING|future PS-guided|"
                          r"not a requirement of this probe|binds\s+a future",
                    f"{f.name} mentions Linux without scoping it away from the probe")


if __name__ == "__main__":
    unittest.main()
