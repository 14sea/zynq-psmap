"""The import manifest is a machine-checked claim, not a comment.

Every row of the manifest's imported-files table names a path, a sha256 and a byte
count.  This test parses that table out of the Markdown and re-hashes the real files.
It is written to fail on the two ways such a table rots: a file changing under a
stale hash, and a number in the table having been typed rather than measured.

It deliberately parses the table structurally.  A substring search for a hash would
pass even if the hash sat in the wrong row, and that is the failure mode this repo
has been bitten by before.
"""
from __future__ import annotations

import hashlib
import re
import subprocess
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST = REPO_ROOT / "docs/import_manifest.md"

SOURCE_COMMIT = "5ad36a1ca26b42022121f1889172dbe4380b4539"
SOURCE_REPO = "github.com/14sea/zynq-fabricmap"

ROW = re.compile(
    r"^\|\s*`([^`]+)`\s*\|\s*`([0-9a-f]{64})`\s*\|\s*(\d+)\s*\|\s*$")


ORIG_ROW = re.compile(r"^\|\s*`([^`]+)`\s*\|\s*$")


def git_tracked() -> list[str]:
    out = subprocess.run(["git", "ls-files"], cwd=REPO_ROOT,
                         capture_output=True, text=True, check=True).stdout
    return [l for l in out.splitlines() if l]


def parse_original_rows() -> list[str]:
    """Rows of the 'Files original to this repository' single-column table."""
    text = MANIFEST.read_text().splitlines()
    start = next(i for i, l in enumerate(text)
                 if l.startswith("## Files original to this repository"))
    end = next(i for i, l in enumerate(text[start + 1:], start + 1)
               if l.startswith("## "))
    return [m.group(1) for l in text[start:end] if (m := ORIG_ROW.match(l))
            and m.group(1) != "path"]


def parse_rows() -> list[tuple[str, str, int]]:
    """Rows of the 'Imported files' table only, not every table in the file."""
    text = MANIFEST.read_text().splitlines()
    start = next(i for i, l in enumerate(text) if l.startswith("## Imported files"))
    end = next(i for i, l in enumerate(text[start + 1:], start + 1)
               if l.startswith("## ") or l.startswith("### "))
    rows = []
    for line in text[start:end]:
        m = ROW.match(line)
        if m:
            rows.append((m.group(1), m.group(2), int(m.group(3))))
    return rows


class ImportManifest(unittest.TestCase):

    def test_table_is_parseable_and_not_empty(self):
        rows = parse_rows()
        self.assertGreaterEqual(len(rows), 8, "manifest table lost rows")
        self.assertEqual(len(rows), len({p for p, _, _ in rows}),
                         "a path is listed twice")

    def test_every_listed_file_exists_and_matches(self):
        for path, want_sha, want_size in parse_rows():
            with self.subTest(path=path):
                f = REPO_ROOT / path
                self.assertTrue(f.is_file(), f"{path} listed but missing")
                data = f.read_bytes()
                self.assertEqual(len(data), want_size,
                                 f"{path}: manifest says {want_size} bytes, "
                                 f"file is {len(data)}")
                self.assertEqual(hashlib.sha256(data).hexdigest(), want_sha,
                                 f"{path}: content does not match manifest sha256")

    def test_tracked_files_are_exactly_the_two_declared_sets(self):
        """Two-way closure over the WHOLE repository, not over chosen directories.

        An earlier version walked only `data/` and `gate_runs/`, so an undeclared
        `scripts/foo.py` or `docs/foo.md` entered unnoticed and the guard's claim was
        true only along the paths it happened to look at.  The census is now `git
        ls-files`, and the manifest must partition it exactly.
        """
        tracked = set(git_tracked())
        imported = {p for p, _, _ in parse_rows()}
        original = set(parse_original_rows())

        overlap = imported & original
        self.assertEqual(overlap, set(),
                         f"declared as both imported and original: {overlap}")

        declared = imported | original
        undeclared = tracked - declared
        self.assertEqual(undeclared, set(),
                         f"tracked but declared in neither set: {undeclared}")
        phantom = declared - tracked
        self.assertEqual(phantom, set(),
                         f"declared in the manifest but not tracked: {phantom}")

    def test_the_original_set_is_not_empty_and_lists_this_test(self):
        """A cheap way for the closure check above to be defeated is an empty table."""
        original = set(parse_original_rows())
        self.assertGreaterEqual(len(original), 8)
        self.assertIn("tests/test_import_manifest.py", original)

    def test_the_prjxray_licence_is_imported_and_declared(self):
        """CC0 data may not travel without the CC0 text."""
        rows = {p: (s, n) for p, s, n in parse_rows()}
        self.assertIn("data/prjxray/LICENSE", rows,
                      "the vendored prjxray subset must ship its own licence")
        sha, size = rows["data/prjxray/LICENSE"]
        self.assertEqual(
            sha, "a2010f343487d3f7618affe54f789f5487602331c0a8d03f49e9a7c547cf0499")
        self.assertEqual(size, 7048)
        data_files = [p for p in rows if p.startswith("data/prjxray/")]
        self.assertGreater(len(data_files), 1, "licence present but no data under it")

    def test_licensing_split_is_stated_where_a_reader_will_look(self):
        """Apache for original content, CC0 for the vendored data — in both files."""
        for name in ("README.md", "NOTICE"):
            with self.subTest(name=name):
                # markdown emphasis is not semantics: "**not** relicensed"
                text = (REPO_ROOT / name).read_text().replace("*", "")
                self.assertIn("CC0", text, f"{name} must name the CC0 terms")
                self.assertIn("data/prjxray/", text)
                self.assertRegex(
                    text, r"not\s+relicensed|NOT\s+relicensed|not\s+original content",
                    f"{name} must say the vendored data is not relicensed")

    def test_notice_qualifies_the_vendor_bitstream(self):
        text = (REPO_ROOT / "NOTICE").read_text()
        self.assertIn("carrier.bit", text)
        self.assertIn("reproducibility artifact", text)
        self.assertRegex(text, r"no rights are claimed",
                         "NOTICE must disclaim rights in the vendor components")

    def test_frozen_source_is_pinned_exactly_once_and_in_full(self):
        text = MANIFEST.read_text()
        self.assertIn(SOURCE_REPO, text)
        self.assertIn(SOURCE_COMMIT, text, "full 40-char source commit must be pinned")
        self.assertNotIn(SOURCE_COMMIT[:12] + "…", text,
                         "the source commit must not be abbreviated in the pin")

    def test_the_left_behind_list_names_the_authority_modules(self):
        """The point of the split is that these are absent; say so, and keep saying it."""
        text = MANIFEST.read_text()
        for name in ("gate_board_identity.py", "board_uboot_axi.py",
                     "precheck_fresh_power.py", "board_uboot_fpga_load.py"):
            with self.subTest(name=name):
                self.assertIn(name, text, f"{name} must be listed as not imported")
                self.assertFalse((REPO_ROOT / "scripts" / name).exists(),
                                 f"{name} is listed as not imported but is present")


if __name__ == "__main__":
    unittest.main()
