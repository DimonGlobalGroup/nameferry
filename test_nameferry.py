#!/usr/bin/env python3
"""Tests for nameferry.py (unittest, stdlib only)."""
import json
import os
import subprocess
import sys
import tempfile
import unicodedata
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "nameferry.py")
sys.path.insert(0, HERE)
import nameferry  # noqa: E402


def run(*argv, cwd=None):
    return subprocess.run([sys.executable, TOOL, *argv],
                          capture_output=True, text=True, cwd=cwd)


class TreeCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def touch(self, rel):
        path = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            fh.write("x")
        return path

    def check_json(self, *extra):
        proc = run("check", self.root, "--json", *extra)
        return proc, json.loads(proc.stdout)


class TestCleanAndGate(TreeCase):
    def test_clean_tree_exit_0(self):
        self.touch("notes.txt")
        self.touch("trips/photo.jpg")
        proc, doc = self.check_json()
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(doc["entries"], 3)  # trips dir + 2 files
        self.assertEqual(doc["errors"], 0)
        self.assertEqual(doc["findings"], [])

    def test_missing_root_exit_2(self):
        proc = run("check", os.path.join(self.root, "nope"))
        self.assertEqual(proc.returncode, 2)

    def test_file_root(self):
        path = self.touch("CON.txt")
        proc = run("check", path, "--json")
        doc = json.loads(proc.stdout)
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(doc["entries"], 1)
        self.assertEqual(doc["counts"], {"error:reserved-name": 1})

    def test_empty_dir_exit_0(self):
        proc, doc = self.check_json()
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(doc["entries"], 0)


class TestPerNameRules(TreeCase):
    def codes(self, doc):
        return [f["code"] for f in doc["findings"]]

    def test_reserved_names(self):
        self.touch("CON.txt")
        self.touch("aux")
        self.touch("Com1.log")
        self.touch("console.txt")  # not reserved: stem is 'console'
        proc, doc = self.check_json()
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(doc["counts"].get("error:reserved-name"), 3)

    def test_reserved_suggestion(self):
        self.touch("CON.txt")
        _, doc = self.check_json()
        f = doc["findings"][0]
        self.assertEqual(f["suggestion"], "CON_.txt")

    def test_illegal_chars_windows_not_linux(self):
        self.touch("a:b.txt")
        self.touch("a?b.txt")
        self.touch("a\\b.txt")
        proc, doc = self.check_json()
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(doc["counts"].get("error:illegal-char"), 3)
        proc2, doc2 = self.check_json("--profile", "linux")
        self.assertEqual(proc2.returncode, 0)
        self.assertEqual(doc2["errors"], 0)

    def test_colon_illegal_on_macos(self):
        self.touch("a:b.txt")
        proc, doc = self.check_json("--profile", "macos")
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(doc["counts"].get("error:illegal-char"), 1)

    def test_trailing_dot_and_space(self):
        self.touch("name.")
        self.touch("name ")
        proc, doc = self.check_json()
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(doc["counts"].get("error:trailing-dot-or-space"), 2)
        proc2, _ = self.check_json("--profile", "linux")
        self.assertEqual(proc2.returncode, 0)

    def test_leading_dash_warning_only(self):
        self.touch("-rf.txt")
        proc, doc = self.check_json()
        self.assertEqual(proc.returncode, 0)  # warnings do not fail the gate
        self.assertEqual(doc["counts"].get("warning:leading-dash"), 1)

    def test_non_nfc_warning_and_suggestion(self):
        nfd = unicodedata.normalize("NFD", "café.txt")
        self.touch(nfd)
        proc, doc = self.check_json()
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(doc["counts"].get("warning:non-nfc-name"), 1)
        self.assertEqual(doc["findings"][0]["suggestion"],
                         unicodedata.normalize("NFC", nfd))

    def test_non_utf8_name(self):
        fd = os.open(os.path.join(os.fsencode(self.root), b"bad\xff.txt"),
                     os.O_CREAT | os.O_WRONLY)
        os.close(fd)
        proc, doc = self.check_json()
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(doc["counts"].get("error:non-utf8-name"), 1)
        # output stayed valid, deterministic JSON
        proc2 = run("check", self.root, "--json")
        self.assertEqual(proc.stdout, proc2.stdout)

    def test_path_too_long(self):
        deep = "/".join(["segment%02d" % i for i in range(30)])  # 30*10=300 chars
        self.touch(deep + "/leaf.txt")
        proc, doc = self.check_json()
        self.assertEqual(proc.returncode, 1)
        self.assertIn("path-too-long", self.codes(doc))
        proc2, _ = self.check_json("--profile", "linux")
        self.assertEqual(proc2.returncode, 0)

    def test_component_too_long_function_level(self):
        # A >255-byte component cannot be created on this filesystem;
        # the rule is exercised at function level and via `name`.
        findings = nameferry.check_component("x" * 300, "portable")
        self.assertIn("component-too-long", [f["code"] for f in findings])
        findings = nameferry.check_component("é" * 128, "linux")  # 256 bytes, 128 chars
        self.assertIn("component-too-long", [f["code"] for f in findings])
        findings = nameferry.check_component("é" * 128, "macos")  # char limit only
        self.assertNotIn("component-too-long", [f["code"] for f in findings])


class TestCollisions(TreeCase):
    def test_case_collision(self):
        self.touch("Photo.jpg")
        self.touch("photo.jpg")
        proc, doc = self.check_json()
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(doc["counts"].get("error:case-collision"), 1)
        proc2, doc2 = self.check_json("--profile", "linux")
        self.assertEqual(proc2.returncode, 0)
        self.assertEqual(doc2["findings"], [])

    def test_normalization_collision(self):
        nfc = unicodedata.normalize("NFC", "café.txt")
        nfd = unicodedata.normalize("NFD", "café.txt")
        self.touch(nfc)
        self.touch(nfd)
        proc, doc = self.check_json()
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(doc["counts"].get("error:normalization-collision"), 1)
        # windows: the same collision is a warning, gate stays green
        proc2, doc2 = self.check_json("--profile", "windows")
        self.assertEqual(proc2.returncode, 0)
        self.assertEqual(doc2["counts"].get("warning:normalization-collision"), 1)

    def test_collisions_are_per_directory(self):
        self.touch("a/Photo.jpg")
        self.touch("b/photo.jpg")  # different directories: no collision
        proc, doc = self.check_json()
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(doc["findings"], [])

    def test_symlink_loop_not_followed(self):
        self.touch("real/file.txt")
        os.symlink(self.root, os.path.join(self.root, "loop"))
        proc, doc = self.check_json()
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(doc["entries"], 3)  # real, file.txt, loop


class TestOutputContract(TreeCase):
    def test_json_deterministic(self):
        self.touch("CON.txt")
        self.touch("a:b.txt")
        p1 = run("check", self.root, "--json")
        p2 = run("check", self.root, "--json")
        self.assertEqual(p1.stdout, p2.stdout)

    def test_max_examples_caps_but_counts_exact(self):
        for i in range(15):
            self.touch(f"d{i:02d}/CON.txt")
        proc, doc = self.check_json("--max-examples", "3")
        shown = [f for f in doc["findings"] if f["code"] == "reserved-name"]
        self.assertEqual(len(shown), 3)
        self.assertEqual(doc["counts"]["error:reserved-name"], 15)
        self.assertEqual(doc["suppressed"]["reserved-name"], 12)

    def test_text_summary_line(self):
        self.touch("CON.txt")
        proc = run("check", self.root)
        self.assertEqual(proc.returncode, 1)
        self.assertTrue(proc.stdout.strip().endswith(
            "nameferry: 1 entries, 1 errors, 0 warnings"))


class TestNameSubcommand(unittest.TestCase):
    def test_good_name(self):
        proc = run("name", "report-2026.txt")
        self.assertEqual(proc.returncode, 0)

    def test_reserved_and_long(self):
        proc = run("name", "CON.txt", "x" * 300, "--json")
        doc = json.loads(proc.stdout)
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(doc["counts"].get("error:reserved-name"), 1)
        self.assertEqual(doc["counts"].get("error:component-too-long"), 1)

    def test_slash_is_usage_error(self):
        proc = run("name", "a/b.txt")
        self.assertEqual(proc.returncode, 2)

    def test_name_collision_among_arguments(self):
        proc = run("name", "Photo.jpg", "photo.jpg", "--json")
        doc = json.loads(proc.stdout)
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(doc["counts"].get("error:case-collision"), 1)

    def test_version(self):
        proc = run("--version")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("1.0.0", proc.stdout)


if __name__ == "__main__":
    unittest.main()
