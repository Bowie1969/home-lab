import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from keystone import miniyaml


class TestMiniYaml(unittest.TestCase):
    def test_scalars_and_types(self):
        d = miniyaml.load("a: 1\nb: 2.5\nc: true\nd: null\ne: hello\nf: \"q:uoted\"")
        self.assertEqual(d["a"], 1)
        self.assertEqual(d["b"], 2.5)
        self.assertIs(d["c"], True)
        self.assertIsNone(d["d"])
        self.assertEqual(d["e"], "hello")
        self.assertEqual(d["f"], "q:uoted")

    def test_nested_map(self):
        d = miniyaml.load("build:\n  containerfile: Containerfile\n  context: .")
        self.assertEqual(d["build"]["containerfile"], "Containerfile")
        self.assertEqual(d["build"]["context"], ".")

    def test_block_and_inline_sequences(self):
        d = miniyaml.load("ports:\n  - 80\n  - 443\nenables: []\ntags: [a, b, c]")
        self.assertEqual(d["ports"], [80, 443])
        self.assertEqual(d["enables"], [])
        self.assertEqual(d["tags"], ["a", "b", "c"])

    def test_sequence_aligned_with_key(self):
        d = miniyaml.load("prereqs:\n- one\n- two")
        self.assertEqual(d["prereqs"], ["one", "two"])

    def test_sequence_of_maps(self):
        d = miniyaml.load("signals:\n  - pcap: traffic\n  - journal: foothold event")
        self.assertEqual(d["signals"], [{"pcap": "traffic"}, {"journal": "foothold event"}])

    def test_folded_block_scalar(self):
        d = miniyaml.load("description: >-\n  line one\n  line two\nnext: x")
        self.assertEqual(d["description"], "line one line two")
        self.assertEqual(d["next"], "x")

    def test_literal_block_scalar(self):
        d = miniyaml.load("note: |\n  a\n  b\nk: 1")
        self.assertEqual(d["note"], "a\nb")

    def test_comments_and_quotes(self):
        d = miniyaml.load("# comment\nval: \"a # not a comment\"  # trailing\n")
        self.assertEqual(d["val"], "a # not a comment")

    def test_windows_path_value(self):
        d = miniyaml.load('placement: "C:\\\\Users\\\\Administrator\\\\flag.txt"')
        self.assertIn("Users", d["placement"])

    def test_tabs_rejected(self):
        with self.assertRaises(miniyaml.YAMLError):
            miniyaml.load("a:\n\t- x")


if __name__ == "__main__":
    unittest.main()
