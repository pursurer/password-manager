"""End-to-end: the real command line with the real Argon2 costs."""

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

VAULT_PY = Path(__file__).resolve().parent.parent / "vault.py"
MASTER = "correct horse battery staple"


class CliTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)

    def run_cli(self, *args, stdin=""):
        return subprocess.run([sys.executable, str(VAULT_PY), "--vault", "vault.json", *args],
                              input=stdin, capture_output=True, text=True, cwd=self.dir, timeout=60)

    def test_session(self):
        self.assertEqual(0, self.run_cli("init", stdin=f"{MASTER}\n{MASTER}\n").returncode)
        self.assertEqual(1, self.run_cli("init", stdin=f"{MASTER}\n{MASTER}\n").returncode)

        added = self.run_cli("add", "github", "--user", "alice",
                             stdin=f"{MASTER}\ngh-Pa55word!\ngh-Pa55word!\n")
        self.assertEqual(0, added.returncode, added.stderr)
        generated = self.run_cli("add", "gitlab", "--user", "bob", "--generate", "--length", "24",
                                 stdin=f"{MASTER}\n")
        self.assertEqual(0, generated.returncode, generated.stderr)
        new_password = generated.stdout.split("Generated password: ")[1].strip()
        self.assertEqual(24, len(new_password))

        listed = self.run_cli("list", stdin=f"{MASTER}\n").stdout
        self.assertIn("github\talice", listed)
        self.assertIn("gitlab\tbob", listed)
        self.assertNotIn("gh-Pa55word!", listed)

        self.assertIn("password: gh-Pa55word!", self.run_cli("get", "github", stdin=f"{MASTER}\n").stdout)
        self.assertIn(f"password: {new_password}", self.run_cli("get", "gitlab", stdin=f"{MASTER}\n").stdout)

        wrong = self.run_cli("get", "github", stdin="not the master password\n")
        self.assertEqual(1, wrong.returncode)
        self.assertIn("Wrong master password", wrong.stderr)
        self.assertNotIn("gh-Pa55word!", wrong.stdout)

        self.assertEqual(0, self.run_cli("delete", "gitlab", stdin=f"{MASTER}\n").returncode)
        self.assertNotIn("gitlab", self.run_cli("list", stdin=f"{MASTER}\n").stdout)

        self.assertEqual(["vault.json"], [path.name for path in self.dir.iterdir()])

        vault_file = self.dir / "vault.json"
        data = bytearray(vault_file.read_bytes())
        data[data.index(b'"ciphertext": "') + 20] ^= 0x01
        vault_file.write_bytes(data)
        tampered = self.run_cli("get", "github", stdin=f"{MASTER}\n")
        self.assertEqual(1, tampered.returncode)
        self.assertIn("modified or damaged", tampered.stderr)
        self.assertEqual("", tampered.stdout)

    def test_input_errors_are_reported_before_any_prompt(self):
        missing = self.run_cli("list")
        self.assertEqual(1, missing.returncode)
        self.assertIn("No vault at vault.json", missing.stderr)
        self.run_cli("init", stdin=f"{MASTER}\n{MASTER}\n")
        for args in (("--length", "40"), ("--generate", "--length", "5")):
            with self.subTest(args=args):
                result = self.run_cli("add", "github", "--user", "alice", *args)
                self.assertEqual(1, result.returncode)
                self.assertNotIn("Traceback", result.stderr)
        deep = self.dir / "deep.json"
        deep.write_bytes(b"[" * 200000)
        self.run_cli("keygen", "bob", stdin="bob passphrase 1\nbob passphrase 1\n")
        received = self.run_cli("receive", "deep.json", "--key", "bob.key.pem", stdin="bob passphrase 1\n")
        self.assertEqual(1, received.returncode)
        self.assertIn("modified or damaged", received.stderr)

    def test_gen_needs_no_vault(self):
        result = self.run_cli("gen", "--length", "20")
        self.assertEqual(0, result.returncode)
        self.assertEqual(20, len(result.stdout.strip()))
        self.assertEqual(1, self.run_cli("gen", "--length", "8").returncode)

    def test_share_and_receive(self):
        self.run_cli("init", stdin=f"{MASTER}\n{MASTER}\n")
        self.run_cli("add", "github", "--user", "alice", stdin=f"{MASTER}\ngh-Pa55word!\ngh-Pa55word!\n")
        keygen = self.run_cli("keygen", "bob", stdin="bob passphrase 1\nbob passphrase 1\n")
        self.assertEqual(0, keygen.returncode, keygen.stderr)
        shared = self.run_cli("share", "github", "--to", "bob.pub.pem", stdin=f"{MASTER}\n")
        self.assertEqual(0, shared.returncode, shared.stderr)
        received = self.run_cli("receive", "github.share.json", "--key", "bob.key.pem",
                                stdin="bob passphrase 1\n")
        self.assertEqual(0, received.returncode, received.stderr)
        self.assertIn("password: gh-Pa55word!", received.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
