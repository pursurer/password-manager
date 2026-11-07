"""Bonus A: an entry encrypted to a public key opens only with the matching private key."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

import share
from vault_store import TamperedError, VaultError

ENTRY = {"username": "alice", "password": "gh-Pa55word!"}


class ShareTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = Path(tempfile.mkdtemp())
        cls.bob_key, cls.bob_pub, _ = share.create_keypair(cls.dir / "bob", "bob passphrase 1")
        cls.carol_key, cls.carol_pub, _ = share.create_keypair(cls.dir / "carol",
                                                               "carol passphrase 1")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.dir)

    def sealed(self):
        return json.dumps(share.seal("github", ENTRY, self.bob_pub)).encode()

    def test_private_key_is_encrypted_and_private(self):
        pem = self.bob_key.read_bytes()
        self.assertTrue(pem.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----"))
        self.assertEqual(0o600, self.bob_key.stat().st_mode & 0o777)

    def test_recipient_opens_the_entry(self):
        raw = self.sealed()
        for secret in (b"github", b"alice", b"gh-Pa55word!"):
            self.assertNotIn(secret, raw)
        self.assertEqual({"site": "github", **ENTRY},
                         share.open_share(raw, self.bob_key, "bob passphrase 1"))

    def test_another_private_key_cannot_open_it(self):
        with self.assertRaises(VaultError):
            share.open_share(self.sealed(), self.carol_key, "carol passphrase 1")

    def test_wrong_passphrase_is_refused(self):
        with self.assertRaises(VaultError):
            share.open_share(self.sealed(), self.bob_key, "wrong passphrase")

    def test_a_changed_share_is_detected(self):
        doc = json.loads(self.sealed())
        ciphertext = bytearray(doc["ciphertext"].encode())
        ciphertext[5] ^= 0x01
        doc["ciphertext"] = ciphertext.decode()
        with self.assertRaises(TamperedError):
            share.open_share(json.dumps(doc).encode(), self.bob_key, "bob passphrase 1")

    def test_a_deeply_nested_share_fails_cleanly(self):
        with self.assertRaises(TamperedError):
            share.open_share(b"[" * 200000, self.bob_key, "bob passphrase 1")

    def test_keypair_files_are_not_overwritten(self):
        with self.assertRaises(VaultError):
            share.create_keypair(self.dir / "bob", "another passphrase")


if __name__ == "__main__":
    unittest.main(verbosity=2)
