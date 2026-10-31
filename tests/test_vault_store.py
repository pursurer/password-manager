"""The three crypto requirements: Argon2 master hash, derived key, AES-GCM vault."""

import base64
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from argon2 import PasswordHasher

from vault_store import (TamperedError, Vault, VaultError, WrongPasswordError, b64decode,
                         derive_key)

# Cheap Argon2 costs keep the byte-by-byte test fast. The program uses DEFAULT_PARAMS.
FAST = {"time_cost": 1, "memory_cost": 1024, "parallelism": 1}
MASTER = "correct horse battery staple"


class VaultStoreTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        self.path = self.dir / "vault.json"
        vault = Vault.create(self.path, MASTER, params=FAST)
        vault.add("github", "alice", "gh-Pa55word!")
        vault.save()

    def doc(self):
        return json.loads(self.path.read_text())

    # Block 1 - master password stored with Argon2
    def test_master_password_is_stored_as_an_argon2id_hash(self):
        self.assertTrue(self.doc()["master_hash"].startswith("$argon2id$"))
        self.assertNotIn(MASTER, self.path.read_text())

    def test_wrong_master_password_is_rejected(self):
        with self.assertRaises(WrongPasswordError):
            Vault.open(self.path, "correct horse battery stapler")

    # Block 2 - key derived from the master password, no key file
    def test_there_is_no_key_file_and_nothing_readable_on_disk(self):
        self.assertEqual(["vault.json"], [path.name for path in self.dir.iterdir()])
        text = self.path.read_text()
        for secret in ("github", "alice", "gh-Pa55word!"):
            self.assertNotIn(secret, text)
        self.assertEqual(0o600, self.path.stat().st_mode & 0o777)

    def test_the_stored_hash_is_not_the_key(self):
        doc = self.doc()
        key = derive_key(MASTER, b64decode(doc["kdf"]["salt"]), FAST)
        hash_b64 = doc["master_hash"].rsplit("$", 1)[1]
        stored_hash = base64.b64decode(hash_b64 + "=" * (-len(hash_b64) % 4))
        self.assertEqual(32, len(key))
        self.assertNotEqual(stored_hash, key)

    def test_entries_come_back_after_reopening(self):
        vault = Vault.open(self.path, MASTER)
        self.assertEqual({"username": "alice", "password": "gh-Pa55word!"}, vault.get("github"))

    # Block 3 - AES-GCM: any change is detected
    def test_any_single_byte_change_fails_loudly(self):
        original = self.path.read_bytes()
        for mask in (0x01, 0x20, 0x80):
            for offset in range(len(original)):
                with self.subTest(mask=hex(mask), offset=offset):
                    changed = bytearray(original)
                    changed[offset] ^= mask
                    self.path.write_bytes(changed)
                    with self.assertRaises(VaultError):
                        Vault.open(self.path, MASTER)
        self.path.write_bytes(original)
        self.assertIn("github", Vault.open(self.path, MASTER).entries)

    def test_whitespace_swaps_and_duplicate_fields_are_detected(self):
        original = self.path.read_bytes()
        for offset, byte in enumerate(original):
            if byte in b" \n":
                for other in b" \t\r\n".replace(bytes([byte]), b""):
                    with self.subTest(offset=offset, other=other):
                        changed = bytearray(original)
                        changed[offset] = other
                        self.path.write_bytes(changed)
                        with self.assertRaises(TamperedError):
                            Vault.open(self.path, MASTER)
        self.path.write_bytes(original.replace(b'{\n  "format"', b'{\n  "format": "x",\n  "format"', 1))
        with self.assertRaises(TamperedError):
            Vault.open(self.path, MASTER)

    def test_deeply_nested_json_fails_cleanly(self):
        self.path.write_bytes(b"[" * 200000)
        with self.assertRaises(TamperedError):
            Vault.open(self.path, MASTER)

    def test_replacing_the_stored_hash_does_not_open_the_vault(self):
        doc = self.doc()
        doc["master_hash"] = PasswordHasher(time_cost=1, memory_cost=1024,
                                            parallelism=1).hash("attacker password")
        self.path.write_text(json.dumps(doc))
        with self.assertRaises(TamperedError):
            Vault.open(self.path, "attacker password")

    def test_huge_argon2_costs_in_the_file_are_refused(self):
        doc = self.doc()
        doc["kdf"]["memory_cost"] = 64 * 1024 * 1024  # 64 GiB
        self.path.write_text(json.dumps(doc))
        with self.assertRaises(TamperedError):
            Vault.open(self.path, MASTER)

    def test_every_save_uses_a_new_nonce(self):
        first = self.doc()
        vault = Vault.open(self.path, MASTER)
        vault.save()
        second = self.doc()
        self.assertNotEqual(first["cipher"]["nonce"], second["cipher"]["nonce"])
        self.assertNotEqual(first["ciphertext"], second["ciphertext"])

    # Vault rules
    def test_create_refuses_an_existing_vault_and_a_short_master_password(self):
        with self.assertRaises(VaultError):
            Vault.create(self.path, MASTER, params=FAST)
        with self.assertRaises(VaultError):
            Vault.create(self.dir / "other.json", "short", params=FAST)

    def test_add_get_delete(self):
        vault = Vault.open(self.path, MASTER)
        with self.assertRaises(VaultError):
            vault.add("github", "bob", "x")
        vault.add("gitlab", "bob", "gl-Pa55word!")
        vault.delete("github")
        vault.save()
        vault = Vault.open(self.path, MASTER)
        self.assertEqual(["gitlab"], list(vault.entries))
        with self.assertRaises(VaultError):
            vault.get("github")


if __name__ == "__main__":
    unittest.main(verbosity=2)
