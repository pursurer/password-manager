"""The encrypted vault file.

The master password is stored only as an Argon2id hash. The vault key is derived
from the master password with Argon2id and a separate salt, and it is never written
anywhere. The entries are encrypted with AES-256-GCM, and the file header is
authenticated as associated data, so any change to the file is detected.
"""

import base64
import binascii
import contextlib
import json
import os
import tempfile
from pathlib import Path

from argon2 import PasswordHasher, extract_parameters
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

FORMAT = "pwvault-1"
# The argon2-cffi defaults, which follow RFC 9106: 3 passes over 64 MiB with 4 lanes.
# The same cost protects the stored hash and the derived key.
DEFAULT_PARAMS = {"time_cost": 3, "memory_cost": 64 * 1024, "parallelism": 4}
PARAM_NAMES = tuple(DEFAULT_PARAMS)
MIN_MASTER_LENGTH = 12
SALT_BYTES = 16
NONCE_BYTES = 12
KEY_BYTES = 32  # AES-256
DAMAGED = "The vault file was modified or damaged. Nothing was decrypted."


class VaultError(Exception):
    """A failure that the command line reports to the user."""


class WrongPasswordError(VaultError):
    """The master password does not match the stored Argon2 hash."""


class TamperedError(VaultError):
    """The vault file is not exactly what this program wrote."""


def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64decode(text) -> bytes:
    """Decode strict, canonical base64: two different strings never give the same bytes."""
    try:
        data = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError, TypeError) as exc:
        raise TamperedError(DAMAGED) from exc
    if b64encode(data) != text:
        raise TamperedError(DAMAGED)
    return data


def check_params(params) -> dict:
    """Accept only sane Argon2 costs, so a modified file cannot demand gigabytes of memory."""
    if (not isinstance(params, dict) or set(params) != set(PARAM_NAMES)
            or any(type(params[name]) is not int for name in PARAM_NAMES)):
        raise TamperedError(DAMAGED)
    if not (1 <= params["time_cost"] <= 10 and 1 <= params["parallelism"] <= 16
            and 8 * params["parallelism"] <= params["memory_cost"] <= 1024 * 1024):
        raise TamperedError(DAMAGED)
    return params


def derive_key(master_password: str, salt: bytes, params: dict) -> bytes:
    """Argon2id as a key derivation function: master password + salt -> 32-byte AES key."""
    kdf = Argon2id(salt=salt, length=KEY_BYTES, iterations=params["time_cost"],
                   lanes=params["parallelism"], memory_cost=params["memory_cost"])
    return kdf.derive(master_password.encode("utf-8"))


def write_atomic(path: Path, data: bytes) -> None:
    """Write a new file next to the old one (mode 0600), then swap it in one step."""
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise


def _associated_data(doc: dict) -> bytes:
    """Everything except the ciphertext, in one fixed byte form. GCM authenticates it."""
    header = {name: value for name, value in doc.items() if name != "ciphertext"}
    return json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _serialize(doc: dict) -> bytes:
    """The one byte form that save() writes."""
    return (json.dumps(doc, indent=2) + "\n").encode("utf-8")


def _parse(raw: bytes):
    """Return (doc, salt, nonce, ciphertext). Any unexpected shape counts as tampering."""
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise TamperedError(DAMAGED) from exc
    if (not isinstance(doc, dict)
            or set(doc) != {"format", "master_hash", "kdf", "cipher", "ciphertext"}
            or doc["format"] != FORMAT):
        raise TamperedError(DAMAGED)
    kdf, cipher, master_hash = doc["kdf"], doc["cipher"], doc["master_hash"]
    if (not isinstance(kdf, dict) or set(kdf) != {"algorithm", "salt", *PARAM_NAMES}
            or kdf["algorithm"] != "argon2id"
            or not isinstance(cipher, dict) or set(cipher) != {"algorithm", "nonce"}
            or cipher["algorithm"] != "AES-256-GCM"
            or not isinstance(master_hash, str) or not master_hash.startswith("$argon2id$")):
        raise TamperedError(DAMAGED)
    check_params({name: kdf[name] for name in PARAM_NAMES})
    try:
        stored = extract_parameters(master_hash)
    except InvalidHashError as exc:
        raise TamperedError(DAMAGED) from exc
    check_params({"time_cost": stored.time_cost, "memory_cost": stored.memory_cost,
                  "parallelism": stored.parallelism})
    salt, nonce = b64decode(kdf["salt"]), b64decode(cipher["nonce"])
    ciphertext = b64decode(doc["ciphertext"])
    if len(salt) != SALT_BYTES or len(nonce) != NONCE_BYTES or len(ciphertext) < 16:
        raise TamperedError(DAMAGED)
    # GCM authenticates the parsed values. This check makes the bytes count too: the file
    # must be exactly what save() writes, so extra spaces or a duplicated field are refused.
    if raw != _serialize(doc):
        raise TamperedError(DAMAGED)
    return doc, salt, nonce, ciphertext


def _parse_entries(plaintext: bytes) -> dict:
    try:
        entries = json.loads(plaintext.decode("utf-8"))["entries"]
    except (UnicodeDecodeError, ValueError, KeyError, TypeError, RecursionError) as exc:
        raise TamperedError(DAMAGED) from exc
    if not isinstance(entries, dict) or not all(
            isinstance(entry, dict) and set(entry) == {"username", "password"}
            and all(isinstance(value, str) for value in entry.values())
            for entry in entries.values()):
        raise TamperedError(DAMAGED)
    return entries


class Vault:
    """An unlocked vault: the derived key and the decrypted entries, in memory only."""

    def __init__(self, path: Path, doc: dict, key: bytes, entries: dict):
        self.path = path
        self._doc = doc
        self._key = key
        self.entries = entries

    @classmethod
    def create(cls, path, master_password: str, params: dict = DEFAULT_PARAMS) -> "Vault":
        path = Path(path)
        if path.exists():
            raise VaultError(f"A vault already exists at {path}.")
        if len(master_password) < MIN_MASTER_LENGTH:
            raise VaultError(f"Use a master password of at least {MIN_MASTER_LENGTH} characters.")
        params = check_params(dict(params))
        hasher = PasswordHasher(time_cost=params["time_cost"], memory_cost=params["memory_cost"],
                                parallelism=params["parallelism"], hash_len=32, salt_len=16)
        # The KDF salt is independent of the salt inside the hash, so the stored
        # hash is never equal to the key.
        salt = os.urandom(SALT_BYTES)
        doc = {
            "format": FORMAT,
            "master_hash": hasher.hash(master_password),
            "kdf": {"algorithm": "argon2id", "salt": b64encode(salt), **params},
            "cipher": {"algorithm": "AES-256-GCM", "nonce": ""},
            "ciphertext": "",
        }
        vault = cls(path, doc, derive_key(master_password, salt, params), {})
        vault.save()
        return vault

    @classmethod
    def open(cls, path, master_password: str) -> "Vault":
        path = Path(path)
        try:
            raw = path.read_bytes()
        except FileNotFoundError:
            raise VaultError(f"No vault at {path}. Run 'init' first.") from None
        doc, salt, nonce, ciphertext = _parse(raw)
        try:
            PasswordHasher().verify(doc["master_hash"], master_password)
        except VerifyMismatchError:
            raise WrongPasswordError(
                "Wrong master password (or the stored hash was modified).") from None
        except (VerificationError, InvalidHashError) as exc:
            raise TamperedError(DAMAGED) from exc
        key = derive_key(master_password, salt, {name: doc["kdf"][name] for name in PARAM_NAMES})
        try:
            plaintext = AESGCM(key).decrypt(nonce, ciphertext, _associated_data(doc))
        except InvalidTag as exc:
            raise TamperedError(DAMAGED) from exc
        return cls(path, doc, key, _parse_entries(plaintext))

    def save(self) -> None:
        # A new random nonce for every encryption: GCM must never reuse a nonce with one key.
        nonce = os.urandom(NONCE_BYTES)
        self._doc["cipher"]["nonce"] = b64encode(nonce)
        plaintext = json.dumps({"entries": self.entries}, ensure_ascii=False).encode("utf-8")
        sealed = AESGCM(self._key).encrypt(nonce, plaintext, _associated_data(self._doc))
        self._doc["ciphertext"] = b64encode(sealed)
        write_atomic(self.path, _serialize(self._doc))

    def add(self, site: str, username: str, password: str) -> None:
        if not site:
            raise VaultError("The site name must not be empty.")
        if site in self.entries:
            raise VaultError(f"'{site}' already exists. Delete it first to replace it.")
        self.entries[site] = {"username": username, "password": password}

    def get(self, site: str) -> dict:
        try:
            return self.entries[site]
        except KeyError:
            raise VaultError(f"No entry for '{site}'.") from None

    def delete(self, site: str) -> None:
        self.get(site)
        del self.entries[site]
