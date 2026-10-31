"""Bonus A: share one entry with a teammate, encrypted to their RSA public key.

Hybrid encryption: a fresh AES-256-GCM key encrypts the entry, and RSA-OAEP with
SHA-256 encrypts ("wraps") that AES key for the recipient. Only the matching
private key can unwrap the AES key, so only the recipient can read the entry.
"""

import hashlib
import json
import os
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from vault_store import DAMAGED, TamperedError, VaultError, b64decode, b64encode

SHARE_FORMAT = "pwshare-1"
RSA_BITS = 3072
OAEP = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(), label=None)


def fingerprint(public_key) -> str:
    """SHA-256 of the public key, to check that a share was made for this key."""
    der = public_key.public_bytes(serialization.Encoding.DER,
                                  serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def write_new(path: Path, data: bytes, mode: int) -> None:
    """Create a new file with this mode; never overwrite an existing one."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)


def create_keypair(prefix, passphrase: str) -> tuple[Path, Path, str]:
    """Write PREFIX.key.pem (private, encrypted with the passphrase, 0600) and PREFIX.pub.pem."""
    private_path, public_path = Path(f"{prefix}.key.pem"), Path(f"{prefix}.pub.pem")
    for path in (private_path, public_path):
        if path.exists():
            raise VaultError(f"{path} already exists.")
    key = rsa.generate_private_key(public_exponent=65537, key_size=RSA_BITS)
    write_new(private_path, key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(passphrase.encode("utf-8"))), 0o600)
    write_new(public_path, key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo), 0o644)
    return private_path, public_path, fingerprint(key.public_key())


def _associated_data(share: dict) -> bytes:
    return json.dumps({"format": share["format"], "recipient": share["recipient"]},
                      sort_keys=True, separators=(",", ":")).encode("utf-8")


def seal(site: str, entry: dict, public_key_path) -> dict:
    """Encrypt one entry for the owner of the public key."""
    try:
        public_key = serialization.load_pem_public_key(Path(public_key_path).read_bytes())
    except (OSError, ValueError) as exc:
        raise VaultError(f"Cannot read a public key from {public_key_path}.") from exc
    if not isinstance(public_key, rsa.RSAPublicKey) or public_key.key_size < RSA_BITS:
        raise VaultError(f"Use an RSA public key of at least {RSA_BITS} bits.")
    aes_key, nonce = AESGCM.generate_key(bit_length=256), os.urandom(12)
    share = {"format": SHARE_FORMAT, "recipient": fingerprint(public_key)}
    plaintext = json.dumps({"site": site, **entry}, ensure_ascii=False).encode("utf-8")
    share["wrapped_key"] = b64encode(public_key.encrypt(aes_key, OAEP))
    share["nonce"] = b64encode(nonce)
    share["ciphertext"] = b64encode(AESGCM(aes_key).encrypt(nonce, plaintext, _associated_data(share)))
    return share


def open_share(raw: bytes, private_key_path, passphrase: str) -> dict:
    """Decrypt a share with the recipient's private key. Returns site, username, password."""
    try:
        private_key = serialization.load_pem_private_key(
            Path(private_key_path).read_bytes(), password=passphrase.encode("utf-8"))
    except (OSError, ValueError, TypeError) as exc:
        raise VaultError("Wrong passphrase, or not an encrypted private key file.") from exc
    try:
        share = json.loads(raw.decode("utf-8"))
        if (not isinstance(share, dict)
                or set(share) != {"format", "recipient", "wrapped_key", "nonce", "ciphertext"}):
            raise ValueError
    except (UnicodeDecodeError, ValueError, TypeError, RecursionError) as exc:
        raise TamperedError("The share file was modified or damaged.") from exc
    if share["format"] != SHARE_FORMAT:
        raise TamperedError("The share file was modified or damaged.")
    if share["recipient"] != fingerprint(private_key.public_key()):
        raise VaultError("This share was encrypted for a different key.")
    try:
        aes_key = private_key.decrypt(b64decode(share["wrapped_key"]), OAEP)
        plaintext = AESGCM(aes_key).decrypt(b64decode(share["nonce"]), b64decode(share["ciphertext"]),
                                            _associated_data(share))
        entry = json.loads(plaintext.decode("utf-8"))
    except (ValueError, InvalidTag, TamperedError, RecursionError) as exc:
        raise TamperedError("The share file was modified or damaged.") from exc
    if not (isinstance(entry, dict) and set(entry) == {"site", "username", "password"}
            and all(isinstance(value, str) for value in entry.values())):
        raise TamperedError(DAMAGED)
    return entry
