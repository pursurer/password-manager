# Password manager — Computer Security, Project 2

**Group:** HAOJIE SONG (2023905496)

A small command-line password manager in Python. One file, `vault.json`, holds every entry.
Only the master password, which is never stored, can open it.

## Install and use

```
python3 -m pip install -r requirements.txt     # argon2-cffi and cryptography

python3 vault.py init                          # set the master password (asked twice)
python3 vault.py add github --user alice       # type the site password (asked twice)
python3 vault.py add gitlab --user bob --generate --length 24
python3 vault.py list                          # sites and usernames, no passwords
python3 vault.py get github
python3 vault.py delete gitlab
python3 vault.py gen --length 20               # a strong password, no vault needed
```

Every command except `gen` asks for the master password; each command is one short session.
On a terminal, secrets are read without echo. In a script, give one secret per line on
standard input. `--vault PATH` (or the `VAULT_FILE` variable) selects another vault file.

## How it works

```
master password --Argon2id, salt A (inside the hash)--> master_hash     stored: checks the password
master password --Argon2id, salt B (kdf.salt)---------> 32-byte AES key  memory only, never stored
entries (JSON)  --AES-256-GCM: key, new 12-byte nonce,
                   header as associated data----------> ciphertext      stored
```

The vault file (values shortened):

```json
{
  "format": "pwvault-1",
  "master_hash": "$argon2id$v=19$m=65536,t=3,p=4$...",
  "kdf": {"algorithm": "argon2id", "salt": "...", "time_cost": 3, "memory_cost": 65536, "parallelism": 4},
  "cipher": {"algorithm": "AES-256-GCM", "nonce": "..."},
  "ciphertext": "..."
}
```

**Unlock** (`vault_store.Vault.open`):

0. Check the file: it must be exactly what the program writes, byte for byte, with
   reasonable Argon2 costs. Extra spaces or a duplicated field are refused here.
1. Verify the typed password against `master_hash` with argon2-cffi. A wrong password
   stops here: `Wrong master password (or the stored hash was modified).`
2. Derive the AES key: Argon2id(master password, `kdf.salt`, the stored costs).
3. Decrypt with AES-GCM. Everything except the ciphertext is the associated data, so a
   change to any value in the file stops here: `The vault file was modified or damaged.
   Nothing was decrypted.`

**Save** (`Vault.save`): encrypt again with a new random nonce, write a temporary file
(mode 0600) next to the vault, then replace the vault in one step (`os.replace`), so a
crash never leaves half a vault.

**Costs:** Argon2id with 3 passes over 64 MiB and 4 lanes (the argon2-cffi defaults, from
RFC 9106). One unlock takes about 0.2 s on the test laptop. The program refuses a file
that asks for unreasonable costs (more than 1 GiB, more than 10 passes), so a modified
file cannot make it allocate gigabytes.

## Why each choice is correct

### 1. Why Argon2 for the master password, and not SHA-256 or AES?

AES is encryption: whoever has the key gets the password back, and the key would have to
be stored somewhere. The master password must never be recoverable, so it needs a one-way
function. SHA-256 is one-way but built to be fast, and fast is what an attacker wants: in
the Class 5 lab our NotesApp container computed about 3.5 million MD5 guesses per second
but only about 10 Argon2id guesses per second. Argon2 is slow on purpose and memory-hard:
every guess needs 64 MiB, so GPUs and custom chips gain little. Each hash has its own
random salt, so equal passwords give different hashes and precomputed tables do not work.
Argon2 won the Password Hashing Competition (2015); its Argon2id variant is the one RFC 9106
recommends.

### 2. Why derive the key from the master password instead of storing a key file?

A key file next to the vault would be stolen together with the vault: a backup, a synced
folder or a lost laptop would give the attacker both, and the vault would open without any
password. The password check would then be only a check in our code, which an attacker
does not have to run. With a derived key there is no key file at all (the tests check that
the folder contains only `vault.json`). The only secret is in the user's head, and every
offline guess costs one Argon2 derivation. The key salt is different from the salt inside
`master_hash`: the hash string contains the Argon2 output, so with the same salt and costs
the stored hash would *be* the key. The price is that a forgotten master password cannot
be recovered.

### 3. Why AES-GCM and not AES without authentication? What does GCM buy?

AES alone (ECB, CBC, CTR) only hides the data. Changed ciphertext still decrypts: into
garbage, or, in CTR mode, into exactly the bits the attacker flipped. The program would
accept it silently. GCM adds a 16-byte authentication tag computed with the key. On
decrypt the tag is checked first; if the ciphertext, the nonce or the associated data
changed, decryption fails and returns nothing. We put the whole header in the associated
data, so the unencrypted parts are protected too: if an attacker replaces `master_hash`
with the hash of their own password, the password check passes, but decryption fails.
The test suite flips every byte of a vault file in three ways (1,557 changed files) and
swaps every space or line break for another whitespace character; every one is rejected.
GCM authenticates values, not formatting, so the byte-for-byte check in step 0 covers the
formatting. GCM needs a nonce that is never reused with the same key, so every
save uses a new random 96-bit nonce.

### 4. Why `secrets` and not `random`?

`random` is the Mersenne Twister, made for simulations. It is predictable: after 624
outputs an observer can rebuild its state and compute every later value. `secrets` reads
the operating system's cryptographically secure generator, so earlier passwords say
nothing about the next one. The generator picks each character with `secrets.choice` from
94 printable characters (letters, digits, punctuation) and requires all four kinds. The
length is chosen with `--length` (12 to 128, default 20); 20 characters give about 131 bits
of randomness.

### 5. What the tool does not protect against

- **Malware or a keylogger** on the machine: it can read the master password as it is typed,
  or the key and entries in memory while a command runs.
- **A weak master password:** Argon2 makes each guess slow, but a password from a dictionary
  is still found. The 12-character minimum helps only a little.
- **Someone reading the screen:** `get` prints the password; it stays in the terminal scrollback.
- **Going back to an old copy:** an older `vault.json` (for example from a backup) is still a
  valid file and opens normally. GCM detects changes, not replacement by an older version.
- **Deleting the file**, and what its size shows (roughly how much is stored).
- **A forgotten master password:** there is no recovery.
- Python cannot wipe strings from memory after use.

## Security model

**Protects:** the stored passwords when someone steals or copies `vault.json`. The file
holds only AES-GCM ciphertext and an Argon2 hash. The master password never touches the
disk, there is no key file, every offline guess costs one Argon2 computation, and any
change to the file is detected.

**Does not protect:** everything in section 5.

## Requirement checks

| Requirement ("done when") | How to check | Result |
|---|---|---|
| 1. Master password stored with Argon2 | `master_hash` in `vault.json`; `get github` with a wrong password | `$argon2id$v=19$m=65536,t=3,p=4$...`; `error: Wrong master password (or the stored hash was modified).` |
| 2. Key derived, no key file | `ls` next to the vault | only `vault.json` (mode 0600) |
| 3. AES-GCM, any change detected | change one character of `ciphertext`, then `get github` | `error: The vault file was modified or damaged. Nothing was decrypted.` |
| 4. Strong generator | `gen --length 20`; `gen --length 8` | 20 random characters from 94; `error: Choose a length from 12 to 128.` |

All commands exit with code 1 on an error.

## Bonus A — share one entry with a teammate

```
python3 vault.py keygen bob                          # bob: bob.key.pem (private) + bob.pub.pem
python3 vault.py share github --to bob.pub.pem       # alice: writes github.share.json
python3 vault.py receive github.share.json --key bob.key.pem [--save]   # bob
```

The entry is encrypted with a new random AES-256-GCM key, and that key is encrypted with
Bob's RSA-3072 public key using OAEP with SHA-256 (hybrid encryption). RSA alone can only
encrypt a few hundred bytes and is slow; AES-GCM also authenticates the entry. OAEP is
used instead of the old PKCS#1 v1.5 padding, which allows padding-oracle attacks. Only
Bob's private key can unwrap the AES key. The private key file is stored encrypted with
Bob's passphrase (PKCS#8) and with mode 0600. The share file records the public key's
SHA-256 fingerprint, so the wrong key gives a clear error. Limitation: the share is not
signed, so Bob cannot prove who made it; anyone with his public key can make one.

## Libraries

| Block | Library and call | Why this library |
|---|---|---|
| 1. Master password hash | [`argon2-cffi`](https://argon2-cffi.readthedocs.io/) `PasswordHasher` (Argon2id) | Wraps the reference Argon2 implementation. One call makes the random salt and stores salt and costs inside the hash string; `verify` reads them back. |
| 2. Key derivation | [`cryptography`](https://cryptography.io/) `Argon2id` (version 44 or newer) | Returns raw key bytes of the length we ask for (32 for AES-256), from our own salt. |
| 3. Vault encryption | `cryptography` `AESGCM` | Authenticated encryption in one call: `decrypt` checks the tag and raises `InvalidTag` instead of returning garbage. |
| 4. Generator | Python standard library `secrets` | Reads the operating system's secure random source; nothing to install. |
| Bonus A | `cryptography` RSA-OAEP, PKCS#8 encrypted private keys | The same maintained library as block 3; OAEP padding is built in. |

These are the libraries the course rule names. Both are widely used and maintained, and no
cryptography is written by hand here.

## Tests

```
python3 -m unittest -v
```

29 tests: the four required blocks (including the byte-by-byte change test and the
whitespace test), the replaced-hash attack, refusal of huge Argon2 costs and of deeply
nested files, a new nonce on every save, the generator, the bonus share, and full
command-line sessions with the real Argon2 costs.

| File | Contents |
|---|---|
| `vault.py` | command line |
| `vault_store.py` | vault format: Argon2 hash, key derivation, AES-GCM, safe writes |
| `password_gen.py` | password generator |
| `share.py` | bonus A |
| `tests/` | tests |
