# Password manager — Computer Security, Project 2

**Group:** HAOJIE SONG (2023905496), ZIQIAN YU (2023902046), ANGRAN YU (2023900899)

A command-line password manager in Python. All entries live in one encrypted file,
`vault.json`. Only the master password, which is never stored, opens it.

## Usage

```
pip install argon2-cffi cryptography

python vault.py init                          # set the master password once
python vault.py add github --user alice       # type the site password
python vault.py add gitlab --user bob --generate --length 24
python vault.py list
python vault.py get github
python vault.py delete gitlab
python vault.py gen --length 20               # no vault needed
```

Each command that opens the vault asks for the master password.

## The four building blocks

1. **Master password stored with Argon2** — library: `argon2-cffi` (`PasswordHasher`, Argon2id).
   It makes the random salt and keeps salt and costs inside the hash string, and `verify` checks
   a typed password against it. The vault stores only `$argon2id$v=19$m=65536,t=3,p=4$...`;
   a wrong master password is rejected.
2. **Key derived from the master password** — library: `cryptography` (`Argon2id` key
   derivation). It turns the master password and a separate random salt into the 32-byte
   AES key, which exists only in memory. There is no key file: the folder holds only `vault.json`.
3. **Vault encrypted with AES-GCM** — library: `cryptography` (`AESGCM`). Every save uses a
   new random 12-byte nonce, and the file header is authenticated together with the entries.
   Changing any byte of `vault.json` makes the command fail, for example with
   `error: The vault file was modified or damaged. Nothing was decrypted.`
4. **Strong password generator** — Python's `secrets` module. Each character is
   `secrets.choice` from 94 letters, digits and symbols; the length is 12 to 128 (default 20).

These are the libraries the course rule names; no cryptography is written by hand.

## Why each choice is correct

**1. Why Argon2 for the master password, and not SHA-256 or AES?**
The master password must never be recoverable. AES is two-way: with the key, the password can be
decrypted back. The key has to be stored somewhere, so it can be stolen together with the database.
A plain SHA-256 hash is one-way, but it is very fast and has no salt, so the same password always
gives the same hash, and common passwords can be found at once in a rainbow table. Even with a salt
it is too fast: in the Class 5 lab we measured about 3.5 million MD5 guesses per second, and
SHA-256 is a fast hash of the same kind. Argon2 adds a random salt, so the same password gives a
different hash each time, and a precomputed table is useless. It is also slow and needs a lot of
memory (3 passes over 64 MiB), so the attacker needs much more time and memory for every guess:
about 10 guesses per second in our lab. The salt stops one guess from working on many accounts,
and the slowness stops many guesses on one account. We need both.

**2. Why derive the encryption key from the master password instead of storing a key file?**
If the key is stored in a file next to the vault, it is stolen together with the vault. The
attacker does not need to guess anything: the key opens the vault at once, and it keeps working,
so all our passwords can be read again and again. With a derived key there is no key on the disk;
the only secret is the master password in the user's head. The attacker can only guess the master
password, and every guess costs one Argon2 run, which is slow and needs a lot of memory. The key
uses a different salt from the stored hash, so the stored hash cannot be used as the key. The cost
is that a forgotten master password cannot be recovered: the vault can never be opened again.

**3. Why AES-GCM and not AES without authentication? What does the "GCM" part buy you?**
AES without authentication only hides the data. It does not detect changes: if someone changes the
ciphertext, it still decrypts, the plaintext comes out different, and the program gives no error
(a grade 14 can become 18). GCM adds a 16-byte tag. The tag is computed with the key, so an
attacker who changes the vault file cannot make a matching tag. Every time we decrypt, GCM checks
the tag first. If the check fails, decryption stops and returns nothing. The file header (the
salts, the nonce and `master_hash`) is also covered by the tag as associated data, so a change
there is detected too. In our tests, changing any single byte of the vault file makes decryption
fail. We also use a new nonce for each save: with the same key and the same nonce, the XOR of the
two ciphertexts is the XOR of the two plaintexts, which leaks information.

**4. Why `secrets` and not `random` for generating passwords?**
`random` uses the Mersenne Twister. It is deterministic and predictable: after an attacker sees
624 of its outputs, the attacker can rebuild its state and predict every next value, so the next
password is not secret. The Python documentation says not to use it for security. `secrets` uses
the cryptographically secure random source of the operating system (`os.urandom`), so earlier
outputs say nothing about the next one. The strength of a random password is
length × log2(number of characters). Our generator picks each character with `secrets.choice`
from 94 characters (letters, digits and symbols), so each character adds about 6.6 bits. The
default length of 20 gives about 131 bits, and the user can choose a length from 12 to 128.

## Security model

**5. What your tool does not protect against.**

**Protects:** if someone steals `vault.json`, they get only AES-GCM ciphertext, the salts and an
Argon2 hash. They cannot read the passwords without the master password, every guess costs one
Argon2 run, and any change to the file is detected.

**Does not protect against:**
- a keylogger on the user's machine, which records the master password as it is typed;
- other malware that reads the key and the entries from memory while a command runs;
- a weak master password: Argon2 makes each guess slow, but a password from a dictionary is still
  found;
- someone reading the screen: `get` prints the password;
- an old copy of `vault.json` put back in place of the current one: it is still a valid file;
- deleting the file;
- a forgotten master password: there is no way to recover it.

## Bonus A — share one entry with a teammate

```
python vault.py keygen bob                                  # bob.key.pem + bob.pub.pem
python vault.py share github --to bob.pub.pem               # writes github.share.json
python vault.py receive github.share.json --key bob.key.pem
```

The entry is encrypted with a new AES-256-GCM key, and that key is encrypted with Bob's
RSA-3072 public key (OAEP, SHA-256), so only Bob's private key can open it. RSA alone can only
encrypt a few hundred bytes. Bob's private key file is protected with his passphrase. The share
is not signed, so Bob cannot prove who sent it.

## Tests

`python -m unittest -v` runs 29 tests: the four "done when" checks (including a change to
every byte of the vault), the bonus, and full command-line sessions.
