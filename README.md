# Password manager — Computer Security, Project 2

**Student:** HAOJIE SONG (2023905496)

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
AES is encryption, so the password could be decrypted again, and the AES key would have to be
stored somewhere. The master password must never be recoverable, so it needs a one-way hash.
SHA-256 is one-way but very fast, which helps an attacker: in the Class 5 lab we measured about
3.5 million MD5 guesses per second against about 10 Argon2id guesses per second. Argon2 is slow
on purpose and needs 64 MiB per guess, so GPUs gain little, and its random salt makes equal
passwords hash differently.

**2. Why derive the key from the master password instead of storing a key file?**
A key file next to the vault is stolen together with it (a backup, a synced folder, a lost
laptop), and then the vault opens without any password. With a derived key, the only secret is
the master password in the user's head, and every guess costs one Argon2 run. The key uses a
different salt from the stored hash: with the same salt the stored hash would be the key itself.
The cost is that a forgotten master password cannot be recovered.

**3. Why AES-GCM and not AES without authentication? What does GCM buy you?**
AES alone only hides the data. A changed ciphertext still decrypts, into garbage or, in CTR
mode, into exactly the bits the attacker flipped, and the program would accept it. GCM adds an
authentication tag: on decrypt, any change to the ciphertext, the nonce or the header makes it
fail instead of returning data. Our tests change every byte of a vault file and every one is
rejected. GCM needs a new nonce for each encryption with the same key, so every save makes one.

**4. Why `secrets` and not `random`?**
`random` is the Mersenne Twister, a generator for simulations: after 624 outputs its state can
be rebuilt and every next value predicted. `secrets` uses the operating system's
cryptographically secure source, so one password says nothing about the next. 20 characters
from 94 symbols give about 131 bits.

## Security model (question 5)

**Protects:** the stored passwords if someone steals `vault.json`. The file holds only AES-GCM
ciphertext and an Argon2 hash; the master password never touches the disk; each guess costs an
Argon2 run; any change to the file is detected.

**Does not protect against:**
- a keylogger or other malware on the user's machine (it reads the master password, or the key
  and entries in memory while a command runs);
- a weak master password (Argon2 slows guessing, but a dictionary word is still found);
- someone reading the screen (`get` prints the password);
- the vault being replaced by an older copy, or deleted;
- a forgotten master password (no recovery).

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
