# Password manager — Computer Security, Project 2

**Group:** HAOJIE SONG (2023905496), ZIQIAN YU (2023902046), ANGRAN YU (2023900899)

A command-line password manager in Python. All entries live in one encrypted file,
`vault.json`. Only the master password, which is never stored, opens it.

| Graded part | Where to find it |
|---|---|
| The four required blocks work | [The four building blocks](#the-four-building-blocks) · [Check it yourself](#check-it-yourself) |
| README justifies every choice | [Why each choice is correct](#why-each-choice-is-correct), questions 1–4 |
| Security model stated honestly | [Security model](#security-model), question 5 |
| Code quality + a bonus attempted | [Bonus A](#bonus-a--share-one-entry-with-a-teammate) · [Code](#code) |

## Usage

Tested with Python 3.12. `requirements.txt` asks for `cryptography` 44 or newer, the first
version with Argon2id.

```
python -m pip install -r requirements.txt

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
   a typed password against it.<br>
   **Done when:** the vault stores only `$argon2id$v=19$m=65536,t=3,p=4$...`; a wrong master
   password is rejected.
2. **Key derived from the master password** — library: `cryptography` (`Argon2id` key
   derivation). It turns the master password and a separate random salt into the 32-byte
   AES key, which exists only in memory.<br>
   **Done when:** there is no key file. The vault is one file, `vault.json`, and the key is never
   written to disk.
3. **Vault encrypted with AES-GCM** — library: `cryptography` (`AESGCM`). Every save uses a
   new random 12-byte nonce, and the file header is authenticated together with the entries.<br>
   **Done when:** changing any byte of `vault.json` makes the command fail, for example with
   `error: The vault file was modified or damaged. Nothing was decrypted.`
4. **Strong password generator** — Python's `secrets` module. Each character is
   `secrets.choice` from 94 letters, digits and symbols, and every password has all four kinds.<br>
   **Done when:** passwords are long (the user picks 12 to 128 characters, default 20: about 131
   bits), random, and use a wide character set.

These are the libraries the course rule names. They are maintained and widely reviewed:
`argon2-cffi` wraps the reference Argon2 implementation, and `cryptography` uses OpenSSL for
AES. We only combine them; no cryptography is written by hand.

**What is on disk** — `vault.json` (shortened). It holds no key:

```json
{
  "format": "pwvault-1",
  "master_hash": "$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>",
  "kdf": {"algorithm": "argon2id", "salt": "<a second salt>",
          "time_cost": 3, "memory_cost": 65536, "parallelism": 4},
  "cipher": {"algorithm": "AES-256-GCM", "nonce": "<new for each save>"},
  "ciphertext": "<the entries, encrypted, with the 16-byte GCM tag>"
}
```

## Check it yourself

The four "done when" checks by hand, in the repository folder:

```
python vault.py init               # type a master password twice
grep master_hash vault.json        # "$argon2id$v=19$m=65536,t=3,p=4$..."
ls                                 # the code and vault.json: no key file
python vault.py list               # type a wrong master password: it is rejected

# change one byte near the end of vault.json, then open the vault again
python -c "p='vault.json';b=bytearray(open(p,'rb').read());b[-20]^=1;open(p,'wb').write(b)"
python vault.py list               # error: The vault file was modified or damaged. ...
python vault.py gen --length 32
```

`python -m unittest -v` runs 29 tests: the four "done when" checks (including a change to
every byte of the vault), the bonus, and full command-line sessions.

## Why each choice is correct

### 1. Why Argon2 for the master password, and not SHA-256 or AES?

The master password should never be recoverable, so AES is the wrong tool. AES is two-way: anyone
who has the key can decrypt the password back, and the key has to be stored somewhere, so it can be
stolen together with the database. SHA-256 is one-way, which is better, but the same password always
gives the same hash, so common passwords can be looked up at once in a rainbow table. It is also
very fast. In our Class 5 lab we could try about 3.5 million MD5 guesses per second, and SHA-256 is
the same kind of fast hash, so even with a salt an attacker can guess very quickly.

Argon2 fixes both problems. It adds a random salt, so the same password gives a different hash
every time and a table computed in advance is useless. It is also slow and uses a lot of memory on
purpose (3 passes over 64 MiB in our tool), so every guess costs the attacker much more time and
memory. In the same lab, Argon2 only managed about 10 guesses per second.

### 2. Why derive the encryption key from the master password instead of storing a key file?

If the key sits in a file next to the vault, whoever steals the vault gets the key too. Then they
don't have to guess anything. The key opens the vault straight away and keeps working, so all our
passwords are transparent to them and can be read again and again.

When the key is derived from the master password, nothing on the disk can open the vault. The only
secret is the password in the user's head, so the attacker has to guess it, and every guess costs a
full Argon2 run. We use a different salt for the key than for the stored hash, because with the same
salt the stored hash would be exactly the key. The price is that a forgotten master password cannot
be recovered, and the vault can never be opened again.

### 3. Why AES-GCM and not AES without authentication? What does the "GCM" part buy you?

AES without authentication only keeps the data secret. It does not notice if someone changes it: a
modified ciphertext still decrypts with no error and just gives a different plaintext, so a stored
password could be changed and we would never know.

GCM adds a 16-byte tag that is computed with the key. Someone who edits the vault file cannot make a
matching tag without the key, and the tag is checked every time we decrypt. If it does not match,
decryption stops and we get nothing back instead of wrong data. We also put the file header (the
salts, the nonce and `master_hash`) into the tag as associated data, so a change to the header is
caught as well. In our tests, changing any single byte of `vault.json` makes the vault refuse to
open. GCM also needs a new nonce for every save, which we do. With the same key and the same nonce,
the XOR of two ciphertexts is the XOR of the two plaintexts, and that leaks information.

### 4. Why `secrets` and not `random` for generating passwords?

`random` is predictable. It uses the Mersenne Twister, which is deterministic: after seeing 624 of
its 32-bit outputs, an attacker can rebuild its internal state and predict every value that comes
next, including our next password. The Python documentation itself says not to use it for security.
`secrets` takes its randomness from the operating system's secure source (`os.urandom`), so seeing
earlier passwords tells you nothing about the next one.

How strong a random password is depends on its length and on how many characters it can use:
length × log2(number of characters). We pick every character with `secrets.choice` out of 94
letters, digits and symbols, which is about 6.6 bits per character, so the default 20 characters
give about 131 bits. The user can choose any length from 12 to 128.

## Security model

### 5. What your tool does not protect against

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

## Code

| File | What it does | The crypto lines |
|---|---|---|
| [`vault.py`](vault.py) | the command line; secrets are typed without echo (`getpass`) | — |
| [`vault_store.py`](vault_store.py) | the vault file | [hash](vault_store.py#L171-L178) · [verify](vault_store.py#L196) · [derive the key](vault_store.py#L73-L77) · [decrypt](vault_store.py#L204) · [encrypt](vault_store.py#L209-L216) |
| [`password_gen.py`](password_gen.py) | the password generator | [`secrets.choice`](password_gen.py#L13-L20) |
| [`share.py`](share.py) | Bonus A | [seal](share.py#L60-L75) · [open](share.py#L78-L106) |
| [`tests/`](tests) | the 29 tests | — |
