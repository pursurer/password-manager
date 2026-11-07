#!/usr/bin/env python3
"""Command-line password manager (Computer Security, Project 2).

Every command that reads or changes the vault asks for the master password.
Secrets are read without echo on a terminal, or one per line from standard input.
"""

import argparse
import getpass
import json
import os
import re
import sys
from pathlib import Path

import password_gen
import share
from vault_store import MIN_MASTER_LENGTH, Vault, VaultError


def read_secret(prompt: str) -> str:
    if sys.stdin.isatty():
        try:
            return getpass.getpass(prompt)
        except EOFError:
            raise VaultError("No input.") from None
    line = sys.stdin.readline()
    if not line:
        raise VaultError("Expected a secret on standard input.")
    return line.rstrip("\r\n")


def read_new_secret(prompt: str) -> str:
    first = read_secret(prompt)
    if read_secret("Repeat: ") != first:
        raise VaultError("The two entries do not match.")
    return first


def unlock(args) -> Vault:
    if not args.vault.exists():
        raise VaultError(f"No vault at {args.vault}. Run 'init' first.")
    return Vault.open(args.vault, read_secret("Master password: "))


def cmd_init(args):
    if args.vault.exists():
        raise VaultError(f"A vault already exists at {args.vault}.")
    Vault.create(args.vault, read_new_secret("New master password: "))
    print(f"Created {args.vault}. There is no key file: only your master password opens it.")


def cmd_add(args):
    if args.length is not None and not args.generate:
        raise VaultError("--length only works together with --generate.")
    # Generate first, so a bad length fails before the slow unlock.
    length = password_gen.DEFAULT_LENGTH if args.length is None else args.length
    password = password_gen.generate(length) if args.generate else None
    vault = unlock(args)
    if args.site in vault.entries:
        raise VaultError(f"'{args.site}' already exists. Delete it first to replace it.")
    if password is None:
        password = read_new_secret(f"Password for {args.site}: ")
    vault.add(args.site, args.user, password)
    vault.save()
    print(f"Added {args.site}.")
    if args.generate:
        print(f"Generated password: {password}")


def cmd_list(args):
    vault = unlock(args)
    if not vault.entries:
        print("The vault is empty.")
    for site in sorted(vault.entries):
        print(f"{site}\t{vault.entries[site]['username']}")


def cmd_get(args):
    entry = unlock(args).get(args.site)
    print(f"site:     {args.site}\nusername: {entry['username']}\npassword: {entry['password']}")


def cmd_delete(args):
    vault = unlock(args)
    vault.delete(args.site)
    vault.save()
    print(f"Deleted {args.site}.")


def cmd_gen(args):
    print(password_gen.generate(args.length))
    bits = password_gen.entropy_bits(args.length)
    print(f"(about {bits:.0f} bits of randomness)", file=sys.stderr)


def cmd_keygen(args):
    passphrase = read_new_secret("Passphrase for the new private key: ")
    if len(passphrase) < MIN_MASTER_LENGTH:
        raise VaultError(f"Use a passphrase of at least {MIN_MASTER_LENGTH} characters.")
    private_path, public_path, key_fingerprint = share.create_keypair(args.name, passphrase)
    print(f"Private key: {private_path} (keep it; encrypted with your passphrase)")
    print(f"Public key:  {public_path} (give this one to your teammates)")
    print(f"Fingerprint: {key_fingerprint}")


def cmd_share(args):
    out = Path(args.out or re.sub(r"[^A-Za-z0-9._-]", "_", args.site).lstrip(".") + ".share.json")
    if out.exists():
        raise VaultError(f"{out} already exists. Choose another file with --out.")
    entry = unlock(args).get(args.site)
    sealed = share.seal(args.site, entry, args.to)
    share.write_new(out, (json.dumps(sealed, indent=2) + "\n").encode("utf-8"), 0o644)
    print(f"Wrote {out}. Only the private key that matches {args.to} can open it.")


def cmd_receive(args):
    entry = share.open_share(Path(args.file).read_bytes(), args.key,
                             read_secret("Private key passphrase: "))
    if args.save:
        vault = unlock(args)
        vault.add(entry["site"], entry["username"], entry["password"])
        vault.save()
        print(f"Saved {entry['site']} in {args.vault}.")
    else:
        print(f"site:     {entry['site']}\nusername: {entry['username']}\n"
              f"password: {entry['password']}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    default_vault = Path(os.environ.get("VAULT_FILE", "vault.json"))
    parser.add_argument("--vault", type=Path, default=default_vault,
                        help="vault file (default: $VAULT_FILE or vault.json)")
    commands = parser.add_subparsers(dest="command", required=True)

    init = commands.add_parser("init", help="set the master password and create an empty vault")
    init.set_defaults(func=cmd_init)

    add = commands.add_parser("add", help="add an entry")
    add.add_argument("site")
    add.add_argument("--user", required=True)
    add.add_argument("--generate", action="store_true",
                     help="generate the password instead of typing it")
    add.add_argument("--length", type=int,
                     help=f"with --generate (default {password_gen.DEFAULT_LENGTH})")
    add.set_defaults(func=cmd_add)

    commands.add_parser("list", help="list sites and usernames").set_defaults(func=cmd_list)

    for name, func, text in (("get", cmd_get, "show one entry"),
                             ("delete", cmd_delete, "delete one entry")):
        command = commands.add_parser(name, help=text)
        command.add_argument("site")
        command.set_defaults(func=func)

    gen = commands.add_parser("gen", help="generate a strong password (no vault needed)")
    gen.add_argument("--length", type=int, default=password_gen.DEFAULT_LENGTH)
    gen.set_defaults(func=cmd_gen)

    keygen = commands.add_parser(
        "keygen", help="bonus A: create an RSA key pair NAME.key.pem / NAME.pub.pem")
    keygen.add_argument("name")
    keygen.set_defaults(func=cmd_keygen)

    share_cmd = commands.add_parser(
        "share", help="bonus A: encrypt one entry for a teammate's public key")
    share_cmd.add_argument("site")
    share_cmd.add_argument("--to", required=True, help="the teammate's NAME.pub.pem")
    share_cmd.add_argument("--out", help="output file (default: SITE.share.json)")
    share_cmd.set_defaults(func=cmd_share)

    receive = commands.add_parser("receive", help="bonus A: open a share with your private key")
    receive.add_argument("file")
    receive.add_argument("--key", required=True, help="your NAME.key.pem")
    receive.add_argument("--save", action="store_true", help="also store the entry in your vault")
    receive.set_defaults(func=cmd_receive)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        args.func(args)
    except (VaultError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print(file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
