"""Strong passwords from the operating system's secure random source (secrets, not random)."""

import math
import secrets
import string

# 26 + 26 + 10 + 32 = 94 printable ASCII characters.
CLASSES = (string.ascii_lowercase, string.ascii_uppercase, string.digits, string.punctuation)
ALPHABET = "".join(CLASSES)
MIN_LENGTH, DEFAULT_LENGTH, MAX_LENGTH = 12, 20, 128


def generate(length: int = DEFAULT_LENGTH) -> str:
    """Pick every character with secrets.choice; retry until all four classes appear."""
    if not MIN_LENGTH <= length <= MAX_LENGTH:
        raise ValueError(f"Choose a length from {MIN_LENGTH} to {MAX_LENGTH}.")
    while True:
        password = "".join(secrets.choice(ALPHABET) for _ in range(length))
        if all(any(char in group for char in password) for group in CLASSES):
            return password


def entropy_bits(length: int) -> float:
    """Upper bound for a uniformly random password of this length over ALPHABET."""
    return length * math.log2(len(ALPHABET))
