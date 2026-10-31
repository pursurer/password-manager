"""Block 4: strong passwords from secrets."""

import string
import unittest
from unittest import mock

import password_gen


class PasswordGenTests(unittest.TestCase):
    def test_length_and_character_classes(self):
        for length in (12, 20, 64, 128):
            password = password_gen.generate(length)
            self.assertEqual(length, len(password))
            self.assertTrue(set(password) <= set(password_gen.ALPHABET))
            for group in (string.ascii_lowercase, string.ascii_uppercase,
                          string.digits, string.punctuation):
                self.assertTrue(set(password) & set(group))

    def test_lengths_outside_the_range_are_refused(self):
        for length in (0, 11, 129):
            with self.assertRaises(ValueError):
                password_gen.generate(length)

    def test_every_character_comes_from_secrets(self):
        with mock.patch("password_gen.secrets.choice", wraps=password_gen.secrets.choice) as choice:
            password = password_gen.generate(20)
        self.assertGreaterEqual(choice.call_count, len(password))

    def test_passwords_do_not_repeat(self):
        self.assertEqual(1000, len({password_gen.generate() for _ in range(1000)}))

    def test_alphabet_and_entropy(self):
        self.assertEqual(94, len(password_gen.ALPHABET))
        self.assertGreater(password_gen.entropy_bits(20), 128)


if __name__ == "__main__":
    unittest.main(verbosity=2)
