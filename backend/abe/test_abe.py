
import base64
import os
import unittest

# Set the test secret before importing the encryption engine.
os.environ["ABE_MASTER_SECRET"] = (
    "test-master-secret-for-cpabe-32-bytes"
)

from cryptography.exceptions import InvalidTag
from abe_cipher import CpAbeCipherEngine
from policy_builder import CpAbePolicyBuilder


class TestCPABE(unittest.TestCase):

    def setUp(self):
        self.cipher = CpAbeCipherEngine()
        self.builder = CpAbePolicyBuilder()

        self.policy = self.builder.build_trip_document_policy(
            "TRIP_1001", "Driver"
        )

        self.data = b"CONFIDENTIAL_BILL_OF_LADING"

        self.attrs = {
            "Role: Driver",
            "TripID: TRIP_1001"
        }

    def test_authorized_decryption(self):
        encrypted = self.cipher.encrypt_document(
            self.data, self.policy
        )

        result = self.cipher.decrypt_document(
            encrypted["ciphertext_b64"],
            self.policy,
            self.attrs
        )

        self.assertEqual(result, self.data)

    def test_unauthorized_decryption_rejection(self):
        encrypted = self.cipher.encrypt_document(
            self.data, self.policy
        )

        unauthorized_attrs = {
            "Role: Driver",
            "TripID: TRIP_9999"
        }

        with self.assertRaises(PermissionError):
            self.cipher.decrypt_document(
                encrypted["ciphertext_b64"],
                self.policy,
                unauthorized_attrs
            )

    def test_same_plaintext_gets_distinct_ciphertexts(self):
        first = self.cipher.encrypt_document(
            self.data, self.policy
        )

        second = self.cipher.encrypt_document(
            self.data, self.policy
        )

        self.assertNotEqual(
            first["ciphertext_b64"],
            second["ciphertext_b64"]
        )

        self.assertEqual(
            self.cipher.decrypt_document(
                first["ciphertext_b64"],
                self.policy,
                self.attrs
            ),
            self.data
        )

        self.assertEqual(
            self.cipher.decrypt_document(
                second["ciphertext_b64"],
                self.policy,
                self.attrs
            ),
            self.data
        )

    def test_ciphertext_tampering_is_rejected(self):
        encrypted = self.cipher.encrypt_document(
            self.data, self.policy
        )

        payload = bytearray(
            base64.b64decode(
                encrypted["ciphertext_b64"],
                validate=True
            )
        )

        self.assertGreater(len(payload), 0)

        # Change the final byte.
        payload[-1] ^= 1

        tampered = base64.b64encode(payload).decode("ascii")

        with self.assertRaises(InvalidTag):
            self.cipher.decrypt_document(
                tampered,
                self.policy,
                self.attrs
            )

    def test_policy_is_authenticated_as_associated_data(self):
        encrypted = self.cipher.encrypt_document(
            self.data, self.policy
        )

        altered_policy = self.builder.build_trip_document_policy(
            "TRIP_1002", "Driver"
        )

        with self.assertRaises((InvalidTag, PermissionError)):
            self.cipher.decrypt_document(
                encrypted["ciphertext_b64"],
                altered_policy,
                self.attrs
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
