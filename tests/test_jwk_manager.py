"""
Tests for the JWK Manager.
"""

import unittest
import os
import json
import tempfile
import shutil

# Set test environment before imports
os.environ["JWKS_ENV"] = "testing"

from jwks_server.jwk_manager import JWKManager

class TestJWKManager(unittest.TestCase):
    """Test cases for JWKManager class."""

    def setUp(self):
        """Set up test environment."""
        self.test_dir = tempfile.mkdtemp()
        self.manager = JWKManager()

        # Sample JWKs for testing
        self.valid_rsa_jwk = {
            "kty": "RSA",
            "kid": "test-key-1",
            "use": "sig",
            "alg": "RS256",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB"
        }

        self.valid_ec_jwk = {
            "kty": "EC",
            "kid": "test-key-2",
            "use": "sig",
            "alg": "ES256",
            "crv": "P-256",
            "x": "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
            "y": "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps"
        }

        self.invalid_jwk = {
            "kty": "RSA",
            # Missing required fields
            "kid": "test-invalid"
        }

    def tearDown(self):
        """Clean up after tests."""
        shutil.rmtree(self.test_dir)

    def test_is_valid_jwk_rsa(self):
        """Test RSA JWK validation."""
        self.assertTrue(self.manager.is_valid_jwk(self.valid_rsa_jwk))

    def test_is_valid_jwk_ec(self):
        """Test EC JWK validation."""
        self.assertTrue(self.manager.is_valid_jwk(self.valid_ec_jwk))

    def test_is_valid_jwk_invalid(self):
        """Test invalid JWK validation."""
        self.assertFalse(self.manager.is_valid_jwk(self.invalid_jwk))

    def test_is_valid_jwks(self):
        """Test JWKS validation."""
        # Valid JWKS
        valid_jwks = {"keys": [self.valid_rsa_jwk, self.valid_ec_jwk]}
        self.assertTrue(self.manager.is_valid_jwks(valid_jwks))

        # Invalid JWKS (contains invalid key)
        invalid_jwks = {"keys": [self.valid_rsa_jwk, self.invalid_jwk]}
        self.assertFalse(self.manager.is_valid_jwks(invalid_jwks))

        # Not a JWKS (missing keys property)
        not_jwks = {"not_keys": []}
        self.assertFalse(self.manager.is_valid_jwks(not_jwks))

    def test_add_key(self):
        """Test adding a key to the JWKS."""
        # Add a key
        result = self.manager.add_key(self.valid_rsa_jwk)
        self.assertTrue(result)

        # Verify key was added
        retrieved = self.manager.get_key_by_id(self.valid_rsa_jwk["kid"])
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved["kid"], self.valid_rsa_jwk["kid"])

    def test_list_keys(self):
        """Test listing keys."""
        # Add keys
        self.manager.add_key(self.valid_rsa_jwk)
        self.manager.add_key(self.valid_ec_jwk)

        # List keys
        keys = self.manager.list_keys()
        self.assertEqual(len(keys), 2)

        # Check key info
        key_ids = [k["kid"] for k in keys]
        self.assertIn(self.valid_rsa_jwk["kid"], key_ids)
        self.assertIn(self.valid_ec_jwk["kid"], key_ids)

if __name__ == "__main__":
    unittest.main()
