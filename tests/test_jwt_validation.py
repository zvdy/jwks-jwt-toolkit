"""
Tests for JWT validation.
"""

import unittest
import json
import jwt
import time
from unittest.mock import patch, MagicMock

from jwt_client.jwt.validator import JWTValidator
from jwt_client.crypto.jwk import JWK

class TestJWTValidation(unittest.TestCase):
    """Test cases for JWT validation."""

    def setUp(self):
        """Set up test environment."""
        # Sample RSA JWK for testing
        self.rsa_jwk = {
            "kty": "RSA",
            "kid": "test-key-1",
            "use": "sig",
            "alg": "RS256",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB"
        }

        self.jwks = {"keys": [self.rsa_jwk]}

        # Create validator with mock URL
        self.validator = JWTValidator("https://example.com/.well-known/jwks.json")

    @patch('requests.get')
    def test_get_jwks(self, mock_get):
        """Test fetching JWKS."""
        # Setup mock
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = self.jwks
        mock_get.return_value = mock_response

        # Test
        result = self.validator.get_jwks()

        # Verify
        self.assertEqual(result, self.jwks)
        mock_get.assert_called_once_with(self.validator.jwks_url)

    @patch('requests.get')
    def test_get_jwks_failure(self, mock_get):
        """Test JWKS fetch failure."""
        # Setup mock for HTTP error
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        # Test and verify
        with self.assertRaises(ValueError):
            self.validator.get_jwks()

    @patch('jwt_client.jwt.validator.JWTValidator.get_jwks')
    def test_find_key(self, mock_get_jwks):
        """Test finding a key by ID."""
        # Setup mock
        mock_get_jwks.return_value = self.jwks

        # Test
        result = self.validator.find_key(self.rsa_jwk["kid"])

        # Verify
        self.assertEqual(result, self.rsa_jwk)

        # Test key not found
        result = self.validator.find_key("non-existent-kid")
        self.assertIsNone(result)

    @patch('jwt_client.jwt.validator.JWTValidator.find_key')
    @patch('jwt_client.crypto.jwk.JWK.to_pem')
    @patch('jwt.decode')
    @patch('jwt.get_unverified_header')
    def test_validate_jwt(self, mock_header, mock_decode, mock_to_pem, mock_find_key):
        """Test JWT validation."""
        # Setup mocks
        mock_header.return_value = {"kid": self.rsa_jwk["kid"], "alg": "RS256"}
        mock_find_key.return_value = self.rsa_jwk
        mock_to_pem.return_value = b"MOCK_PEM"

        payload = {"sub": "test", "exp": time.time() + 3600}
        mock_decode.return_value = payload

        # Test
        valid, result = self.validator.validate_jwt("test.token.here")

        # Verify
        self.assertTrue(valid)
        self.assertEqual(result, payload)
        mock_header.assert_called_once()
        mock_find_key.assert_called_once_with(self.rsa_jwk["kid"])
        mock_to_pem.assert_called_once()
        mock_decode.assert_called_once()

    @patch('jwt.get_unverified_header')
    def test_validate_jwt_missing_kid(self, mock_header):
        """Test JWT validation with missing kid."""
        # Setup mock
        mock_header.return_value = {"alg": "RS256"}  # No kid

        # Test
        valid, error = self.validator.validate_jwt("test.token.here")

        # Verify
        self.assertFalse(valid)
        self.assertIn("no kid", error.lower())

    @patch('jwt.get_unverified_header')
    @patch('jwt_client.jwt.validator.JWTValidator.find_key')
    def test_validate_jwt_key_not_found(self, mock_find_key, mock_header):
        """Test JWT validation with key not found."""
        # Setup mocks
        mock_header.return_value = {"kid": "non-existent-kid", "alg": "RS256"}
        mock_find_key.return_value = None  # Key not found

        # Test
        valid, error = self.validator.validate_jwt("test.token.here")

        # Verify
        self.assertFalse(valid)
        self.assertIn("no matching key found", error.lower())

if __name__ == "__main__":
    unittest.main()
