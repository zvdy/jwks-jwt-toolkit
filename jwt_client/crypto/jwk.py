"""
JWK Module

This module handles JWK (JSON Web Key) operations according to RFC 7517.
It provides functionality for working with both RSA and EC keys.
"""

import base64
import json
import logging
from typing import Dict, Any, Tuple, Optional, Union
import uuid

from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger(__name__)

class JWKError(Exception):
    """Exception raised for JWK related errors."""
    pass


class JWK:
    """
    JSON Web Key (JWK) implementation as defined in RFC 7517.

    This class handles the creation, serialization, and conversion of
    JWKs for various key types.
    """

    @staticmethod
    def _b64_encode(data: bytes) -> str:
        """
        Base64url encode bytes without padding as specified in RFC 7515.

        Args:
            data (bytes): The data to encode

        Returns:
            str: Base64url encoded string without padding
        """
        return base64.urlsafe_b64encode(data).decode('ascii').rstrip('=')

    @staticmethod
    def _b64_decode(data: str) -> bytes:
        """
        Decode a base64url encoded string, handling missing padding.

        Args:
            data (str): Base64url encoded string

        Returns:
            bytes: Decoded bytes
        """
        # Add padding if necessary
        padding = len(data) % 4
        if padding:
            data += '=' * (4 - padding)
        return base64.urlsafe_b64decode(data)

    @staticmethod
    def from_rsa_key(private_key: rsa.RSAPrivateKey,
                     kid: Optional[str] = None,
                     use: str = "sig",
                     alg: str = "RS256") -> Dict[str, Any]:
        """
        Create a JWK from an RSA private key.

        Args:
            private_key (rsa.RSAPrivateKey): The RSA private key
            kid (Optional[str]): Key ID, generated if not provided
            use (str): Key usage, default 'sig' for signature
            alg (str): Algorithm, default 'RS256'

        Returns:
            Dict[str, Any]: JWK representation of the public key
        """
        if kid is None:
            kid = str(uuid.uuid4())

        public_key = private_key.public_key()
        public_numbers = public_key.public_numbers()

        # Get modulus (n) and exponent (e) for RSA key
        n_bytes = public_numbers.n.to_bytes(
            (public_numbers.n.bit_length() + 7) // 8, byteorder='big'
        )
        e_bytes = public_numbers.e.to_bytes(
            (public_numbers.e.bit_length() + 7) // 8, byteorder='big'
        )

        # Create the JWK
        jwk = {
            "kty": "RSA",
            "kid": kid,
            "use": use,
            "alg": alg,
            "n": JWK._b64_encode(n_bytes),
            "e": JWK._b64_encode(e_bytes),
        }

        logger.debug(f"Created RSA JWK with kid: {kid}")
        return jwk

    @staticmethod
    def from_ec_key(private_key: ec.EllipticCurvePrivateKey,
                    kid: Optional[str] = None,
                    use: str = "sig",
                    alg: Optional[str] = None) -> Dict[str, Any]:
        """
        Create a JWK from an EC private key.

        Args:
            private_key (ec.EllipticCurvePrivateKey): The EC private key
            kid (Optional[str]): Key ID, generated if not provided
            use (str): Key usage, default 'sig' for signature
            alg (Optional[str]): Algorithm, detected from curve if not provided

        Returns:
            Dict[str, Any]: JWK representation of the public key
        """
        if kid is None:
            kid = str(uuid.uuid4())

        public_key = private_key.public_key()
        public_numbers = public_key.public_numbers()
        curve_name = JWK._get_curve_name(public_key.curve)

        # Determine algorithm if not provided
        if alg is None:
            alg = {
                "P-256": "ES256",
                "P-384": "ES384",
                "P-521": "ES512"
            }.get(curve_name, "ES256")

        # Convert x and y coordinates to bytes
        x_bytes = public_numbers.x.to_bytes(
            (public_numbers.x.bit_length() + 7) // 8, byteorder='big'
        )
        y_bytes = public_numbers.y.to_bytes(
            (public_numbers.y.bit_length() + 7) // 8, byteorder='big'
        )

        # Create the JWK
        jwk = {
            "kty": "EC",
            "kid": kid,
            "use": use,
            "alg": alg,
            "crv": curve_name,
            "x": JWK._b64_encode(x_bytes),
            "y": JWK._b64_encode(y_bytes)
        }

        logger.debug(f"Created EC JWK with kid: {kid}, curve: {curve_name}")
        return jwk

    @staticmethod
    def _get_curve_name(curve: ec.EllipticCurve) -> str:
        """
        Get the JWA curve name for an elliptic curve.

        Args:
            curve (ec.EllipticCurve): The elliptic curve

        Returns:
            str: JWA curve name

        Raises:
            JWKError: If the curve is not supported
        """
        if isinstance(curve, ec.SECP256R1):
            return "P-256"
        elif isinstance(curve, ec.SECP384R1):
            return "P-384"
        elif isinstance(curve, ec.SECP521R1):
            return "P-521"
        else:
            raise JWKError(f"Unsupported elliptic curve: {curve}")

    @staticmethod
    def to_pem(jwk: Dict[str, Any]) -> bytes:
        """
        Convert a JWK to a PEM-encoded public key.

        Args:
            jwk (Dict[str, Any]): The JWK to convert

        Returns:
            bytes: PEM-encoded public key

        Raises:
            JWKError: If the key type is not supported or the JWK is invalid
        """
        kty = jwk.get("kty")

        if kty == "RSA":
            # Extract RSA parameters
            try:
                n = int.from_bytes(JWK._b64_decode(jwk["n"]), byteorder='big')
                e = int.from_bytes(JWK._b64_decode(jwk["e"]), byteorder='big')

                # Create public key
                public_numbers = rsa.RSAPublicNumbers(e=e, n=n)
                public_key = public_numbers.public_key()

                # Serialize to PEM
                pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                return pem
            except (KeyError, ValueError) as e:
                raise JWKError(f"Invalid RSA JWK: {str(e)}")

        elif kty == "EC":
            # Extract EC parameters
            try:
                x = int.from_bytes(JWK._b64_decode(jwk["x"]), byteorder='big')
                y = int.from_bytes(JWK._b64_decode(jwk["y"]), byteorder='big')

                # Get curve
                curve_name = jwk.get("crv")
                curve = {
                    "P-256": ec.SECP256R1(),
                    "P-384": ec.SECP384R1(),
                    "P-521": ec.SECP521R1()
                }.get(curve_name)

                if curve is None:
                    raise JWKError(f"Unsupported curve: {curve_name}")

                # Create public key
                public_numbers = ec.EllipticCurvePublicNumbers(x=x, y=y, curve=curve)
                public_key = public_numbers.public_key()

                # Serialize to PEM
                pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                return pem
            except (KeyError, ValueError) as e:
                raise JWKError(f"Invalid EC JWK: {str(e)}")

        else:
            raise JWKError(f"Unsupported key type: {kty}")

    @staticmethod
    def is_valid(jwk: Dict[str, Any]) -> bool:
        """
        Validate a JWK according to RFC 7517.

        Args:
            jwk (Dict[str, Any]): The JWK to validate

        Returns:
            bool: True if valid, False otherwise
        """
        # Check if it's a dictionary
        if not isinstance(jwk, dict):
            logger.debug("JWK is not a dictionary")
            return False

        # Check required fields
        if "kty" not in jwk:
            logger.debug("JWK missing 'kty' field")
            return False

        kty = jwk["kty"]

        # Check RSA key required parameters
        if kty == "RSA":
            required = ["n", "e"]
            for param in required:
                if param not in jwk:
                    logger.debug(f"RSA JWK missing '{param}' field")
                    return False

        # Check EC key required parameters
        elif kty == "EC":
            required = ["crv", "x", "y"]
            for param in required:
                if param not in jwk:
                    logger.debug(f"EC JWK missing '{param}' field")
                    return False

        # Check symmetric key required parameters
        elif kty == "oct":
            if "k" not in jwk:
                logger.debug("oct JWK missing 'k' field")
                return False

        else:
            logger.debug(f"Unsupported key type: {kty}")
            return False

        return True
