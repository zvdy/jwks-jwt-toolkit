"""
JWT Validator Module

This module provides functionality for validating JWTs against a JWKS.
"""

import logging
import requests
from typing import Dict, Any, Tuple, Optional, List, Union
import jwt

from jwt_client.crypto.jwk import JWK

logger = logging.getLogger(__name__)

class JWTValidator:
    """
    JWT Validator

    This class provides methods to validate JWTs against a JWKS endpoint
    according to RFC 7519 and RFC 7517.
    """

    def __init__(self, jwks_url: str):
        """
        Initialize the validator with a JWKS URL.

        Args:
            jwks_url (str): URL of the JWKS endpoint
        """
        self.jwks_url = jwks_url
        logger.debug(f"Initialized JWT validator with JWKS URL: {jwks_url}")

    def get_jwks(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Fetch the JWKS from the configured endpoint.

        Returns:
            Dict[str, List[Dict[str, Any]]]: The JWKS

        Raises:
            ValueError: If the JWKS cannot be fetched or is invalid
        """
        try:
            logger.info(f"Fetching JWKS from {self.jwks_url}")
            response = requests.get(self.jwks_url)

            if response.status_code != 200:
                logger.error(f"Failed to fetch JWKS: HTTP {response.status_code}")
                raise ValueError(f"Failed to fetch JWKS: HTTP {response.status_code}")

            jwks = response.json()

            # Basic validation
            if not isinstance(jwks, dict) or "keys" not in jwks or not isinstance(jwks["keys"], list):
                logger.error("Invalid JWKS format")
                raise ValueError("Invalid JWKS format")

            return jwks
        except requests.RequestException as e:
            logger.error(f"Request error: {str(e)}")
            raise ValueError(f"JWKS request failed: {str(e)}")
        except Exception as e:
            logger.error(f"Error fetching JWKS: {str(e)}")
            raise ValueError(f"Error fetching JWKS: {str(e)}")

    def find_key(self, kid: str) -> Optional[Dict[str, Any]]:
        """
        Find a key in the JWKS by its ID.

        Args:
            kid (str): Key ID to find

        Returns:
            Optional[Dict[str, Any]]: The JWK if found, None otherwise
        """
        try:
            jwks = self.get_jwks()

            for key in jwks.get("keys", []):
                if key.get("kid") == kid:
                    logger.debug(f"Found key with ID: {kid}")
                    return key

            logger.warning(f"No key found with ID: {kid}")
            return None
        except Exception as e:
            logger.error(f"Error finding key: {str(e)}")
            return None

    def validate_jwt(self, token: str, options: Optional[Dict[str, Any]] = None) -> Tuple[bool, Union[Dict[str, Any], str]]:
        """
        Validate a JWT against the JWKS.

        Args:
            token (str): The JWT to validate
            options (Optional[Dict[str, Any]]): JWT decode options

        Returns:
            Tuple[bool, Union[Dict[str, Any], str]]:
                (True, payload) if valid, (False, error_message) otherwise
        """
        try:
            # Default options for validation
            if options is None:
                options = {
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iat": True,
                    "verify_aud": False
                }

            # Get the unverified header to extract kid
            header = jwt.get_unverified_header(token)
            kid = header.get("kid")

            if not kid:
                logger.warning("JWT has no kid in header")
                return False, "JWT has no kid in header"

            # Find the key in JWKS
            jwk = self.find_key(kid)
            if not jwk:
                logger.warning(f"No matching key found for kid: {kid}")
                return False, f"No matching key found for kid: {kid}"

            # Convert JWK to PEM
            try:
                pem = JWK.to_pem(jwk)
            except Exception as e:
                logger.error(f"Failed to convert JWK to PEM: {str(e)}")
                return False, f"Failed to convert JWK to PEM: {str(e)}"

            # Verify the token
            alg = jwk.get("alg") or header.get("alg")
            if not alg:
                logger.warning("No algorithm specified in JWK or JWT header")
                return False, "No algorithm specified"

            payload = jwt.decode(
                token,
                pem,
                algorithms=[alg],
                options=options
            )

            logger.info(f"JWT validation successful for kid: {kid}")
            return True, payload

        except jwt.ExpiredSignatureError:
            logger.warning("JWT has expired")
            return False, "Token has expired"
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token: {str(e)}")
            return False, f"Invalid token: {str(e)}"
        except Exception as e:
            logger.error(f"JWT validation error: {str(e)}")
            return False, f"Validation error: {str(e)}"
