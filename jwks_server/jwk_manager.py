"""
JWK Manager Module

Handles JWK storage, retrieval, and validation according to RFC 7517.
"""

import json
import os
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple, Union

from jwks_server.config import active_config as config

logger = logging.getLogger(__name__)

class JWKManager:
    """
    JSON Web Key Manager

    This class handles the storage, retrieval, and validation of JWKs
    according to RFC 7517 specifications.
    """

    def __init__(self):
        """Initialize the JWK Manager."""
        self._ensure_jwks_directory()
        self._ensure_jwks_file()

    def _ensure_jwks_directory(self) -> None:
        """Ensure the JWKS storage directory exists."""
        try:
            os.makedirs(config.JWKS_FOLDER, exist_ok=True)
            logger.info(f"JWKS directory created or exists at {config.JWKS_FOLDER}")
        except Exception as e:
            logger.error(f"Failed to create JWKS directory: {str(e)}")
            raise

    def _ensure_jwks_file(self) -> None:
        """Ensure the JWKS file exists, creating it with an empty keyset if needed."""
        if not os.path.exists(config.JWKS_FILE):
            try:
                with open(config.JWKS_FILE, 'w') as f:
                    json.dump({"keys": []}, f)
                logger.info(f"Created empty JWKS file at {config.JWKS_FILE}")
            except Exception as e:
                logger.error(f"Failed to create JWKS file: {str(e)}")
                raise

    def get_jwks(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Get the current JWK Set.

        Returns:
            Dict[str, List[Dict[str, Any]]]: The current JWKS

        Raises:
            IOError: If the file cannot be read
            json.JSONDecodeError: If the file contains invalid JSON
        """
        try:
            with open(config.JWKS_FILE, 'r') as f:
                jwks = json.load(f)
            logger.debug("JWKS retrieved successfully")
            return jwks
        except (IOError, json.JSONDecodeError) as e:
            logger.error(f"Failed to read JWKS: {str(e)}")
            raise

    def save_jwks(self, jwks: Dict[str, List[Dict[str, Any]]]) -> bool:
        """
        Save a JWK Set to storage.

        Args:
            jwks (Dict[str, List[Dict[str, Any]]]): The JWKS to save

        Returns:
            bool: True if successful, False otherwise

        Raises:
            ValueError: If the JWKS is invalid
        """
        # Validate the JWKS
        if not self.is_valid_jwks(jwks):
            logger.error("Invalid JWKS format")
            raise ValueError("Invalid JWKS format")

        try:
            # Save the JWKS
            with open(config.JWKS_FILE, 'w') as f:
                json.dump(jwks, f)

            # Create backup if enabled
            if config.ENABLE_BACKUPS:
                self._create_backup(jwks)

            logger.info(f"JWKS saved successfully with {len(jwks.get('keys', []))} keys")
            return True
        except Exception as e:
            logger.error(f"Failed to save JWKS: {str(e)}")
            return False

    def _create_backup(self, jwks: Dict[str, List[Dict[str, Any]]]) -> None:
        """
        Create a backup of the JWKS.

        Args:
            jwks (Dict[str, List[Dict[str, Any]]]): The JWKS to backup
        """
        try:
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            backup_file = os.path.join(config.JWKS_FOLDER, f"jwks_{timestamp}.json")
            with open(backup_file, 'w') as f:
                json.dump(jwks, f)
            logger.info(f"JWKS backup created at {backup_file}")
        except Exception as e:
            logger.warning(f"Failed to create JWKS backup: {str(e)}")

    def get_key_by_id(self, kid: str) -> Optional[Dict[str, Any]]:
        """
        Get a JWK by its Key ID.

        Args:
            kid (str): The Key ID to look for

        Returns:
            Optional[Dict[str, Any]]: The JWK if found, None otherwise
        """
        try:
            jwks = self.get_jwks()
            for key in jwks.get("keys", []):
                if key.get("kid") == kid:
                    return key
            return None
        except Exception as e:
            logger.error(f"Error retrieving key {kid}: {str(e)}")
            return None

    def add_key(self, jwk: Dict[str, Any]) -> bool:
        """
        Add a key to the JWKS.

        Args:
            jwk (Dict[str, Any]): The JWK to add

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if not self.is_valid_jwk(jwk):
                logger.error("Invalid JWK format")
                return False

            jwks = self.get_jwks()
            keys = jwks.get("keys", [])

            # Check if key with same ID already exists
            for i, key in enumerate(keys):
                if key.get("kid") == jwk.get("kid"):
                    # Replace existing key
                    keys[i] = jwk
                    jwks["keys"] = keys
                    return self.save_jwks(jwks)

            # Add new key
            keys.append(jwk)
            jwks["keys"] = keys
            return self.save_jwks(jwks)
        except Exception as e:
            logger.error(f"Failed to add key: {str(e)}")
            return False

    def list_keys(self) -> List[Dict[str, str]]:
        """
        List all keys with their basic information.

        Returns:
            List[Dict[str, str]]: List of key information dictionaries
        """
        try:
            jwks = self.get_jwks()
            keys_info = []
            for key in jwks.get("keys", []):
                keys_info.append({
                    "kid": key.get("kid", "Unknown"),
                    "kty": key.get("kty", "Unknown"),
                    "alg": key.get("alg", "Unknown"),
                    "use": key.get("use", "Unknown")
                })
            return keys_info
        except Exception as e:
            logger.error(f"Failed to list keys: {str(e)}")
            return []

    @staticmethod
    def is_valid_jwk(jwk: Dict[str, Any]) -> bool:
        """
        Validate a JWK according to RFC 7517.

        Args:
            jwk (Dict[str, Any]): The JWK to validate

        Returns:
            bool: True if valid, False otherwise
        """
        # Check if it's a dictionary
        if not isinstance(jwk, dict):
            return False

        # Check required fields based on key type
        if "kty" not in jwk:
            return False

        kty = jwk["kty"]

        # Check RSA key required parameters
        if kty == "RSA":
            required_params = ["n", "e"]
            for param in required_params:
                if param not in jwk:
                    logger.debug(f"Missing required RSA param: {param}")
                    return False

        # Check EC key required parameters
        elif kty == "EC":
            required_params = ["crv", "x", "y"]
            for param in required_params:
                if param not in jwk:
                    logger.debug(f"Missing required EC param: {param}")
                    return False

        # Check symmetric key required parameters
        elif kty == "oct":
            if "k" not in jwk:
                logger.debug("Missing required oct param: k")
                return False

        # Check for recommended parameters
        if "kid" not in jwk:
            logger.warning("JWK is missing recommended 'kid' parameter")

        return True

    @staticmethod
    def is_valid_jwks(jwks: Dict[str, List[Dict[str, Any]]]) -> bool:
        """
        Validate a JWKS according to RFC 7517.

        Args:
            jwks (Dict[str, List[Dict[str, Any]]]): The JWKS to validate

        Returns:
            bool: True if valid, False otherwise
        """
        # Check if it's a dictionary
        if not isinstance(jwks, dict):
            logger.debug("JWKS is not a dictionary")
            return False

        # Check if it has a "keys" property that's a list
        if "keys" not in jwks or not isinstance(jwks["keys"], list):
            logger.debug("JWKS missing 'keys' list")
            return False

        # Check that each key is valid
        for key in jwks["keys"]:
            if not JWKManager.is_valid_jwk(key):
                logger.debug(f"Invalid key in JWKS: {key.get('kid', 'unknown')}")
                return False

        return True

# Create a singleton instance
jwk_manager = JWKManager()
