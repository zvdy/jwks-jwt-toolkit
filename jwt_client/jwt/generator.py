"""
JWT Generator Module

This module provides functionality for generating JWTs according to RFC 7519.
"""

import time
import json
import logging
from typing import Dict, Any, Optional, Union
import jwt

from cryptography.hazmat.primitives.asymmetric import rsa, ec
from jwt_client.crypto.keys import KeyGenerator

logger = logging.getLogger(__name__)

class JWTGenerator:
    """
    JSON Web Token Generator
    
    This class provides methods to create JWTs using various key types
    according to RFC 7519.
    """
    
    @staticmethod
    def generate_jwt(private_key_pem: bytes, 
                     kid: str, 
                     payload: Optional[Dict[str, Any]] = None,
                     algorithm: Optional[str] = None,
                     headers: Optional[Dict[str, Any]] = None) -> str:
        """
        Generate a JWT using the provided private key and parameters.
        
        Args:
            private_key_pem (bytes): Private key in PEM format
            kid (str): Key ID to include in the header
            payload (Optional[Dict[str, Any]]): JWT payload, default includes standard claims
            algorithm (Optional[str]): Algorithm to use, auto-detected if not provided
            headers (Optional[Dict[str, Any]]): Additional headers to include
            
        Returns:
            str: The generated JWT
            
        Raises:
            ValueError: If an invalid key or algorithm is provided
        """
        # Load the private key
        try:
            private_key = KeyGenerator.load_private_key(private_key_pem)
        except Exception as e:
            logger.error(f"Failed to load private key: {str(e)}")
            raise ValueError(f"Invalid private key: {str(e)}")
        
        # Determine algorithm if not provided
        if algorithm is None:
            try:
                algorithm = KeyGenerator.get_algorithm_for_key(private_key)
            except ValueError as e:
                logger.error(f"Failed to determine algorithm: {str(e)}")
                raise
        
        # Prepare default payload
        if payload is None:
            payload = {
                "iss": "jwt-client",
                "sub": "jwt-subject",
                "iat": int(time.time()),
                "exp": int(time.time()) + 3600,  # 1 hour expiration
                "jti": f"id-{int(time.time())}"
            }
        
        # Prepare headers
        jwt_headers = {"kid": kid}
        if headers:
            jwt_headers.update(headers)
        
        logger.info(f"Generating JWT with algorithm {algorithm} and kid {kid}")
        
        try:
            # Generate the JWT
            token = jwt.encode(
                payload,
                private_key_pem,  # PyJWT can handle PEM directly
                algorithm=algorithm,
                headers=jwt_headers
            )
            return token
        except Exception as e:
            logger.error(f"Failed to generate JWT: {str(e)}")
            raise ValueError(f"JWT generation failed: {str(e)}")
    
    @staticmethod
    def load_payload_from_file(file_path: str) -> Dict[str, Any]:
        """
        Load a JWT payload from a JSON file.
        
        Args:
            file_path (str): Path to the JSON file
            
        Returns:
            Dict[str, Any]: The loaded payload
            
        Raises:
            ValueError: If the file cannot be read or contains invalid JSON
        """
        try:
            with open(file_path, 'r') as f:
                payload = json.load(f)
            return payload
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in payload file: {str(e)}")
            raise ValueError(f"Invalid JSON in payload file: {str(e)}")
        except Exception as e:
            logger.error(f"Failed to read payload file: {str(e)}")
            raise ValueError(f"Failed to read payload file: {str(e)}")
