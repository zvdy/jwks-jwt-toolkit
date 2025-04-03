"""
Key Generation Module

This module provides functionality for generating and working with
RSA and EC key pairs for use with JWK and JWT.
"""

import uuid
import logging
from typing import Tuple, Dict, Any, Optional, Union

from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization

from jwt_client.crypto.jwk import JWK

logger = logging.getLogger(__name__)

class KeyGenerator:
    """
    Cryptographic Key Generator
    
    This class provides methods to generate RSA and EC key pairs
    and convert them to various formats.
    """
    
    @staticmethod
    def generate_rsa_key(key_size: int = 2048, 
                         public_exponent: int = 65537, 
                         kid: Optional[str] = None) -> Tuple[bytes, Dict[str, Any]]:
        """
        Generate an RSA key pair and return the private key in PEM format
        and public key as a JWK.
        
        Args:
            key_size (int): Size of the key in bits
            public_exponent (int): Public exponent for the key
            kid (Optional[str]): Key ID, generated if not provided
            
        Returns:
            Tuple[bytes, Dict[str, Any]]: (Private key PEM, public key JWK)
        """
        if kid is None:
            kid = str(uuid.uuid4())
        
        logger.info(f"Generating RSA key with size: {key_size}, kid: {kid}")
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=public_exponent,
            key_size=key_size
        )
        
        # Convert to PEM format
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Create JWK from the key
        jwk = JWK.from_rsa_key(private_key, kid=kid)
        
        logger.debug(f"Generated RSA key pair with kid: {kid}")
        return private_pem, jwk
    
    @staticmethod
    def generate_ec_key(curve: ec.EllipticCurve = ec.SECP256R1(), 
                        kid: Optional[str] = None,
                        alg: Optional[str] = None) -> Tuple[bytes, Dict[str, Any]]:
        """
        Generate an EC key pair and return the private key in PEM format
        and public key as a JWK.
        
        Args:
            curve (ec.EllipticCurve): The curve to use
            kid (Optional[str]): Key ID, generated if not provided
            alg (Optional[str]): Algorithm to use, determined from curve if not provided
            
        Returns:
            Tuple[bytes, Dict[str, Any]]: (Private key PEM, public key JWK)
        """
        if kid is None:
            kid = str(uuid.uuid4())
            
        logger.info(f"Generating EC key with curve: {curve.name}, kid: {kid}")
        
        # Generate private key
        private_key = ec.generate_private_key(curve)
        
        # Convert to PEM format
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Create JWK from the key
        jwk = JWK.from_ec_key(private_key, kid=kid, alg=alg)
        
        logger.debug(f"Generated EC key pair with kid: {kid}")
        return private_pem, jwk
    
    @staticmethod
    def load_private_key(pem_data: bytes) -> Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]:
        """
        Load a private key from PEM format.
        
        Args:
            pem_data (bytes): The PEM data to load
            
        Returns:
            Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]: The loaded private key
            
        Raises:
            ValueError: If the PEM data is invalid
        """
        try:
            private_key = serialization.load_pem_private_key(
                pem_data,
                password=None
            )
            
            if isinstance(private_key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
                return private_key
            else:
                raise ValueError(f"Unsupported key type: {type(private_key)}")
        except Exception as e:
            logger.error(f"Failed to load private key: {str(e)}")
            raise ValueError(f"Invalid private key: {str(e)}")
    
    @staticmethod
    def get_algorithm_for_key(private_key: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]) -> str:
        """
        Determine the appropriate JWT algorithm for a given private key.
        
        Args:
            private_key (Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]): The private key
            
        Returns:
            str: The recommended algorithm
            
        Raises:
            ValueError: If the key type is not supported
        """
        if isinstance(private_key, rsa.RSAPrivateKey):
            key_size = private_key.key_size
            if key_size >= 4096:
                return "RS512"
            elif key_size >= 3072:
                return "RS384"
            else:
                return "RS256"
        
        elif isinstance(private_key, ec.EllipticCurvePrivateKey):
            curve = private_key.curve
            if isinstance(curve, ec.SECP256R1):
                return "ES256"
            elif isinstance(curve, ec.SECP384R1):
                return "ES384"
            elif isinstance(curve, ec.SECP521R1):
                return "ES512"
            else:
                raise ValueError(f"Unsupported curve: {curve.name}")
        
        else:
            raise ValueError(f"Unsupported key type: {type(private_key)}")
