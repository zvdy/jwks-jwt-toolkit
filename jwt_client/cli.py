"""
Command Line Interface Module

This module provides a command-line interface for the JWT client.
"""

import os
import sys
import json
import logging
import argparse
from typing import Dict, Any, Optional, List

from cryptography.hazmat.primitives.asymmetric import ec
import requests

from jwt_client.crypto.keys import KeyGenerator
from jwt_client.crypto.jwk import JWK
from jwt_client.jwt.generator import JWTGenerator
from jwt_client.jwt.validator import JWTValidator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Default JWKS URL
DEFAULT_JWKS_URL = 'http://localhost:5000/.well-known/jwks.json'


class CLI:
    """
    Command Line Interface for JWT Client

    This class provides a command-line interface for generating keys,
    creating JWTs, and validating JWTs.
    """

    @staticmethod
    def setup_parser() -> argparse.ArgumentParser:
        """
        Set up the command-line argument parser.

        Returns:
            argparse.ArgumentParser: Configured parser
        """
        parser = argparse.ArgumentParser(
            description='JWT Generator and Validator',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  # Generate an RSA key pair and upload to server
  python -m jwt_client.cli generate-key --type rsa --upload --save

  # Generate a JWT using a private key
  python -m jwt_client.cli generate-jwt --key-file my_key.pem --kid my-key-id

  # Verify a JWT against a JWKS endpoint
  python -m jwt_client.cli verify-jwt --token eyJh...
"""
        )

        subparsers = parser.add_subparsers(dest='command', help='Command to run')

        # Generate key command
        gen_parser = subparsers.add_parser('generate-key', help='Generate a key pair')
        gen_parser.add_argument('--type', choices=['rsa', 'ec'], default='rsa',
                               help='Key type (default: rsa)')
        gen_parser.add_argument('--kid', help='Key ID (default: auto-generated UUID)')
        gen_parser.add_argument('--upload', action='store_true',
                               help='Upload the JWK to the server')
        gen_parser.add_argument('--save', action='store_true',
                               help='Save the private key to a file')
        gen_parser.add_argument('--server', default='http://localhost:5000/upload',
                               help='JWK server URL')
        gen_parser.add_argument('--key-size', type=int, default=2048,
                               help='Key size for RSA keys (default: 2048)')
        gen_parser.add_argument('--curve', choices=['P-256', 'P-384', 'P-521'],
                               default='P-256', help='Curve for EC keys (default: P-256)')

        # Generate JWT command
        jwt_parser = subparsers.add_parser('generate-jwt', help='Generate a JWT')
        jwt_parser.add_argument('--key-file', required=True,
                               help='Private key file')
        jwt_parser.add_argument('--kid', required=True,
                               help='Key ID to use')
        jwt_parser.add_argument('--alg',
                               help='Algorithm (default: auto-detect)')
        jwt_parser.add_argument('--payload',
                               help='JSON payload file (optional)')
        jwt_parser.add_argument('--output',
                               help='Output file for JWT (default: stdout)')

        # Verify JWT command
        verify_parser = subparsers.add_parser('verify-jwt', help='Verify a JWT')
        verify_parser.add_argument('--token', required=True,
                                 help='JWT to verify')
        verify_parser.add_argument('--jwks-url', default=DEFAULT_JWKS_URL,
                                 help='JWKS URL')
        verify_parser.add_argument('--ignore-exp', action='store_true',
                                 help='Ignore token expiration')

        return parser

    @staticmethod
    def generate_key(args: argparse.Namespace) -> int:
        """
        Handle the generate-key command.

        Args:
            args (argparse.Namespace): Command-line arguments

        Returns:
            int: Exit code
        """
        try:
            if args.type == 'rsa':
                logger.info(f"Generating RSA key pair with size {args.key_size} bits")
                private_pem, jwk = KeyGenerator.generate_rsa_key(
                    key_size=args.key_size,
                    kid=args.kid
                )
            else:  # ec
                # Convert curve name to cryptography curve object
                curve = {
                    'P-256': ec.SECP256R1(),
                    'P-384': ec.SECP384R1(),
                    'P-521': ec.SECP521R1(),
                }.get(args.curve, ec.SECP256R1())

                logger.info(f"Generating EC key pair with curve {args.curve}")
                private_pem, jwk = KeyGenerator.generate_ec_key(
                    curve=curve,
                    kid=args.kid
                )

            print(f"Generated {args.type.upper()} key with ID: {jwk['kid']}")

            if args.save:
                filename = f"{jwk['kid']}.pem"
                with open(filename, 'wb') as f:
                    f.write(private_pem)
                print(f"Private key saved to {filename}")

            if args.upload:
                CLI.upload_jwk(jwk, args.server)

            # Print JWK
            print("\nJWK:")
            print(json.dumps(jwk, indent=2))

            return 0
        except Exception as e:
            logger.error(f"Error generating key: {str(e)}")
            print(f"Error: {str(e)}")
            return 1

    @staticmethod
    def generate_jwt(args: argparse.Namespace) -> int:
        """
        Handle the generate-jwt command.

        Args:
            args (argparse.Namespace): Command-line arguments

        Returns:
            int: Exit code
        """
        try:
            # Load private key
            with open(args.key_file, 'rb') as f:
                private_key_pem = f.read()

            # Load payload if provided
            payload = None
            if args.payload:
                payload = JWTGenerator.load_payload_from_file(args.payload)

            # Generate JWT
            token = JWTGenerator.generate_jwt(
                private_key_pem,
                args.kid,
                payload,
                args.alg
            )

            if args.output:
                with open(args.output, 'w') as f:
                    f.write(token)
                print(f"JWT written to {args.output}")
            else:
                print("\nGenerated JWT:")
                print(token)

            return 0
        except Exception as e:
            logger.error(f"Error generating JWT: {str(e)}")
            print(f"Error: {str(e)}")
            return 1

    @staticmethod
    def verify_jwt(args: argparse.Namespace) -> int:
        """
        Handle the verify-jwt command.

        Args:
            args (argparse.Namespace): Command-line arguments

        Returns:
            int: Exit code
        """
        try:
            validator = JWTValidator(args.jwks_url)

            # Set validation options
            options = {
                "verify_signature": True,
                "verify_exp": not args.ignore_exp,
                "verify_nbf": True,
                "verify_iat": True
            }

            valid, result = validator.validate_jwt(args.token, options)

            if valid:
                print("\nJWT is valid!")
                print("Payload:")
                print(json.dumps(result, indent=2))
                return 0
            else:
                print(f"\nJWT verification failed: {result}")
                return 1
        except Exception as e:
            logger.error(f"Error verifying JWT: {str(e)}")
            print(f"Error: {str(e)}")
            return 1

    @staticmethod
    def upload_jwk(jwk: Dict[str, Any], server_url: str) -> bool:
        """
        Upload a JWK to the server.

        Args:
            jwk (Dict[str, Any]): The JWK to upload
            server_url (str): The server URL

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # First, get the current JWKS
            jwks_url = server_url.replace('/upload', '/.well-known/jwks.json')
            logger.info(f"Fetching current JWKS from {jwks_url}")

            try:
                response = requests.get(jwks_url)
                if response.status_code == 200:
                    jwks = response.json()
                else:
                    logger.warning(f"Failed to fetch JWKS, creating new one")
                    jwks = {"keys": []}
            except Exception as e:
                logger.warning(f"Failed to fetch JWKS: {str(e)}, creating new one")
                jwks = {"keys": []}

            # Check if key with same ID already exists
            for i, key in enumerate(jwks.get("keys", [])):
                if key.get("kid") == jwk.get("kid"):
                    # Replace existing key
                    logger.info(f"Replacing existing key with ID: {jwk['kid']}")
                    jwks["keys"][i] = jwk
                    break
            else:
                # Add our key to the JWKS
                jwks["keys"].append(jwk)

            # Upload the updated JWKS
            logger.info(f"Uploading JWKS to {server_url}")
            response = requests.post(server_url, json=jwks)

            if response.status_code == 201:
                logger.info(f"JWK uploaded successfully with key ID: {jwk.get('kid')}")
                print(f"JWK uploaded successfully with key ID: {jwk.get('kid')}")
                return True
            else:
                logger.error(f"Failed to upload JWK: {response.text}")
                print(f"Failed to upload JWK: {response.text}")
                return False

        except Exception as e:
            logger.error(f"Error uploading JWK: {str(e)}")
            print(f"Error uploading JWK: {str(e)}")
            return False


def main() -> int:
    """
    Main entry point for the CLI.

    Returns:
        int: Exit code
    """
    parser = CLI.setup_parser()
    args = parser.parse_args()

    if args.command == 'generate-key':
        return CLI.generate_key(args)
    elif args.command == 'generate-jwt':
        return CLI.generate_jwt(args)
    elif args.command == 'verify-jwt':
        return CLI.verify_jwt(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
