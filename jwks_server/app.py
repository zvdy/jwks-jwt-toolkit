"""
JWKS Server Application

A Flask server that provides JSON Web Key Set (JWKS) functionality
according to RFC 7517.
"""

import os
import json
import logging
from flask import Flask, request, jsonify
from typing import Dict, Any, Tuple, Union

from jwks_server.jwk_manager import jwk_manager
from jwks_server.config import active_config as config

# Configure logging
logger = logging.getLogger(__name__)

# Create Flask application
app = Flask(__name__)

# Apply configuration
app.config["MAX_CONTENT_LENGTH"] = config.MAX_CONTENT_LENGTH


@app.route('/.well-known/jwks.json', methods=['GET'])
def get_jwks() -> Tuple[Dict[str, Any], int]:
    """
    Serve the JWK Set according to RFC 7517 section 5.

    Returns:
        Tuple[Dict[str, Any], int]: JWKS response and HTTP status code
    """
    try:
        jwks = jwk_manager.get_jwks()
        logger.info("JWKS requested and served successfully")
        return jwks, 200
    except Exception as e:
        logger.error(f"Error serving JWKS: {str(e)}")
        return {"error": str(e)}, 500


@app.route('/upload', methods=['POST'])
def upload_jwks() -> Tuple[Dict[str, Any], int]:
    """
    Upload a JWK Set.

    Accepts a JWK Set either as a JSON file upload or
    direct JSON in the request body.

    Returns:
        Tuple[Dict[str, Any], int]: Response message and HTTP status code
    """
    try:
        if 'file' not in request.files:
            if request.is_json:
                # Direct JSON upload
                jwks = request.get_json()
                if not jwk_manager.is_valid_jwks(jwks):
                    logger.warning("Invalid JWKS format received")
                    return {"error": "Invalid JWKS format"}, 400

                # Save the JWKS
                if jwk_manager.save_jwks(jwks):
                    logger.info(f"JWKS uploaded via JSON with {len(jwks.get('keys', []))} keys")
                    return {
                        "message": "JWKS uploaded successfully",
                        "keys_count": len(jwks.get("keys", []))
                    }, 201
                else:
                    return {"error": "Failed to save JWKS"}, 500

            logger.warning("No file or JSON data provided in upload request")
            return {"error": "No file or JSON data provided"}, 400

        # Handle file upload
        file = request.files['file']
        if file.filename == '':
            logger.warning("Empty filename in upload request")
            return {"error": "No file selected"}, 400

        if not file.filename.endswith('.json'):
            logger.warning(f"Non-JSON file uploaded: {file.filename}")
            return {"error": "Only .json files are allowed"}, 400

        # Read and validate the JWKS from the file
        file_content = file.read().decode('utf-8')
        jwks = json.loads(file_content)

        if not jwk_manager.is_valid_jwks(jwks):
            logger.warning("Invalid JWKS format in uploaded file")
            return {"error": "Invalid JWKS format"}, 400

        # Save the JWKS
        if jwk_manager.save_jwks(jwks):
            logger.info(f"JWKS uploaded via file with {len(jwks.get('keys', []))} keys")
            return {
                "message": "JWKS uploaded successfully",
                "keys_count": len(jwks.get("keys", []))
            }, 201
        else:
            return {"error": "Failed to save JWKS"}, 500

    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error in upload: {str(e)}")
        return {"error": "Invalid JSON format"}, 400
    except Exception as e:
        logger.error(f"Error in upload: {str(e)}")
        return {"error": str(e)}, 500


@app.route('/keys', methods=['GET'])
def list_keys() -> Tuple[Dict[str, Any], int]:
    """
    List all keys in the JWK Set with basic information.

    Returns:
        Tuple[Dict[str, Any], int]: List of keys and HTTP status code
    """
    try:
        keys_info = jwk_manager.list_keys()
        logger.info(f"Listed {len(keys_info)} keys")
        return {"keys": keys_info}, 200
    except Exception as e:
        logger.error(f"Error listing keys: {str(e)}")
        return {"error": str(e)}, 500


def main():
    """
    Run the JWKS server application.
    """
    # Ensure JWKS directory exists
    os.makedirs(config.JWKS_FOLDER, exist_ok=True)

    # Start the server
    logger.info(f"Starting JWKS server on {config.HOST}:{config.PORT}")
    app.run(debug=config.DEBUG, host=config.HOST, port=config.PORT)


if __name__ == '__main__':
    main()
