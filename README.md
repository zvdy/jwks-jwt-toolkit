# JWKS Server and JWT Client

Implementation of a JSON Web Key Set (JWKS) server and JWT client following RFC 7517 (JWK) and RFC 7519 (JWT).

## Architecture

```
+-------------+          +---------------+
|             |  1. GET  |               |
|  JWT Client | -------> |  JWKS Server  |
|             | <------- |               |
+------+------+  2. JWKS +-------+-------+
       |                         |
       | 3. Generate             | 4. Store/Manage
       | JWT                     | JWKs
       v                         v
+------+------+          +-------+-------+
|  JWT Token  |          |   JWK Store   |
|             |          |               |
+-------------+          +---------------+
```

## Request/Response Flow

### JWT Verification Flow

```
+-------------+           +---------------+          +--------------+
|             | 1. Token  |               | 2. Fetch |              |
|  Client     | --------> | JWT Validator | -------> |  JWKS Server |
|             |           |               | <------- |              |
|             |           |               | 3. JWKS  |              |
|             | 4. Result |               |          |              |
|             | <-------- |               |          |              |
+-------------+           +---------------+          +--------------+
```

### JWK Management Flow

```
+-------------+           +---------------+          +--------------+
|             | 1. JWK    |               | 2. Store |              |
| Admin/Tool  | --------> | JWKS Server   | -------> |  JWK Store   |
|             |           |               | <------- |              |
|             | 3. Result |               | 4. Saved |              |
|             | <-------- |               |          |              |
+-------------+           +---------------+          +--------------+
```

## Project Structure

```
jwks/
├── jwks_server/             # JWKS server implementation
│   ├── __init__.py
│   ├── app.py               # Main Flask application 
│   ├── config.py            # Configuration settings
│   └── jwk_manager.py       # JWK storage and validation
└── jwt_client/              # JWT client implementation
    ├── __init__.py
    ├── cli.py               # Command-line interface
    ├── crypto/              # Cryptographic operations
    │   ├── __init__.py
    │   ├── jwk.py           # JWK handling (RFC 7517)
    │   └── keys.py          # Key generation and conversion
    └── jwt/                 # JWT operations (RFC 7519)
        ├── __init__.py
        ├── generator.py     # JWT token generation
        └── validator.py     # JWT token validation
```

## Requirements

- Python 3.8+
- Flask
- PyJWT
- cryptography

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### Starting the JWKS Server

```bash
python -m jwks_server.app
```

### Using the JWT Client

1. Generate a key pair:
```bash
python -m jwt_client.cli generate-key --type rsa --save --upload
```

2. Generate a JWT:
```bash
python -m jwt_client.cli generate-jwt --key-file [key_file.pem] --kid [key_id]
```

3. Verify a JWT:
```bash
python -m jwt_client.cli verify-jwt --token [jwt_token]
```

## References

- [RFC 7517 - JSON Web Key (JWK)](https://tools.ietf.org/html/rfc7517)
- [RFC 7519 - JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)
