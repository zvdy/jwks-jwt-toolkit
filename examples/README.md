# JWKS and JWT Examples

This directory contains examples for working with the JWKS server and JWT client.

## Available Examples

### Custom JWT Payload

The `custom_payload.json` file demonstrates a typical JWT payload with custom claims.
You can use it to generate a JWT with these claims:

```bash
python -m jwt_client.cli generate-jwt --key-file my_key.pem --kid my-key-id --payload examples/custom_payload.json
```

## Common Workflows

### Complete JWT Workflow

1. Start the JWKS server:
   ```bash
   python run_server.py
   ```

2. Generate a new key pair and upload it to the server:
   ```bash
   python run_client.py generate-key --type rsa --save --upload
   ```

3. Generate a JWT using the key:
   ```bash
   python run_client.py generate-jwt --key-file <kid>.pem --kid <kid>
   ```

4. Verify the JWT against the JWKS server:
   ```bash
   python run_client.py verify-jwt --token <jwt_token>
   ```

### Using Multiple Keys

You can generate and manage multiple keys for different purposes:

1. Generate an RSA key for signing:
   ```bash
   python run_client.py generate-key --type rsa --kid "signing-key-1" --save --upload
   ```

2. Generate an EC key for another application:
   ```bash
   python run_client.py generate-key --type ec --curve P-256 --kid "api-key-1" --save --upload
   ```

3. List all keys on the server:
   ```bash
   curl http://localhost:5000/keys
   ```
