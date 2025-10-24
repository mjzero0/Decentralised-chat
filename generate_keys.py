"""
Key Generator for SOCP Server (RSA-4096)

This script generates a 4096-bit RSA key pair using the `cryptography` library
and saves them in PEM format:

- Private key → server_priv.pem (unencrypted PKCS#8)
- Public key → server_pub.pem (SubjectPublicKeyInfo)

Used for server-side transport signing and message verification under SOCP v1.3.
"""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Generate RSA private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096
)

# Save private key to PEM file
with open("server_priv.pem", "wb") as f:
    f.write(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    )

# Save public key to PEM file
with open("server_pub.pem", "wb") as f:
    f.write(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

print("✅ Keys generated: server_priv.pem and server_pub.pem")
