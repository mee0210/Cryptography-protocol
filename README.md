# Cryptography-protocol
Secure digital contract exchange using RSA, ECDH, AES
# Cryptographic Protocol for Secure Contract Exchange

This project implements a secure contract exchange protocol using:
- ECDH for key exchange
- RSA for digital signatures
- AES-256 for document encryption
- SHA-256 for integrity

Workflow

1. Seller’s solicitor signs contract using RSA.
2. Contract sent to buyer via H&R, encrypted.
3. Buyer signs contract and returns it.
4. H&R verifies and forwards securely using ECDH + AES.
