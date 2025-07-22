from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os


# Step 1: Generate RSA Keys (Buyer and Seller)
def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

buyer_private_key, buyer_public_key = generate_rsa_keys()
seller_private_key, seller_public_key = generate_rsa_keys()

# Step 2: Generate ECDH Keys (HR and Seller's Solicitor)

HR_ecdh_private = ec.generate_private_key(ec.SECP256R1())
HR_ecdh_public = HR_ecdh_private.public_key()

seller_ecdh_private = ec.generate_private_key(ec.SECP256R1())
seller_ecdh_public = seller_ecdh_private.public_key()


# Step 3: Seller Signs the Contract

contract = b"This is the digital contract for property transaction."

contract_hash = hashes.Hash(hashes.SHA256())
contract_hash.update(contract)
hashed_contract = contract_hash.finalize()

seller_signature = seller_private_key.sign(
    hashed_contract,
    padding.PKCS1v15(),
    hashes.SHA256()
)


# Step 4: Buyer Verifies Seller's Signature and Signs
try:
    seller_public_key.verify(
        seller_signature,
        hashed_contract,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    print("Seller's signature verified.")
except Exception as e:
    print("Seller's signature verification failed.")
    exit()

# Buyer signs the contract
buyer_hash = hashes.Hash(hashes.SHA256())
buyer_hash.update(contract)
hashed_buyer_contract = buyer_hash.finalize()

buyer_signature = buyer_private_key.sign(
    hashed_buyer_contract,
    padding.PKCS1v15(),
    hashes.SHA256()
)

# Step 5: ECDH Key Exchange for AES Key Derivation

shared_secret = HR_ecdh_private.exchange(ec.ECDH(), seller_ecdh_public)
aes_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'key agreement').derive(shared_secret)

# Step 6: AES Encrypt the Contract and Signatures

message_to_encrypt = contract + b"::SELLER_SIG::" + seller_signature + b"::BUYER_SIG::" + buyer_signature

iv = os.urandom(16)
cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
encryptor = cipher.encryptor()
ciphertext = encryptor.update(message_to_encrypt) + encryptor.finalize()

print("\nEncrypted contract sent from H&R to Seller's Solicitor.")

# Step 7: Decryption on Seller’s End
decryptor = Cipher(algorithms.AES(aes_key), modes.CFB(iv)).decryptor()
decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()

print("\nDecrypted Contract and Signatures Preview:\n")
print(decrypted_message[:300])  
