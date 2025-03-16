from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
import os



# Generate Diffie-Hellman Key Pair
def generate_dh_keys():
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

# Serialize Public Key
def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

# Load Public Key
def load_public_key(public_key_bytes):
    return serialization.load_pem_public_key(public_key_bytes)

# Derive AES Key from DH Shared Secret
def derive_aes_key(shared_secret, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    return kdf.derive(shared_secret)

# Generate a New AES Key for Each File
def generate_aes_key():
    return os.urandom(32)  # Generate a 256-bit AES key

# Encrypt AES Key using the Shared Secret Key
def encrypt_aes_key(aes_key, shared_secret):
    cipher = Cipher(algorithms.AES(shared_secret[:32]), modes.CBC(os.urandom(16)))
    encryptor = cipher.encryptor()
    padding_length = 16 - (len(aes_key) % 16)
    aes_key_padded = aes_key + bytes([padding_length]) * padding_length
    encrypted_aes_key = encryptor.update(aes_key_padded) + encryptor.finalize()
    return encrypted_aes_key

# Encrypt File using AES-CBC
def encrypt_file(data, aes_key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    # Padding for AES block size
    padding_length = 16 - (len(data) % 16)
    data += bytes([padding_length]) * padding_length

    encrypted_data = encryptor.update(data) + encryptor.finalize()
    return encrypted_data, iv  

# Example Usage
if __name__ == "__main__":
    # Generate DH keys
    private_key, public_key = generate_dh_keys()

    # Serialize Public Key
    public_key_bytes = serialize_public_key(public_key)
    print("Serialized Public Key:", public_key_bytes.decode())

    # Simulating receiving a public key
    received_public_key = load_public_key(public_key_bytes)

    # Compute shared secret
    shared_secret = private_key.exchange(received_public_key)

    # Use a fixed salt (must be shared)
    salt = os.urandom(16)
    dh_key = derive_aes_key(shared_secret, salt)

    # Generate unique AES key for this file
    aes_key = generate_aes_key()

    # Encrypt the AES key using the derived DH key
    encrypted_aes_key = encrypt_aes_key(aes_key, dh_key)

    # Encrypt sample file data
    data = b"Confidential patient record"
    encrypted_data, iv = encrypt_file(data, aes_key)

    print("Encrypted AES Key:", encrypted_aes_key.hex())
    print("Encrypted File Data:", encrypted_data.hex())
    print("IV:", iv.hex())
