from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


def generate_rsa_keys():
    # generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )
    # generate public key
    public_key = private_key.public_key()

    # serialize the private key to pem format
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # serialize the public key to pem format
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
      
    return pem_private_key, pem_public_key

def main():
    pem_sender_private, pem_sender_public = generate_rsa_keys()
    
    pem_receiver_private, pem_receiver_public = generate_rsa_keys()
    
    # save sender private key as a file
    with open("sender_private.pem", "wb") as file:
        file.write(pem_sender_private)
    
    # save sender public key as a file  
    with open("sender_public.pem", "wb") as file:
        file.write(pem_sender_public)
        
    # save receiver private key as a file
    with open("receiver_private.pem", "wb") as file:
        file.write(pem_receiver_private)
    
    # save receiver public key as a file  
    with open("receiver_public.pem", "wb") as file:
        file.write(pem_receiver_public)