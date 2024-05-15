from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import os

def encrypt_message(msg, aes_key, aes_iv):
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(aes_iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Pad the message to make its length a multiple of the block size
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_msg = padder.update(msg) + padder.finalize()
    
    cipher_txt = encryptor.update(padded_msg) + encryptor.finalize()
    return cipher_txt

def encrypt_aes_key(aes_key, receiver_public):
    encrpyed_aes_key = receiver_public.encrypt(
        aes_key, 
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
            )
        )
    return encrpyed_aes_key

def generate_mac(cipher_txt, aes_key):
    h = hmac.HMAC(aes_key, hashes.SHA256(), backend=default_backend())
    h.update(cipher_txt)
    mac = h.finalize()
    return mac

def main():
    # load receiver's public key
    with open("receiver_public.pem", "rb") as receiver_key_file:
        receiver_public = serialization.load_pem_public_key(
            receiver_key_file.read(), 
            backend=default_backend()
        )
    
    # read message from file
    with open ("msg1.txt", "rb") as msg_file:
        msg = msg_file.read()
        
    # genreate aes key and iv
    aes_key = os.urandom(32) # key size = 32 bytes =  256 bits
    aes_iv = os.urandom(16) # 128 bits
    
    # encrypt message using AES
    cipher_txt = encrypt_message(msg, aes_key, aes_iv)
    
    # encrypt aes key using reciever's public key
    encrypted_aes_key = encrypt_aes_key(aes_key, receiver_public)

    # generate MAC
    sender_mac = generate_mac(cipher_txt,aes_key)
    
    #record everything in file
    with open("Transmitted_Data.txt", "wb") as file:
        file.write(encrypted_aes_key) #512 bytes
        file.write(aes_iv) # 16 bytes
        file.write(sender_mac) #32 bytes
        file.write(cipher_txt) #32 bytes
        
    print("Data transmitted successful")
        
if __name__ == "__main__":
    main()
