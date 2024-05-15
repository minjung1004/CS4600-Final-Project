from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding


def decrypt_aes_key(encrypted_aes_key, receiver_private):
    aes_key = receiver_private.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return aes_key

def verify_mac(cipher_txt, sender_mac, aes_key):
    h = hmac.HMAC(aes_key, hashes.SHA256(), backend=default_backend())
    h.update(cipher_txt)
    receiver_mac = h.finalize()

    if (receiver_mac == sender_mac):
        print("Mac verfication successful")
    else:
        print("Not successful")
    

def decrypt_msg(cipher_txt, aes_key, aes_iv):
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(aes_iv), backend=default_backend)
    decryptor = cipher.decryptor()
    
    plain_txt = decryptor.update(cipher_txt) + decryptor.finalize()
    return plain_txt

def main():
    with open("receiver_private.pem", "rb") as receiver_key_file:
        receiver_private = serialization.load_pem_private_key(
            receiver_key_file.read(), 
            password=None,
            backend=default_backend()
        )
        
    # read transmitted data from file
    with open("Transmitted_Data.txt", "rb") as file:
        data = file.read()
        encrypted_aes_key = data[:512]
        aes_iv = data[512:528]
        sender_mac = data[528:560]
        cipher_txt = data[560:]
  
    #decrypt aes key using receiver private key
    aes_key = decrypt_aes_key(encrypted_aes_key, receiver_private)
    
   
    # # verify the mac
    verify_mac(cipher_txt, sender_mac, aes_key)
    
    # decrypt message
    plain_txt = decrypt_msg(cipher_txt, aes_key, aes_iv)
    
    print("Received msg: ", plain_txt.decode().strip())
    
if __name__ == "__main__":
    main()