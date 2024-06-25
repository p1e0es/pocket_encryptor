from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend
import os
import sys
import base64

def encrypt_chacha20(key, nonce, plaintext):
    # chacha20 instance
    algorithm = algorithms.ChaCha20(key, nonce)
    cipher = Cipher(algorithm, mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    
    # encrypt
    ciphertext = encryptor.update(plaintext)
    return ciphertext

def decrypt_chacha20(key, nonce, ciphertext):
    # chacha20 instance
    algorithm = algorithms.ChaCha20(key, nonce)
    cipher = Cipher(algorithm, mode=None, backend=default_backend())
    decryptor = cipher.decryptor()
    
    # decrypt
    plaintext = decryptor.update(ciphertext)
    return plaintext

# generate random key and nonce
def generate_key_nonce():
    key = os.urandom(32)  
    nonce = os.urandom(16)
    return key, nonce

# generate new config
def generate_config():
    # generate key、nonce、config file
    if os.path.exists('config'):
        print(f"config file already exist, if you want generate new config file please rename config file\n")
    else:
        with open('config', 'w') as file:
            file.write("author: p1e0es\n")

        key, nonce = generate_key_nonce()
        key_b64 = base64.b64encode(key).decode('utf-8')
        nonce_b64 = base64.b64encode(nonce).decode('utf-8')
        print("Please write key and nonce to paper. It's only credential for interview your information")
        print(f"key: {key_b64}")
        print(f"nonce: {nonce_b64}")

def help():
    print("Usage: python3 main.py command\n")
    print("command:\n")
    print("--- gen (generate key, nonce, config file)\n")
    print("--- find (find recorded information in config file)\n")
    print("--- record (record new information to config file)\n")

def main():
    option = sys.argv[1]

    if option == "gen":
        generate_config()
    elif option == "find":
        # find recorded information
        pass
    elif option == "record":
        # record new information to config file
        pass
    else:
        help()

if __name__ == "__main__":
    main()