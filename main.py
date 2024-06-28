import json
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend
import os
import sys
import base64

def encrypt_chacha20(key, nonce, plaintext):
    key_decoded = base64.b64decode(key)
    nonce_decoded = base64.b64decode(nonce)

    # chacha20 instance
    algorithm = algorithms.ChaCha20(key_decoded, nonce_decoded)
    cipher = Cipher(algorithm, mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    
    # encrypt
    ciphertext = encryptor.update(plaintext)
    return ciphertext

def decrypt_chacha20(key, nonce, ciphertext):
    key_decoded = base64.b64decode(key)
    nonce_decoded = base64.b64decode(nonce)

    # chacha20 instance
    algorithm = algorithms.ChaCha20(key_decoded, nonce_decoded)
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
        key, nonce = generate_key_nonce()
        key_b64 = base64.b64encode(key).decode('utf-8')
        nonce_b64 = base64.b64encode(nonce).decode('utf-8')

        init_data = []
        init_data_json = json.dumps(init_data)
        init_data_bytes = init_data_json.encode()
        init_data_bytes_len = len(init_data_bytes)
        packed_data = struct.pack(f'I{init_data_bytes_len}s', init_data_bytes_len, init_data_bytes)

        encrypt_data =  encrypt_chacha20(key_b64, nonce_b64, packed_data)

        with open('config', 'wb') as file:
            file.write(encrypt_data)

        
        print("Please write key and nonce to paper. It's only credential for interview your information")
        print(f"key: {key_b64}")
        print(f"nonce: {nonce_b64}")

def help():
    print("Usage: python3 main.py command\n")
    print("command:\n")
    print("--- gen (generate key, nonce, config file)\n")
    print("--- find (find recorded information in config file)\n")
    print("--- record (record new information to config file)\n")

# find recorded information
def findInfo():
    if os.path.exists('config'):
        key = input('please input key:')
        nonce = input('please input nonce:')

        with open('config', 'rb') as f:
            data = f.read()
            decrypted_data = decrypt_chacha20(key, nonce, data)
            data_length = struct.unpack('I', decrypted_data[:4])[0]
            data = decrypted_data[4:4+data_length]
            data_json = json.loads(data)
            # print(data_length)
            # print(data_json)
            print('All recorded information list:\n')
            for item in data_json:
                for k, v in item.items():
                    print(f'{k}: {v}')
                print('\n')

    else:
        print('config file not found!')
        
# record new information
def recordInfo():
    if os.path.exists('config'):
        key = input('please input key:')
        nonce = input('please input nonce:')

        with open('config', 'rb') as f:
            encrypted_data = f.read()

        decrypted_data = decrypt_chacha20(key, nonce, encrypted_data)
        data_length = struct.unpack('I', decrypted_data[:4])[0]
        data = decrypted_data[4:4+data_length]
        data_json = json.loads(data)

        title = input('title:')
        url = input('url:')
        username = input('username:')
        password = input('password:')

        new_data = {
            'title': title,
            'url': url,
            'username': username,
            'password': password
        }

        data_json.append(new_data)

        combined_data_json = json.dumps(data_json)
        combined_data_bytes = combined_data_json.encode()
        combined_data_bytes_len = len(combined_data_bytes)
        
        packed_data = struct.pack(f'I{combined_data_bytes_len}s', combined_data_bytes_len, combined_data_bytes)

        encrypt_data =  encrypt_chacha20(key, nonce, packed_data)

        with open('config', 'wb') as file:
            file.write(encrypt_data)
    else:
        print('config file not found!')

def main():
    option = sys.argv[1]

    if option == "gen":
        generate_config()
    elif option == "find":
        # find recorded information
        findInfo()
    elif option == "record":
        # record new information to config file
        recordInfo()
    else:
        help()

if __name__ == "__main__":
    main()