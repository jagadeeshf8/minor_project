from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
import pandas as pd
import os
import random

def generate_dh_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def perform_dh_and_derive_key(private_key, public_key):
    shared_key = private_key.exchange(ec.ECDH(), public_key)
    symmetric_key = hashes.Hash(hashes.SHA256(), backend=default_backend())
    symmetric_key.update(shared_key)
    symmetric_key = symmetric_key.finalize()
    return symmetric_key

def encrypt_message(key, message):
    iv = os.urandom(12)  # Use os.urandom() for generating the Initialization Vector (IV)
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=backend)
    encryptor = cipher.encryptor()
    encryptor.authenticate_additional_data(iv)
    ciphertext = encryptor.update(message) + encryptor.finalize()
    return iv + ciphertext + encryptor.tag

# Decrypt a message using AES
def decrypt_message(key, encrypted_message):
    iv = encrypted_message[:12]
    backend = default_backend()
    ciphertext = encrypted_message[12:-16]
    tag = encrypted_message[-16:]
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=backend)
    decryptor = cipher.decryptor()
    decryptor.authenticate_additional_data(iv)
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

def main():
    Node1_private_key, Node1_public_key = generate_dh_key_pair()
    Node2_private_key, Node2_public_key = generate_dh_key_pair()

    Node1_shared_key = perform_dh_and_derive_key(Node1_private_key, Node2_public_key)
    Node2_shared_key = perform_dh_and_derive_key(Node2_private_key, Node1_public_key)

    if Node1_shared_key == Node2_shared_key:
        print("Shared keys match!")
        print("Node1 and Node2 are verified")
        print("So,AES Encryption and Decryption Process  Will start") 
        print()
        excel_file_path = r'C:\Users\M.JAGADEESH\Downloads\Book1.xlsx'
        df = pd.read_excel(excel_file_path)
        column_names = df.columns.tolist()
        bp_column = 'bp'
        data = df[bp_column]
        i = random.randint(0, 84)
        for _ in range(5):
            index_to_print = i
            d = data.iloc[index_to_print]
            h=str(d)
            i+=1
            message = h.encode()
            print("data:",float(message.decode()));
            # Encrypt the message using the symmetric key
            encrypted_message = encrypt_message(Node1_shared_key, message)
            print("Encrypted data at Node1:", encrypted_message)

            # Decrypt the message using the symmetric key
            decrypted_message = decrypt_message(Node2_shared_key, encrypted_message)
            print("Decrypted data at Node2:", decrypted_message.decode(),"\n")
        print("A circle is done")                                                
    else:
        print("Shared keys do not match!")

if __name__ == "__main__":
    main()
