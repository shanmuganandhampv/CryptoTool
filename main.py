import os
from Crypto.Random import get_random_bytes
from utils.aes_algo import AESCipher
from utils.rsa_algo import RSACipher
from utils.hashing import generate_sha256

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def main():
    while True:
        print("\n=== Python Crypto Project ===")
        print("1. AES Encryption (Symmetric)")
        print("2. RSA Encryption (Asymmetric)")
        print("3. SHA-256 Hashing")
        print("4. Exit")
        
        choice = input("Select an option: ")

        if choice == '1':
            print("\n--- AES Mode ---")
            # Create a random 32-byte key for this session
            key = get_random_bytes(32) 
            aes = AESCipher(key)
            print(f"Session Key (Hex): {key.hex()}")
            
            msg = input("Enter message to encrypt: ")
            encrypted = aes.encrypt(msg)
            print(f"Encrypted (Base64): {encrypted}")
            
            decrypted = aes.decrypt(encrypted)
            print(f"Decrypted: {decrypted}")

        elif choice == '2':
            print("\n--- RSA Mode ---")
            rsa = RSACipher()
            print("Generating 2048-bit Key Pair... (this may take a second)")
            priv, pub = rsa.generate_keys()
            
            msg = input("Enter message to encrypt: ")
            # Encrypt with Public Key
            cipher_text = rsa.encrypt(msg, pub)
            print(f"Encrypted: {cipher_text}")
            
            # Decrypt with Private Key
            plain_text = rsa.decrypt(cipher_text, priv)
            print(f"Decrypted: {plain_text}")

        elif choice == '3':
            print("\n--- Hashing Mode ---")
            msg = input("Enter data to hash: ")
            h = generate_sha256(msg)
            print(f"SHA-256: {h}")

        elif choice == '4':
            print("Exiting...")
            break
        else:
            print("Invalid selection.")

if __name__ == "__main__":
    main()