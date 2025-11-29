from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

class AESCipher:
    def __init__(self, key):
        # AES-256 requires a 32-byte key
        self.key = key 

    def encrypt(self, raw_data):
        # Generate a random Initialization Vector (IV)
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        
        # Pad the data to be a multiple of block size
        padded_data = pad(raw_data.encode('utf-8'), AES.block_size)
        encrypted_bytes = cipher.encrypt(padded_data)
        
        # Return IV + Encrypted Data (encoded in base64 for readability)
        return base64.b64encode(iv + encrypted_bytes).decode('utf-8')

    def decrypt(self, enc_data):
        try:
            # Decode from base64
            enc_data = base64.b64decode(enc_data)
            
            # Extract IV (first 16 bytes) and Ciphertext
            iv = enc_data[:AES.block_size]
            ct = enc_data[AES.block_size:]
            
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            decrypted_padded = cipher.decrypt(ct)
            
            # Unpad to get original message
            return unpad(decrypted_padded, AES.block_size).decode('utf-8')
        except (ValueError, KeyError):
            return "Error: Decryption Failed (Wrong Key or Corrupted Data)"