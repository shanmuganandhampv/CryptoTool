from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

class RSACipher:
    def generate_keys(self):
        # Generate a 2048-bit RSA key pair
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return private_key, public_key

    def encrypt(self, message, public_key_pem):
        recipient_key = RSA.import_key(public_key_pem)
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        encrypted_blob = cipher_rsa.encrypt(message.encode('utf-8'))
        return base64.b64encode(encrypted_blob).decode('utf-8')

    def decrypt(self, encrypted_msg, private_key_pem):
        try:
            private_key = RSA.import_key(private_key_pem)
            cipher_rsa = PKCS1_OAEP.new(private_key)
            encrypted_blob = base64.b64decode(encrypted_msg)
            decrypted_blob = cipher_rsa.decrypt(encrypted_blob)
            return decrypted_blob.decode('utf-8')
        except ValueError:
            return "Error: Decryption Failed."