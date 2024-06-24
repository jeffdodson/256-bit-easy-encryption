import os
import sys
import subprocess

# Check if 'pycryptodome' is installed, if not, install it
try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    import base64
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pycryptodome"])
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    import base64

def generate_key(sentence):
    if len(sentence) < 32:
        raise ValueError(f"The key must be exactly 32 bytes long. Add {32 - len(sentence)} more characters.")
    return sentence[:32].encode('utf-8')

# Encrypt
def encrypt(message, key):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
    return base64.b64encode(nonce + ciphertext).decode('utf-8')

# Decrypt
def decrypt(ciphertext, key):
    decoded = base64.b64decode(ciphertext.encode('utf-8'))
    nonce = decoded[:16]
    ciphertext = decoded[16:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext).decode('utf-8')
    return plaintext

if __name__ == "__main__":
    while True:
        try:
            # Ask the user for the key sentence
            sentence = input("Enter a sentence to use as a key (will be truncated or padded to 32 characters): ")
            key = generate_key(sentence)
            break
        except ValueError as e:
            print(e)
            continue
    
    # Ask the user for the message to encrypt
    message = input("Enter the message to encrypt: ")

    # Encrypt the message
    encrypted_message = encrypt(message, key)
    print(f"Encrypted Message: {encrypted_message}")

    # Decrypt the message
    decrypted_message = decrypt(encrypted_message, key)
    print(f"Decrypted Message: {decrypted_message}")
