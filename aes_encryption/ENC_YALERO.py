import sys
import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from key_derivation.derive_key import derive_key, is_valid_password

def encrypt_file(file_path, password):
    if not os.path.isfile(file_path):
        print("❌ The file does not exist. Please check the path and try again.")
        return

    # Validate password
    if not is_valid_password(password):
        raise ValueError ("❌ Password must be at least 8 characters long and include letters, digits, and punctuation marks.")
        

    # Derive key from password
    key, salt = derive_key(password)
    
    key_hash = hashlib.sha256(key).digest()[:16]


    print("Encryption salt (hex):", salt.hex())
    print("Encryption derived key SHA-256:", hashlib.sha256(key).hexdigest())

    # Read file contents
    with open(file_path, 'rb') as f:
        plaintext = f.read()

    # Encrypt with AES-192 GCM
    #cipher = AES.new(key, AES.MODE_GCM)
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    print("Encryption salt (hex):", salt.hex())
    print("Encryption derived key hash:", hashlib.sha256(key).hexdigest())
    print("Nonce (hex):", cipher.nonce.hex())
    print("Tag (hex):", tag.hex())
    print("Ciphertext size:", len(ciphertext))
    
    # Save encrypted file as .jet
    dir_name = os.path.dirname(file_path)
    base_name = os.path.basename(file_path)
    name, ext = os.path.splitext(base_name)
    encrypted_filename = os.path.splitext(base_name)[0] + '.jet'
    encrypted_path = os.path.join(dir_name, encrypted_filename)

    ext_encoded = ext.encode('utf-8')
    ext_encoded = ext_encoded.ljust(10, b'\x00')  # pad to 10 bytes# Store: salt(16) | nonce(12) | tag(16) | ciphertext
    
    with open(encrypted_path, 'wb') as f:
        f.write(ext_encoded)
        f.write(salt)
        f.write(key_hash) 
        f.write(cipher.nonce)
        f.write(tag)
        f.write(ciphertext)    
    
    # Delete original file
    os.remove(file_path)

    print(f"✅ File encrypted and saved as: {encrypted_path}")
    print("🗑️ Original file deleted.")

    return encrypted_path  # Optional: return path of saved file

if __name__ == "__main__":
    path = input("Enter file path: ")
    pw = input("Enter password: ")
    encrypt_file(path, pw)
