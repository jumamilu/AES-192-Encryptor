import sys
import os
import hashlib
from Crypto.Cipher import AES

# Add parent folder to path for key_derivation module
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from key_derivation.derive_key import derive_key, is_valid_password

def decrypt_file(encrypted_file_path, password):
    if not os.path.isfile(encrypted_file_path):
        print("❌ Encrypted file does not exist.")
        return

    # Step 1: Read encrypted file
    with open(encrypted_file_path, 'rb') as f:
        data = f.read()

    if len(data) < 44:
        print("❌ Encrypted file is too small or corrupted.")
        return

    # Step 2: Parse structure
    ext_encoded = data[:10]
    salt = data[10:26] 
    stored_key_hash = data[26:42]              # 16 bytes
    nonce = data[42:54]            # 12 bytes
    tag = data[54:70]              # 16 bytes
    ciphertext = data[70:]         # remaining bytes

    original_ext = ext_encoded.rstrip(b'\x00').decode('utf-8')
    
    # Debug info
    
    print("Decryption salt (hex):", salt.hex())
    print("Nonce (hex):", nonce.hex())
    print("Tag (hex):", tag.hex())
    print("Ciphertext size:", len(ciphertext))

    # Step 3: Validate password and derive key using same salt
    if not is_valid_password(password):
        raise ValueError("Invalid password format. Must be at least 8 characters with letters, digits, and punctuation.")

    key, _ = derive_key(password, salt)

    # Debug info
    print("Decryption salt (hex):", salt.hex())
    print("Decryption derived key SHA-256:", hashlib.sha256(key).hexdigest())
    
    derived_key_hash = hashlib.sha256(key).digest()[:16]
    if stored_key_hash != derived_key_hash:
        raise ValueError("❌ Invalid password.")
        
    
    # key, _ = derive_key(password, salt)
    # print("Decryption derived key hash:", hashlib.sha256(key).hexdigest())

    # Step 4: Decrypt
    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        print("❌ File integrity check failed (file was modified).")
        return
    
    except Exception as e:
        print(f"⚠️ Unexpected error: {e}")
        return

    # Step 5: Save decrypted file
    decrypted_path = os.path.splitext(encrypted_file_path)[0] + original_ext
    with open(decrypted_path, 'wb') as f:
        f.write(plaintext)

    try:
        os.remove(encrypted_file_path)
        print("🗑️ Encrypted .jet file deleted.")
    except Exception as e:
        print(f"⚠️ Failed to delete encrypted file: {e}")
        
    print(f"✅ Decryption successful! File saved as: {decrypted_path}")

if __name__ == "__main__":
    enc_path = input("Enter path to .jet encrypted file: ")
    pw = input("Enter password for decryption: ")
    decrypt_file(enc_path, pw)
