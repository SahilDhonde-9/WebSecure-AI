import hashlib

def run():
    print("\n--- [Module 20] Cryptography Tool ---")
    text = input("Enter text to hash: ")
    sha256_hash = hashlib.sha256(text.encode()).hexdigest()
    print(f"[+] SHA-256 Digest: {sha256_hash}")