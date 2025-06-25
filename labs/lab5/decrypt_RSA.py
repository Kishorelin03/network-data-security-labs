from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Load private key (converted to PKCS#8 without passphrase)
with open("private8.pem", "rb") as f:
    private_key = RSA.import_key(f.read())

# Load the ciphertext
with open("ciphertext.bin", "rb") as f:
    ciphertext = f.read()

# Decrypt using RSA PKCS1_OAEP
cipher = PKCS1_OAEP.new(private_key)
message = cipher.decrypt(ciphertext)

# Print the decrypted message
print("Decrypted message:", message.decode())

