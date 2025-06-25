from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Load public key
with open("public.pem", "rb") as f:
    public_key = RSA.import_key(f.read())

cipher = PKCS1_OAEP.new(public_key)
message = b'Kishorelin Aruldhas Mabelclarabai 110159981'  # Replace with your actual name and ID
ciphertext = cipher.encrypt(message)

# Save ciphertext
with open("ciphertext.bin", "wb") as f:
    f.write(ciphertext)
