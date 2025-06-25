from Crypto.Signature import pss
from Crypto.Hash import SHA512
from Crypto.PublicKey import RSA

message = b"I owe you $3000"

# Load private key
with open("private8.pem", "rb") as f:
    private_key = RSA.import_key(f.read())

# Hash the message
hashed_msg = SHA512.new(message)

# Create PSS signer and sign
signer = pss.new(private_key)
signature = signer.sign(hashed_msg)

# Save signature to file
with open("signature.bin", "wb") as f:
    f.write(signature)

print("✅ Signature created and saved as signature.bin.")
