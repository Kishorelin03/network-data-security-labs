from Crypto.Signature import pss
from Crypto.Hash import SHA512
from Crypto.PublicKey import RSA

message = b"I owe you $3000"

# Load public key
with open("public.pem", "rb") as f:
    public_key = RSA.import_key(f.read())

# Hash the message
hashed_msg = SHA512.new(message)

# Load signature
with open("signature.bin", "rb") as f:
    signature = f.read()

# Create PSS verifier
verifier = pss.new(public_key)

try:
    verifier.verify(hashed_msg, signature)
    print("✅ Signature is valid.")
except (ValueError, TypeError):
    print("❌ Signature is invalid.")
