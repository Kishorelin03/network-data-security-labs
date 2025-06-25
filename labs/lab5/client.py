import socket, pickle
from Crypto.Random import random, get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Hash import SHA256

p = int("2582249878086908589655919172003011874329705792829223512830659356540647622016841194629645353280137831435903171972747559779")
g = 2

# Connect to server
s = socket.socket()
s.connect(("localhost", 9999))

# Receive server's public key
B = int(s.recv(2048).decode())

# Generate client DH keys
a = random.getrandbits(400)
A = pow(g, a, p)
s.send(str(A).encode())

# Compute shared secret
shared = pow(B, a, p)
print(f"Shared secret: {shared}")

# Hash to get 32-byte AES key
sk = SHA256.new(str(shared).encode()).digest()
print(f"AES Key (sk): {sk.hex()}")

# Message to send
message = b"Hello from client!"

# Encrypt message
iv = get_random_bytes(16)
cipher = AES.new(sk, AES.MODE_CBC, iv)
ciphertext = iv + cipher.encrypt(pad(message, AES.block_size))

# Tag = SHA256(ciphertext)
tag = SHA256.new(ciphertext).digest()

# Send (ciphertext, tag)
s.send(pickle.dumps((ciphertext, tag)))
print("Encrypted message sent!")
