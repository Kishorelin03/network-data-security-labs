import socket, pickle
from Crypto.Random import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256

p = int("2582249878086908589655919172003011874329705792829223512830659356540647622016841194629645353280137831435903171972747559779")
g = 2

# Start server
s = socket.socket()
s.bind(("localhost", 9999))
s.listen(1)
print("Server waiting for connection...")
conn, addr = s.accept()

# Generate server DH keys
b = random.getrandbits(400)
B = pow(g, b, p)
conn.send(str(B).encode())

# Receive client's DH public key
A = int(conn.recv(2048).decode())
shared = pow(A, b, p)
print(f"Shared secret: {shared}")

# Hash to get 32-byte AES key
sk = SHA256.new(str(shared).encode()).digest()
print(f"AES Key (sk): {sk.hex()}")

# Receive (ciphertext, tag)
data = conn.recv(4096)
ciphertext, tag = pickle.loads(data)

# Verify tag
if SHA256.new(ciphertext).digest() != tag:
    raise Exception("Tag verification failed!")

# Decrypt message
cipher = AES.new(sk, AES.MODE_CBC, iv=ciphertext[:16])
plaintext = unpad(cipher.decrypt(ciphertext[16:]), AES.block_size)
print(f"Decrypted message: {plaintext.decode()}")
