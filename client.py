import socket
import os
import struct
from cryptography.hazmat.primitives.asymmetric import dh, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ---------------------- Helper Functions ----------------------
def send_msg(sock, data: bytes):
    sock.sendall(struct.pack(">I", len(data)) + data)

def recv_msg(sock):
    raw_len = recvall(sock, 4)
    if not raw_len:
        return None
    msg_len = struct.unpack(">I", raw_len)[0]
    return recvall(sock, msg_len)

def recvall(sock, n):
    data = b""
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

def encrypt_message(key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv + ciphertext

def decrypt_message(key, ciphertext):
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ct) + decryptor.finalize()

# ---------------------- Socket Client ----------------------
def main():
    HOST = "127.0.0.1"
    PORT = 4000

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((HOST, PORT))
    print("[CLIENT] Connected to server")

    # ----------- Receive DH Parameters -----------
    p = int(recv_msg(client).decode())
    g = int(recv_msg(client).decode())
    dh_parameters = dh.DHParameterNumbers(p, g).parameters()

    # ----------- Receive Server DH Public Key -----------
    server_pub_bytes = recv_msg(client)
    server_public_key = serialization.load_pem_public_key(server_pub_bytes)

    # ----------- Generate Client Keys -----------
    private_key = dh_parameters.generate_private_key()
    public_key = private_key.public_key()

    client_pub_bytes = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    send_msg(client, client_pub_bytes)

    # Shared secret
    shared_key = private_key.exchange(server_public_key)

    # Derive AES key
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"handshake data",
    ).derive(shared_key)
    print("[CLIENT] AES key derived")

    # ----------- Receive RSA Public Key -----------
    rsa_pub_bytes = recv_msg(client)
    rsa_public = serialization.load_pem_public_key(rsa_pub_bytes)
    print("[CLIENT] Received RSA public key")

    # ----------- Send Encrypted Message -----------
    plaintext = b"Hello secure server!"
    encrypted_msg = encrypt_message(derived_key, plaintext)
    send_msg(client, encrypted_msg)
    print(f"[CLIENT] Sent encrypted message: {plaintext.decode()}")

    # ----------- Signing Verification -----------
    data = b"Verify this message"
    send_msg(client, data)

    signature = recv_msg(client)
    try:
        rsa_public.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("[CLIENT] Signature verified ✅")
    except Exception as e:
        print("[CLIENT] Signature verification failed ❌", e)

    client.close()

if __name__ == "__main__":
    main()
