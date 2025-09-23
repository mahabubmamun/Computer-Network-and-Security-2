import socket
import os
import struct
from cryptography.hazmat.primitives.asymmetric import dh, rsa, padding
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
    return iv + ciphertext  # prepend IV

def decrypt_message(key, ciphertext):
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ct) + decryptor.finalize()

# ---------------------- Socket Server ----------------------
def main():
    HOST = "127.0.0.1"
    PORT = 4000

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(1)
    print(f"[SERVER] Listening on {HOST}:{PORT}")

    conn, addr = server.accept()
    print(f"[SERVER] Connected by {addr}")

    # ----------- Diffie-Hellman Key Exchange -----------
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    params = parameters.parameter_numbers()

    # Send p and g
    send_msg(conn, str(params.p).encode())
    send_msg(conn, str(params.g).encode())

    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()

    # Send server DH public key
    server_pub_bytes = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    send_msg(conn, server_pub_bytes)

    # Receive client DH public key
    client_pub_bytes = recv_msg(conn)
    client_public_key = serialization.load_pem_public_key(client_pub_bytes)

    # Shared secret
    shared_key = private_key.exchange(client_public_key)

    # Derive AES key
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"handshake data",
    ).derive(shared_key)
    print("[SERVER] AES key derived")

    # ----------- RSA Keys -----------
    rsa_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_public = rsa_private.public_key()

    rsa_pub_bytes = rsa_public.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    send_msg(conn, rsa_pub_bytes)
    print("[SERVER] RSA public key sent to client")

    # ----------- Receive Encrypted Message -----------
    encrypted_msg = recv_msg(conn)
    decrypted_msg = decrypt_message(derived_key, encrypted_msg)
    print(f"[SERVER] Received (decrypted): {decrypted_msg.decode(errors='ignore')}")

    # ----------- Signing -----------
    data_to_sign = recv_msg(conn)
    signature = rsa_private.sign(
        data_to_sign,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    send_msg(conn, signature)
    print("[SERVER] Signature sent to client")

    conn.close()

if __name__ == "__main__":
    main()
