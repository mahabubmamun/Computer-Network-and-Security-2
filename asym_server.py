import socket, struct
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

HOST = '127.0.0.1'
PORT = 50010

def send_msg(conn, data):
    conn.sendall(struct.pack('!I', len(data)) + data)

def recv_msg(conn):
    raw_len = conn.recv(4)
    if not raw_len:
        return None
    length = struct.unpack('!I', raw_len)[0]
    data = b''
    while len(data) < length:
        chunk = conn.recv(length - len(data))
        if not chunk:
            raise ConnectionError("Socket closed")
        data += chunk
    return data

def main():
    # Generate RSA keypair
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with socket.socket() as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(1)
        print(f"[Server] RSA server listening on {HOST}:{PORT}")
        conn, addr = s.accept()
        with conn:
            print("[Server] Client connected:", addr)

            # Send public key
            send_msg(conn, public_pem)
            print("[Server] Sent public key to client (PEM):")
            print(public_pem.decode())

            # Receive message to sign
            msg = recv_msg(conn)
            print(f"[Server] Received message to sign: {msg.decode()}")

            # Create signature
            signature = private_key.sign(
                msg,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            print(f"[Server] Signature (hex): {signature.hex()}")

            # Send signature back
            send_msg(conn, signature)
            print("[Server] Signature sent back to client.")

if __name__ == "__main__":
    main()