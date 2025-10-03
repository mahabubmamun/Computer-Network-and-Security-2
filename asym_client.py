
import socket, struct
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

HOST = '127.0.0.1'
PORT = 50010

def send_msg(sock, data):
    sock.sendall(struct.pack('!I', len(data)) + data)

def recv_msg(sock):
    raw_len = sock.recv(4)
    if not raw_len:
        return None
    length = struct.unpack('!I', raw_len)[0]
    data = b''
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise ConnectionError("Socket closed")
        data += chunk
    return data

def main():
    with socket.socket() as s:
        s.connect((HOST, PORT))

        # Receive server public key
        public_pem = recv_msg(s)
        print("[Client] Received server public key (PEM):")
        print(public_pem.decode())
        public_key = serialization.load_pem_public_key(public_pem)

        # Message to sign
        message = b"This message will be signed by the server."
        print(f"[Client] Actual plaintext message to send: {message.decode()}")
        send_msg(s, message)
        print("[Client] Sent message for signing.")

        # Receive signature
        signature = recv_msg(s)
        print(f"[Client] Received signature (hex): {signature.hex()}")
        print("[Client] Verifying signature...")

        try:
            public_key.verify(
                signature,
                message,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            print("[Client] Signature is valid. Message verified.")
        except Exception as e:
            print("[Client] Signature verification failed:", e)

if __name__ == "__main__":
    main()