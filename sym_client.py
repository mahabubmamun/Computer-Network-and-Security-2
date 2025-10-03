import socket, struct, json, os
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HOST = '127.0.0.1'
PORT = 50000

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

def derive_aes_key(shared_bytes, length=32):
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=b'handshake')
    return hkdf.derive(shared_bytes)

def aes_encrypt(key, iv, plaintext):
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    enc = cipher.encryptor()
    return enc.update(plaintext) + enc.finalize()

def aes_decrypt(key, iv, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    dec = cipher.decryptor()
    return dec.update(ciphertext) + dec.finalize()

def main():
    with socket.socket() as s:
        s.connect((HOST, PORT))
        params = json.loads(recv_msg(s).decode())
        p, g = int(params['p']), int(params['g'])
        server_pub_y = int(recv_msg(s).decode())

        # Client keys
        pn = dh.DHParameterNumbers(p, g)
        parameters = pn.parameters()
        client_private_key = parameters.generate_private_key()
        client_pub_y = client_private_key.public_key().public_numbers().y
        send_msg(s, str(client_pub_y).encode())

        # Server public key
        server_pub_key = dh.DHPublicNumbers(server_pub_y, pn).public_key()

        shared_key = client_private_key.exchange(server_pub_key)
        aes_key = derive_aes_key(shared_key)
        print(f"[Client] Derived AES key (hex): {aes_key.hex()}")

        # Encrypt and send
        iv = os.urandom(16)
        message = b"Hello from symmetric client"
        print(f"[Client] Actual plaintext to send: {message.decode()}")
        ct = aes_encrypt(aes_key, iv, message)
        print(f"[Client] Sending ciphertext (hex): {ct.hex()}")
        send_msg(s, iv + ct)

        # Receive reply
        enc_reply = recv_msg(s)
        iv2, ct2 = enc_reply[:16], enc_reply[16:]
        print(f"[Client] Received ciphertext (hex): {ct2.hex()}")
        plaintext = aes_decrypt(aes_key, iv2, ct2)
        print(f"[Client] After decryption, server replied: {plaintext.decode()}")

if __name__ == "__main__":
    main()