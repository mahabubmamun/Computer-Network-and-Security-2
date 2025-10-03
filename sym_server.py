import socket, struct, json, os
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HOST = '127.0.0.1'
PORT = 50000

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
    parameters = dh.generate_parameters(generator=2, key_size=2048) 
    param_nums = parameters.parameter_numbers()
    p, g = param_nums.p, param_nums.g

    with socket.socket() as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(1)
        print(f"[Server] Listening on {HOST}:{PORT} ...")
        conn, addr = s.accept()
        with conn:
            print("[Server] Client connected:", addr)

            # Send parameters and server public number
            send_msg(conn, json.dumps({'p': str(p), 'g': str(g)}).encode())
            server_private_key = parameters.generate_private_key()
            server_pub_y = server_private_key.public_key().public_numbers().y
            send_msg(conn, str(server_pub_y).encode())

            # Receive client public number
            client_pub_y = int(recv_msg(conn).decode())
            pn = dh.DHParameterNumbers(p, g)
            client_pub_key = dh.DHPublicNumbers(client_pub_y, pn).public_key()

            # Shared secret and AES key
            shared_key = server_private_key.exchange(client_pub_key)
            aes_key = derive_aes_key(shared_key)
            print(f"[Server] Derived AES key (hex): {aes_key.hex()}")

            # Receive encrypted message
            enc_blob = recv_msg(conn)
            iv, ciphertext = enc_blob[:16], enc_blob[16:]
            print(f"[Server] Received ciphertext (hex): {ciphertext.hex()}")
            plaintext = aes_decrypt(aes_key, iv, ciphertext)
            print(f"[Server] After decryption, client said: {plaintext.decode()}")

            # Prepare and send reply
            reply = b"Server received your message: " + plaintext
            print(f"[Server] Actual reply plaintext: {reply.decode()}")
            iv2 = os.urandom(16)
            ct2 = aes_encrypt(aes_key, iv2, reply)
            print(f"[Server] Sending ciphertext (hex): {ct2.hex()}")
            send_msg(conn, iv2 + ct2)

if __name__ == "__main__":
    main()
