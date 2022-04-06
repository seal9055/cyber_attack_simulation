import socket
import base64
import sys
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# For testing, the main program will print out the symmetric key in the beginning, paste it below before running

if len(sys.argv) != 2:
    print("USAGE: python3 "+sys.argv[0]+" ENCRYPTION_KEY")
    sys.exit(1)


key = bytes.fromhex(sys.argv[1])

heartbeat_message = b"heartbeat"

node_id = 69420


def build_message(message):
    message_encoded = base64.b64encode(message)
    pre_aes = str(node_id) + "_" + message_encoded.decode()
    plaintext = pre_aes.encode()
    nonce = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, nonce)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    nonce_encoded = base64.b64encode(nonce).decode()
    ciphertext_encoded = base64.b64encode(ciphertext).decode()
    final_output = nonce_encoded + "_" + ciphertext_encoded
    return final_output.encode()


def deconstruct_message(message):
    nonce_encoded, ciphertext_encoded = message.decode().strip().split("_")
    nonce = base64.b64decode(nonce_encoded)
    ciphertext = base64.b64decode(ciphertext_encoded)
    cipher = AES.new(key, AES.MODE_CBC, nonce)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode()


IP = "127.0.0.1"
PORT = 53045

client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client_socket.sendto(build_message(heartbeat_message), (IP, PORT))
recv = client_socket.recvfrom(4096)
print(recv)
plaintext = deconstruct_message(recv[0])
print(plaintext)
if plaintext.strip() == 'uninstall':
    client_socket.sendto(build_message(b"uninstall ack"), (IP, PORT))
client_socket.close()
