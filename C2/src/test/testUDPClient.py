import socket
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

# For testing, the main program will print out the symmetric key in the beginning, paste it below before running
key = bytes.fromhex("be83247a1f487935796e25a09ae99d14")

message = b"heartbeat"

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


IP = "127.0.0.1"
PORT = 53045

client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client_socket.sendto(build_message(message), (IP, PORT))
