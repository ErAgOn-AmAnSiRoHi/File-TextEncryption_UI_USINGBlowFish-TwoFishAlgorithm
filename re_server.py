import socket
from blowfish import encryption, decryption
from twofish import encrypt,decrypt
import binascii


def blowfish_encrypt(key,plaintext):
    encrypt_bytes = plaintext.encode('utf-8')
    # Process the input data in 64-bit blocks
    encrypted_data = b''
    for i in range(0, len(encrypt_bytes), 8):
        block = encrypt_bytes[i:i+8].ljust(8, b'\x00')  # Pad to 8 bytes if needed
        block_data = int.from_bytes(block, byteorder='big')
        encrypted_block = encryption(block_data)
        encrypted_data += encrypted_block.to_bytes(8, byteorder='big')
    output = binascii.hexlify(encrypted_data)
    return output

def blowfish_decrypt(key,encrypted_text):
    encrypted_data = binascii.unhexlify(encrypted_text)
    decrypted_data = b''
    for i in range(0, len(encrypted_data), 8):
        block = encrypted_data[i:i+8]
        block_data = int.from_bytes(block, byteorder='big')
        decrypted_block = decryption(block_data)
        decrypted_data += decrypted_block.to_bytes(8, byteorder='big')
    decrypted_data = decrypted_data.decode('utf-8').rstrip('\x00')
    return decrypted_data


# def twofish_encrypt():
#     pass
# def twofish_decrypt():
#     pass

def twofish_encrypt(text, key):
    # Convert the plaintext to hexadecimal
    text = text.encode('utf-8').hex()
    # Check if length of message is more than 32 bytes, if yes then create blocks of 32 bytes and encrypt them
    if(len(text)>32):
        text_blocks = [text[i:i+32] for i in range(0,len(text),32)]
        # Now encrypt each block , check if size of block is less than 32 bytes, then pad the block with null bytes and then encrypt it
        ciphertext_blocks = []
        for block in text_blocks:
            if(len(block)<32):
                block = block.zfill(32)
            ciphertext_blocks.append(encrypt(block,key))
        ciphertext = ''.join(ciphertext_blocks)
        return ciphertext
    else:
        text = text.zfill(32)
        ciphertext = encrypt(text, key)
        return ciphertext
    
def twofish_decrypt(ciphertext, key):
    if(len(ciphertext)>32):
        ciphertext_blocks = [ciphertext[i:i+32] for i in range(0,len(ciphertext),32)]
        # Now decrypt each block and decrypt each into alphabet string and then store it in a list using bytes.fromhex().decode('utf-8')
        decrypted_blocks = []
        for block in ciphertext_blocks:
            decrypted_blocks.append(bytes.fromhex(decrypt(block,key)).decode('utf-8'))
        # Remove the padding from each decrypted block
        decrypted_blocks = [block.lstrip('\x00') for block in decrypted_blocks]
        decrypted_txt = ''.join(decrypted_blocks)
        # Send the plaintext to client
    # If length of message is less than 32 bytes then decrypt it
    else:
# Normal decryption
        decrypted_txt = decrypt(ciphertext,key)
        # Convert the decrypted text from hex to character string
        decrypted_txt = bytes.fromhex(decrypted_txt).decode('utf-8')
        # remove the padding from the decrypted text
        decrypted_txt = decrypted_txt.lstrip('\x00')
    return decrypted_txt

def run_server():
    # Define the server address and port
    # host = socket.gethostbyname(socket.gethostname())
    host = gethost()
    port = 12345
    server_address = (host, port)

    # Create a TCP/IP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to the server address
    server_socket.bind(server_address)

    # Listen for incoming connections
    server_socket.listen(2)

    print(f"Server listening on {server_address}")

    # while True:
        # Wait for a connection
    print("Waiting for a connection...")
    connection, client_address = server_socket.accept()
    
    algorithm = connection.recv(1024).decode()
    operation = connection.recv(1024).decode()
    key = connection.recv(1024).decode()
    print(algorithm)
    print(operation)
    print(key)
    
    if algorithm == "blowfish":
        if operation == "encrypt":
            plaintext = connection.recv(1024).decode()
            encrypted_text = blowfish_encrypt(key,plaintext)
            connection.sendall(encrypted_text)
        else:
            encrypted_text = connection.recv(1024).decode()
            decrypted_text = blowfish_decrypt(key,encrypted_text)
            connection.sendall(decrypted_text.encode())
    else:
        if operation == "encrypt":    
            plaintext = connection.recv(1024).decode()
            encrypted_text = twofish_encrypt(plaintext, key)
            connection.sendall(encrypted_text.encode())
        else:
            encrypted_text = connection.recv(1024).decode()
            decrypted_text = twofish_decrypt(encrypted_text, key)
            connection.sendall(decrypted_text.encode())


    connection.close()

def gethost():
  """Returns the IPv4 address of the wireless LAN adapter."""
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  s.connect(("8.8.8.8", 80))
  ip_address = s.getsockname()[0]
  s.close()
  return ip_address