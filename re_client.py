import socket
import time

def run_client(algorithm, operation, key, pltext):
    # Define the server address and port
    # server_address = ('localhost', 12345)
    server_address = ("192.168.201.241", 12345)

    # Create a TCP/IP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect the socket to the server's address and port
    client_socket.connect(server_address)
    print("Connection Established!")
    client_socket.send(algorithm.encode())
    time.sleep(0.1)
    client_socket.send(operation.encode())
    time.sleep(0.1)
    time.sleep(0.1)

    # print(key)
    client_socket.send(key.encode())
    time.sleep(0.1)

    if operation == "encrypt":
        client_socket.send(pltext.encode())
        ciphertext = client_socket.recv(1024).decode()
        print("Encrypted message received from server is:",ciphertext)
        print()
        result = ciphertext
    
    else:
        client_socket.send(pltext.encode())
        decrypted_txt = client_socket.recv(1024).decode()
        print("Decrypted message received from server is:", decrypted_txt)
        print()
        result = decrypted_txt


    client_socket.close()

    return result