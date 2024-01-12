In order to run this User Interface Application, make sure that you have the blowfish.py, twofish.py, re_server.py and re_client.py scripts in the same directory as the file_encryption_app_clientserver.py

Also the python library - tkinter should be installed beforehand for the UI.

To install Tkinter, do
pip install tk

And to verify the installation, boot up the Python Shell and run:
import tkinter 
tkinter._test()


Make sure to install other necessary libraries as well.


NOW,
if you want to encrypt your files (implemented locally), select None when asked for "Are you a Client or Server" and then you may upload a .txt, .png,. wav files to encrypt and store them locally. For text, since outputs aren't too big, the outputs will be shown in the Output Window in the UI otherwise it will show the status of the operation.

but, if you want to use the power of Client Server Model (communication across platform) to send a text message {user input} from a client machine to a server where the server could process it and return the encrypted message back to the client, you may chose Client Radio Button and in another machine hosted on the same network, chose Server.
At the server end, there is no need to check any radio button other than "Server" as the Algorithm and Operations to be used/performed will be sent by the Client.
At the Client end, select the Algorithm you want to use, operation you want to perform, Client as your machine, then type some input in "PlainText" TextBox provided and a hexadecimal key in "Key" TextBox and press Start.

This way, the client can send a plaintext and get it's encrypted ciphertext back from the server and similarly, it may pass the ciphertext and get the decrypted plaintext back.


[POINT TO NOTE: CHANGE THE HOST IP ADDRESS IN THE re_client.py TO THE IP ADDRESS OF THE MACHINE ACTING AS SERVER. TO CHECK THAT, USE COMMAND IPCONFIG(Win) or IFCONFIG(Linux) ON THE SERVER MACHINE TO GET ITS "Wireless LAN adapter Wi-Fi: IPV4 ADDRESS"]