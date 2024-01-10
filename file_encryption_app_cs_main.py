import tkinter as tk
from tkinter import filedialog
from tkinter import ttk
import time
from PIL import Image
import wave
import numpy as np
from threading import Thread
import subprocess
from blowfish import encryption, decryption
import binascii
from concurrent.futures import ThreadPoolExecutor
from twofish import encrypt, decrypt
from re_client import run_client
from re_server import run_server


def process_video_frames(frame, encryption_func):
    frame_bytes = frame.tobytes()
    encrypted_frame_bytes = b''
    for i in range(0, len(frame_bytes), 8):
        block = frame_bytes[i:i + 8].ljust(8, b'\x00')
        block_data = int.from_bytes(block, byteorder='big')
        encrypted_block = encryption_func(block_data)
        encrypted_frame_bytes += encrypted_block.to_bytes(8, byteorder='big')
    return encrypted_frame_bytes


class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("CRYPTOGRAPHIC ALGORITHMS")
        # self.root.configure(bg="#010117")
        self.root.configure(bg="#010117")

        # Maximize the window
        self.root.state("zoomed")

        tk.Label(root, text="", bg="#010117").pack()

                # Add a big heading
        big_heading = tk.Label(root, text="BlowFish and TwoFish", font=("Helvetica", 25), bg="#010117", fg="white")
        big_heading.pack(pady=20)

        tk.Label(root, text="", bg="#010117").pack()
        tk.Label(root, text="", bg="#010117").pack()
        tk.Label(root, text="", bg="#010117").pack()
        tk.Label(root, text="", bg="#010117").pack()

        
        # Encryption/Decryption section
        encrypt_decrypt_frame = tk.Frame(root)
        encrypt_decrypt_frame.pack()

        # Move mode creation here
        self.mode = tk.StringVar()
        self.mode.set("Encrypt")

        # Top horizontal line for Encryption/Decryption
        encrypt_decrypt_label = tk.Label(encrypt_decrypt_frame, text="Choose Operation:")
        encrypt_decrypt_label.grid(row=0, column=0, columnspan=2)

        self.encrypt_decrypt_var = tk.StringVar()
        encrypt_radio = tk.Radiobutton(encrypt_decrypt_frame, text="Encrypt", variable=self.encrypt_decrypt_var, value="Encrypt")
        encrypt_radio.grid(row=1, column=0)

        decrypt_radio = tk.Radiobutton(encrypt_decrypt_frame, text="Decrypt", variable=self.encrypt_decrypt_var, value="Decrypt")
        decrypt_radio.grid(row=1, column=1)

        # Create a space between the two horizontal lines
        tk.Label(root, text="", bg="#010117").pack()
        tk.Label(root, text="", bg="#010117").pack()

        # Bottom horizontal line for Algorithm
        algorithm_frame = tk.Frame(root)
        algorithm_frame.pack()

        algorithm_label = tk.Label(algorithm_frame, text="Choose Algorithm:")
        algorithm_label.grid(row=0, column=0, columnspan=2)

        self.algorithm_var = tk.StringVar()
        blowfish_radio = tk.Radiobutton(algorithm_frame, text="Blowfish", variable=self.algorithm_var, value="BlowFish")
        blowfish_radio.grid(row=1, column=0)

        twofish_radio = tk.Radiobutton(algorithm_frame, text="Twofish", variable=self.algorithm_var, value="TwoFish")
        twofish_radio.grid(row=1, column=1)

        # Create a space between the two horizontal lines
        tk.Label(root, text="", bg="#010117").pack()
        tk.Label(root, text="", bg="#010117").pack()


        # Bottom horizontal line for Client-Server Model
        client_server_frame = tk.Frame(root)
        client_server_frame.pack()

        client_server_label = tk.Label(client_server_frame, text="Are you Client or Server: ")
        client_server_label.grid(row=0, column=0, columnspan=3)

        self.client_server_var = tk.StringVar()
        client_radio = tk.Radiobutton(client_server_frame, text="Client", variable=self.client_server_var, value="Client")
        client_radio.grid(row=1, column=0)

        server_radio = tk.Radiobutton(client_server_frame, text="Server", variable=self.client_server_var, value="Server")
        server_radio.grid(row=1, column=1)

        none_radio = tk.Radiobutton(client_server_frame, text="None", variable=self.client_server_var, value="None")
        none_radio.grid(row=1, column=2)


        # Create a space between the two horizontal lines
        tk.Label(root, text="", bg="#010117").pack()
        tk.Label(root, text="", bg="#010117").pack()



        # File paths
        file_frame = tk.Frame(root)
        file_frame.pack()

        input_file_label = tk.Label(file_frame, text="File:")
        input_file_label.pack(side=tk.LEFT)

        self.input_file_entry = tk.Entry(file_frame)
        self.input_file_entry.pack(side=tk.LEFT)

        browse_input_button = tk.Button(file_frame, text="Browse...", command=self.select_input_file)
        browse_input_button.pack(side=tk.LEFT)

        # Add space between the two sections
        tk.Label(file_frame, text="   ").pack(side=tk.LEFT)

        output_file_label = tk.Label(file_frame, text="Output:")
        output_file_label.pack(side=tk.LEFT)

        self.output_file_entry = tk.Entry(file_frame)
        self.output_file_entry.pack(side=tk.LEFT)

        browse_output_button = tk.Button(file_frame, text="Browse...", command=self.save_blowfish_result)
        browse_output_button.pack(side=tk.LEFT)

                # Create a space between the two horizontal lines
        tk.Label(root, text="", bg="#010117").pack()


        # Key section
        text_frame = tk.Frame(root)
        text_frame.pack()

        text_label = tk.Label(text_frame, text="PlainText: ")
        text_label.pack(side=tk.LEFT)

        self.text = tk.StringVar()
        self.text_entry = tk.Entry(text_frame, textvariable=self.text)
        self.text_entry.pack(side=tk.LEFT)

                # Create a space between the two horizontal lines
        tk.Label(root, text="", bg="#010117").pack()

        # Key section
        key_frame = tk.Frame(root)
        key_frame.pack()

        key_label = tk.Label(key_frame, text="Key (Hexa):")
        key_label.pack(side=tk.LEFT)

        self.key = tk.StringVar()
        self.key_entry = tk.Entry(key_frame, textvariable=self.key)
        self.key_entry.pack(side=tk.LEFT)

        # key_show_button = tk.Button(key_frame, text="Show key", command=self.show_key)
        # key_show_button.pack(side=tk.LEFT)

        
                # Create a space between the two horizontal lines
        tk.Label(root, text="", bg="#010117").pack()
        
        # Info section
        # info_frame = tk.Frame(root)
        # info_frame.pack()

        # Timer section
        # timer_frame = tk.Frame(root)
        # timer_frame.pack()

        # timer_label = tk.Label(timer_frame, text="Timer:")
        # timer_label.pack(side=tk.LEFT)

        # self.timer_display = tk.Label(timer_frame, text="0:00:00")
        # self.timer_display.pack(side=tk.LEFT)

        # # Add space between the two sections
        # tk.Label(timer_frame, text="   ").pack(side=tk.LEFT, ipadx=0, ipady=0)


                # Create a space between the two horizontal lines
        # tk.Label(root, text="", bg="#010117").pack()


        # Buttons
        button_frame = tk.Frame(root)
        button_frame.pack()

        start_button = tk.Button(button_frame, text="Start", command=self.start)
        start_button.pack(side=tk.LEFT)

        # stop_button = tk.Button(button_frame, text="Stop", command=self.stop)
        # stop_button.pack(side=tk.LEFT)



                        # Create a space between the two horizontal lines
        tk.Label(root, text="", bg="#010117").pack()

        

                # Output section
        output_frame = tk.Frame(root)
        output_frame.pack()

        output_label = tk.Label(output_frame, text="Output:")
        output_label.pack(side=tk.LEFT)

        self.output_text = tk.Text(output_frame, height=5, width=40)
        self.output_text.pack(side=tk.LEFT)

        #         # Subheading at the bottom right corner
        # subheading_label = tk.Label(root, text="Created By:-\nAman Sirohi\n[CB.EN.U4AIE21003]", font=("Helvetica", 10), bg="#010117", fg="#4b4b4d")
        # subheading_label.pack(side=tk.RIGHT, anchor=tk.SE, padx=20, pady=20)



    def select_input_file(self):
        filename = filedialog.askopenfilename()
        self.input_file_entry.delete(0, tk.END)
        self.input_file_entry.insert(0, filename)

    def start(self):
        # Get the chosen operation (Encrypt/Decrypt)
        operation = self.encrypt_decrypt_var.get().lower()

        # Get the chosen algorithm
        algorithm = self.algorithm_var.get().lower()

        # Get the chosen machine (client/server)
        machine = self.client_server_var.get()

        # Get the key (required for TwoFish)
        # key_value = self.key.get() if algorithm == "twofish" else " "
        key_value = self.key.get()
        # print(key_value)
        # print(type(key_value))

        # Take Input PlainText
        text_value = self.text.get()


        # Get the input file path
        input_file_path = self.input_file_entry.get()

        # Get the output file path
        output_file_path = self.output_file_entry.get()

        # Start the encryption/decryption process in a separate thread
        # if machine == "None":
        #     self.process_thread = Thread(target=self.run_algorithm, args=(operation, algorithm, machine, key_value, input_file_path, output_file_path))
        # else:
        #     self.process_thread = Thread(target=self.clientserver, args=(operation, algorithm, machine, key_value, text_value))
        self.process_thread = Thread(target=self.commonfunc, args=(operation, algorithm, machine, key_value, text_value, input_file_path, output_file_path))

        self.process_thread.start()
    # def stop(self):
    #     # Stop the encryption/decryption process
    #     pass
    
    def commonfunc(self, operation, algorithm, machine, key_value, input_text, input_file_path, output_file_path):
        if machine == "None":
            self.run_algorithm(operation, algorithm, machine, key_value, input_file_path, output_file_path)
        else:
            self.clientserver(operation, algorithm, machine, key_value, input_text)  

    def clientserver(self, operation, algorithm, machine, key_value, input_text):
        if machine == "Client":
            output = run_client(algorithm, operation, key_value, input_text)
            self.show_output_cs(output)
        elif machine == "Server":
            output = run_server()
            print(operation)
            self.show_output_cs("Operation Successful")
        else:
            pass


    def run_algorithm(self, operation, algorithm, machine, key, input_file, output_file):
        try:
            if algorithm == "blowfish":
                    # Check for the extension of the file, if it is .txt then use the twofish algorithm directly
                if input_file[-4:] == ".txt":
                    if operation == "encrypt":
                        # Use Blowfish encryption directly
                        with open(input_file, "r") as file:
                            plaintext = file.read()
                        encrypt_bytes = plaintext.encode('utf-8')  # Convert string to bytes

                        # Process the input data in 64-bit blocks
                        encrypted_data = b''
                        for i in range(0, len(encrypt_bytes), 8):
                            block = encrypt_bytes[i:i + 8].ljust(8, b'\x00')  # Pad to 8 bytes if needed
                            block_data = int.from_bytes(block, byteorder='big')
                            encrypted_block = encryption(block_data)
                            encrypted_data += encrypted_block.to_bytes(8, byteorder='big')
                        output = binascii.hexlify(encrypted_data).decode()
                        self.display_output(output, operation)    
                        # # self.blowfish_result = binascii.hexlify(encrypted_data).decode()
                        # self.root.after(0, self.display_output,
                        #                f"Encrypted data: {binascii.hexlify(encrypted_data).decode()}")

                    elif operation == "decrypt":
                        # Read the ciphertext from the input file
                        with open(input_file, "r") as file:
                            ciphertext = file.read().strip()
                        # ciphertext = ciphertext.hex()
                        # print(ciphertext)
                        # Perform Blowfish decryption 
                        decrypted_data = b''
                        for i in range(0, len(ciphertext), 16):  # Assuming ciphertext is in hexadecimal format
                            block = bytes.fromhex(ciphertext[i:i + 16])
                            block_data = int.from_bytes(block, byteorder='big')
                            decrypted_block = decryption(block_data)
                            decrypted_data += decrypted_block.to_bytes(8, byteorder='big')
                            # decrypted_data += decrypted_block
                        # print(type(decrypted_block)) # should be int
                        # print(type(decrypted_data)) # should be bytes
                        # Convert decrypted bytes to string
                        decrypted_text = decrypted_data.decode('utf-8').rstrip('\x00')
                        # Display the decrypted output in the Text widget
                        self.display_output(decrypted_text, operation)
                        # self.root.after(0, self.display_output, decrypted_text)

                        # Allow the user to save the decrypted output to a file
                        # self.root.after(0, self.save_result)

                elif input_file[-4:] == ".png" or input_file[-4:] == ".jpg":
                    with Image.open(input_file) as img:
                        img_data = img.tobytes()
                        img_size = img.size
                        img_mode = img.mode
                    # def write_image(file_path, data, size, mode):
                    #     with Image.frombytes(mode, size, data) as img:
                    #         img.save(file_path)
                    if operation == "encrypt":
                        encrypted_data = bytearray()
                        for i in range(0, len(img_data), 8):
                            block = img_data[i:i + 8].ljust(8, b'\x00')
                            block_data = int.from_bytes(block, byteorder='big')
                            encrypted_block = encryption(block_data)
                            encrypted_data.extend(encrypted_block.to_bytes(8, byteorder='big'))
                        encrypted_data = bytes(encrypted_data)
                        encrypted_data = [encrypted_data, img_size, img_mode]
                        self.display_output(encrypted_data, operation)
                        # output_file_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG Files", "*.png")])
                        # if output_file_path:
                        #     write_image(output_file_path, encrypted_data, img_size, img_mode)
                        #     print(f"Image saved to: {output_file_path}")
                    else:
                        decrypted_data = bytearray()
                        for i in range(0, len(img_data), 8):
                            block = img_data[i:i + 8]
                            block_data = int.from_bytes(block, byteorder='big')
                            decrypted_block = decryption(block_data)
                            decrypted_data.extend(decrypted_block.to_bytes(8, byteorder='big'))
                        decrypted_data = bytes(decrypted_data).rstrip(b'\x00')
                        decrypted_data = [decrypted_data, img_size, img_mode]
                        self.display_output(decrypted_data, operation)
                        # output_file_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG Files", "*.png")])
                        # if output_file_path:
                        #     write_image(output_file_path, decrypted_data, img_size, img_mode)
                        #     print(f"Image saved to: {output_file_path}")
                elif input_file[-4:] == ".wav":
                    with wave.open(input_file, 'rb') as audio_file:
                        frames = audio_file.readframes(audio_file.getnframes())
                        params = audio_file.getparams()
                    
                    if operation == "encrypt":
                        encrypted_frames = b''
                        for i in range(0, len(frames), 8):
                            block = frames[i:i + 8].ljust(8, b'\x00')  # Pad to 8 bytes if needed
                            block_data = int.from_bytes(block, byteorder='big')
                            encrypted_block = encryption(block_data)
                            encrypted_frames += encrypted_block.to_bytes(8, byteorder='big')
                        output = [encrypted_frames, params]
                        self.display_output(output, operation)
                    else:
                        decrypted_frames = b''
                        for i in range(0, len(frames), 8):
                            block = frames[i:i + 8]
                            block_data = int.from_bytes(block, byteorder='big')
                            decrypted_block = decryption(block_data)
                            decrypted_frames += decrypted_block.to_bytes(8, byteorder='big')
                        decrypted_frames = decrypted_frames.rstrip(b'\x00')
                        output = [decrypted_frames, params]
                        self.display_output(output, operation)

                # elif input_file[-4:] in [".mp4", ".mov"]:
                #     import moviepy.editor as mp

                #     video = mp.VideoFileClip(input_file)
                    
                #     def process_audio_block(block):
                #         block_data = int.from_bytes(block, byteorder='big')
                #         encrypted_block = encryption(block_data)
                #         return encrypted_block.to_bytes(8, byteorder='big')

                #     # Process video frames in parallel
                #     with ThreadPoolExecutor() as executor:
                #         encrypted_frames = list(executor.map(lambda frame: process_video_frames(frame, encryption), video.iter_frames()))

                #     # Process audio frames
                #     audio_data = video.audio.to_soundarray()
                #     with ThreadPoolExecutor() as executor:
                #         encrypted_audio = list(executor.map(process_audio_block, audio_data))

                #     output_video = mp.CompositeVideoClip([
                #         mp.ImageSequenceClip(encrypted_frames, fps=video.fps),
                #         mp.AudioClip(np.array(encrypted_audio), fps=audio_data.fps)
                #     ])

                #     self.display_output(output_video, operation)


            elif algorithm == "twofish":
                # Check for the extension of the file, if it is .txt then use the twofish algorithm directly
                if input_file[-4:] == ".txt":
                    if operation == "encrypt":
                        # Use TwoFish encryption directly
                        with open(input_file, "r") as file:
                            plaintext = file.read()
                        plaintext = plaintext.encode('utf-8').hex()  # Convert string to hexadecimal
                        if len(plaintext)>32:
                            plaintext_blocks = [plaintext[i:i+32] for i in range(0, len(plaintext), 32)]  # Split into 32-byte blocks
                            ciphertext_blocks = []
                            for block in plaintext_blocks:
                                if len(block) < 32:
                                    block = block.zfill(32)  # Pad to 32 bytes if needed
                                ciphertext_blocks.append(encrypt(block, key))
                            ciphertext = "".join(ciphertext_blocks)
                        else:
                            plaintext = plaintext.zfill(32)  # Pad to 32 bytes if needed
                            ciphertext = encrypt(plaintext, key)
                            
                        # Now display the output in the Text widget
                        self.display_output(ciphertext, operation)
                    elif operation == "decrypt":
                        # Read the ciphertext from the input file
                        with open(input_file, "r") as file:
                            ciphertext = file.read().strip()

                        # Perform TwoFish decryption
                        if len(ciphertext)>32:
                            ciphertext_blocks = [ciphertext[i:i+32] for i in range(0, len(ciphertext), 32)]
                            decrypted_blocks = []
                            for block in ciphertext_blocks:
                                decrypted_blocks.append(bytes.fromhex(decrypt(block, key)).decode('utf-8'))
                            decrypted_blocks = [block.lstrip('\x00') for block in decrypted_blocks]
                            decrypted_txt = "".join(decrypted_blocks)
                        else:
                            decrypted_txt = decrypt(ciphertext, key)
                            decrypted_txt = bytes.fromhex(decrypted_txt).decode('utf-8')
                            decrypted_txt = decrypted_txt.lstrip('\x00')
                        # Display the decrypted output in the Text widget
                        self.display_output(decrypted_txt, operation)
                                              
                elif input_file[-4:] == ".png" or input_file[-4:] == ".jpg":
                    with Image.open(input_file) as img:
                        input_data = img.tobytes()
                        size = img.size
                        mode = img.mode
                    def write_image(file_path, data, size, mode):
                        with Image.frombytes(mode, size, data) as img:
                            img.save(file_path)
                    if operation == "encrypt":
                        # Use TwoFish encryption directly
                        input_data = input_data.hex()
                        ciphertext_blocks = []
                        if len(input_data)>32:
                            input_data_blocks = [input_data[i:i+32] for i in range(0,len(input_data),32)]
                            for block in input_data_blocks:
                                if(len(block)<32):
                                    block = block.zfill(32)
                                ciphertext_blocks.append(encrypt(block,key))
                        else:
                            input_data = input_data.zfill(32)
                            ciphertext_blocks = encrypt(input_data,key)
                        cipher_img = (''.join(ciphertext_blocks))
                        cipher_img = bytes.fromhex(cipher_img)
                        # Ask the user for output file path
                        output_file_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png")])
                        if output_file_path:
                            write_image(output_file_path, cipher_img, size, mode)
                            print("Encryption Successful")
                            print(f"Image saved to: {output_file_path}")
                            
                    else:
                        input_data = input_data.hex()
                        if len(input_data)>32:
                            input_data_blocks = [input_data[i:i+32] for i in range(0,len(input_data),32)]
                            decrypted_blocks = []
                            for block in input_data_blocks:
                                decrypted_blocks.append((decrypt(block,key)))
                            # decrypted_blocks = [block.lstrip('\x00') for block in decrypted_blocks]
                        else:
                            decrypted_img = decrypt(input_data,key)
                        decrypted_img = (''.join(decrypted_blocks))
                        decrypted_img = bytes.fromhex(decrypted_img)
                        # Ask the user for output file path
                        output_file_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png")])
                        if output_file_path:
                            write_image(output_file_path, decrypted_img, size, mode)
                            print("Decryption Successful")
                            print(f"Image saved to: {output_file_path}")
                elif input_file[-4:] == ".wav":
                    with wave.open(input_file, 'rb') as audio_file:
                        frames = audio_file.readframes(-1)
                        params = audio_file.getparams()
                    def write_audio_file(file_path, frames, params):
                        with wave.open(file_path, 'wb') as audio_file:
                            audio_file.setparams(params)
                            audio_file.writeframes(frames)
                    if operation == "encrypt":
                        input_frames = frames.hex()
                        cipher_text_blocks = []
                        if len(input_frames)>32:
                            input_frames_blocks = [input_frames[i:i+32] for i in range(0,len(input_frames),32)]
                            for block in input_frames_blocks:
                                if(len(block)<32):
                                    block = block.zfill(32)
                                cipher_text_blocks.append(encrypt(block,key))
                        else:
                            input_frames = input_frames.zfill(32)
                            cipher_text_blocks = encrypt(input_frames,key)
                        encrypted_frames = (''.join(cipher_text_blocks))
                        encrypted_frames = bytes.fromhex(encrypted_frames)
                        # Ask the user for output file path
                        output_file_path = filedialog.asksaveasfilename(defaultextension=".wav", filetypes=[("WAV files", "*.wav")])
                        if output_file_path:
                            write_audio_file(output_file_path, encrypted_frames, params)
                            print("Encryption Successful")
                            print(f"Audio saved to: {output_file_path}")
                    else:
                        encrypted_frames = frames.hex()
                        if len(encrypted_frames)>32:
                            encrypted_frames = [encrypted_frames[i:i+32] for i in range(0,len(encrypted_frames),32)]
                            decrypted_frames = []
                            for block in encrypted_frames:
                                decrypted_frames.append(decrypt(block,key))
                        else:
                            decrypted_frames = decrypt(encrypted_frames,key)
                        decrypted_frames = (''.join(decrypted_frames))
                        decrypted_frames = bytes.fromhex(decrypted_frames)
                        # Ask the user for output file path
                        output_file_path = filedialog.asksaveasfilename(defaultextension=".wav", filetypes=[("WAV files", "*.wav")])
                        if output_file_path:
                            write_audio_file(output_file_path, decrypted_frames, params)
                            print("Decryption Successful")
                            print(f"Audio saved to: {output_file_path}")
                    


            else:
                # Run other algorithms using subprocess (as in your original code)
                command = f"python {algorithm}.py {operation} {key} {input_file} {output_file}"
                start_time = time.time()

                process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                output, error = process.communicate()

                end_time = time.time()
                elapsed_time = end_time - start_time
                # self.root.after(0, self.update_timer, elapsed_time)

                # Display the output in the Text widget
                self.root.after(0, self.display_output, output.decode())

        except Exception as e:
            print(f"Error: {e}")
            # self.root.after(0, self.update_timer, 0)
  

    def show_output_cs(self, output):
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, output)

    def display_output(self, output, operation):

        if operation == "encrypt":
            message = "Encryption successful"
        elif operation == "decrypt":  
            message = "Decryption successful"
        self.output_text.delete(1.0, tk.END)
        # self.output_text.insert(tk.END, output)
        self.output_text.insert(tk.END, message)

        # If it's Blowfish encryption, store the result in a variable
        if (self.encrypt_decrypt_var.get().lower() == "encrypt" or self.encrypt_decrypt_var.get().lower() == "decrypt") and self.algorithm_var.get().lower() == "blowfish":
            self.blowfish_result = output
        elif (self.encrypt_decrypt_var.get().lower() == "encrypt" or self.encrypt_decrypt_var.get().lower() == "decrypt") and self.algorithm_var.get().lower() == "twofish":
            self.twofish_result = output

    def save_blowfish_result(self):
        # Check if it's Blowfish encryption and the result is available
        if hasattr(self, "blowfish_result"):
            result_to_save = self.blowfish_result
        elif hasattr(self, "twofish_result"):
            result_to_save = self.twofish_result
        else:
            return  # No result available
        # print(result_to_save)
        # print(self.blowfish_result[1], " ", self.blowfish_result[2])
        def write_image(file_path, data, size, mode):
                        with Image.frombytes(mode, size, data) as img:
                            img.save(file_path)
        # Extract the ciphertext from the result
        # ciphertext_start = str(result_to_save).find(":")  # Find the position of ":"
        # if ciphertext_start != -1:
        #     ciphertext = result_to_save[ciphertext_start + 1:].strip()  # Extract ciphertext part
        # else:
        #     ciphertext = result_to_save.strip()  # Use the entire result if no ":"
        # # Check if there is any ciphertext to save
        # if ciphertext:
            # Get the file path to save the result
        output_file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"),("PNG files", "*.png"),("WAV files", "*.wav"),("MP4 Files", "*.mp4")])
        if output_file_path[-4:] == ".txt":
            with open(output_file_path, "w") as file:
                file.write(result_to_save)
                print(f"Text saved to: {output_file_path}")
            self.output_text.delete(1.0, tk.END)    
            self.output_text.insert(tk.END, result_to_save)    
        elif output_file_path[-4:] == ".png":
            write_image(output_file_path, self.blowfish_result[0], self.blowfish_result[1], self.blowfish_result[2])
            print(f"Image saved to: {output_file_path}")
        elif output_file_path[-4:] == ".wav":
            with wave.open(output_file_path, 'wb') as audio_file:
                audio_file.setparams(self.blowfish_result[1])
                audio_file.writeframes(self.blowfish_result[0])

            # elif output_file_path[-4:] in [".mp4", ".mov" ]:
            #     self.blowfish_result.write_videofile(output_file_path)


    # def update_timer(self, elapsed_time):
    #     # Update the timer display in real-time
    #     while self.process_thread.is_alive():
    #         # time.sleep(1)
    #         elapsed_time += 1
    #         hours, remainder = divmod(int(elapsed_time), 3600)
    #         minutes, seconds = divmod(remainder, 60)
    #         timer_text = f"{hours:02}:{minutes:02}:{seconds:02}"
    #         self.timer_display.config(text=timer_text)
    #         self.root.update()

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()

