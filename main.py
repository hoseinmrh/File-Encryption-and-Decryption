from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import base64
from tkinter import *
from tkinter import filedialog as fd
from tkinter.messagebox import showinfo, showerror
import os


def encrypt_message(key, message):
    backend = default_backend()
    iv = b'\x00' * 16  # Initialization vector
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(ciphertext).decode()


def decrypt_message(key, ciphertext):
    backend = default_backend()
    iv = b'\x00' * 16  # Initialization vector
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    ciphertext = base64.b64decode(ciphertext)
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_message = unpadder.update(padded_data) + unpadder.finalize()
    return decrypted_message.decode()


def select_file_and_save(prompt):
    filetypes = (
        ('text files', '*.txt'),
        ('All files', '*.*')
    )

    filename = fd.askopenfilename(
        title='Open a file',
        initialdir=os.curdir,
        filetypes=filetypes)

    if filename:
        file_name = os.path.basename(filename)
        save_path = f'Files/{prompt}{file_name}'
        if save_path:
            with open(filename, 'r') as f:
                content = f.read()
            with open(save_path, 'w') as f:
                f.write(content)
            showinfo(
                title='File Saved',
                message=f'{file_name} has been imported successfully!'
            )


def submit(secretKeyEntry, mode):
    secret_key = secretKeyEntry.get()
    secretKeyEntry.delete(0, 'end')
    if len(secret_key) != 16:
        showerror(
            title="Length Error",
            message="Secret Key must be in length of 16"
        )
    else:
        secret_key_byte = secret_key.encode()
        input_dir = "Files/"
        if mode == "encrypt":
            for file_name in os.listdir(input_dir):
                if file_name.startswith("original_"):
                    file = open(f'{input_dir}{file_name}', 'r')
                    content = file.read()
                    enc_file = open(f'Output/encrypted.txt', 'w')
                    try:
                        encrypted_file = encrypt_message(secret_key_byte, content)
                        enc_file.write(encrypted_file)
                        enc_file.close()
                        showinfo(
                            title='File Encrypted',
                            message=f'{file_name} has been encrypted successfully!'
                        )
                    except:
                        showerror(
                            title="Secret Key Error",
                            message="Secret Key is Invalid"
                        )

        else:
            for file_name in os.listdir(input_dir):
                if file_name.startswith("encrypted"):
                    file = open(f'{input_dir}{file_name}', 'r')
                    content = file.read()
                    dec_file = open(f'Output/decrypted.txt', 'w')
                    try:
                        decrypted_file = decrypt_message(secret_key_byte, content)
                        dec_file.write(decrypted_file)
                        dec_file.close()
                        showinfo(
                            title='File Decrypted',
                            message=f'{file_name} has been decrypted successfully!'
                        )
                    except:
                        showerror(
                            title="Secret Key Error",
                            message="Secret Key is Invalid"
                        )


def encrypt_page():

    def back_on_click():
        root.destroy()
        main_page()

    root = Tk()
    root.title("LOGIC CIRCUITS PROJECT")
    root.geometry("400x500")
    root['background'] = '#525252'

    label = Label(root, text="Let's Encrypt a File", font=("Helvetica", 24, "bold"), fg="#EC625F", bg="#525252")
    label.pack()
    label.place(y=50, relx=0.5, anchor='center')

    label2 = Label(root, text="Import your file 👇", font=("Helvetica", 16, ""), fg="#DAD4B5", bg="#525252")
    label2.pack()
    label2.place(y=100, relx=0.5, anchor='center')

    open_button = Button(
        root,
        text='Add file',
        command=lambda: select_file_and_save("original_"),
        bg='#313131',
        fg='#EC625F',
        font=("Helvetica", 12, "")
    )

    open_button.pack(expand=True)
    open_button.place(y=150, width=120, relx=0.5, anchor='center')

    label2 = Label(root, text="Add your secret key 👇", font=("Helvetica", 16, ""), fg="#DAD4B5", bg="#525252")
    label2.pack()
    label2.place(y=200, relx=0.5, anchor='center')

    secretKey = Entry(root, show="*", font=("Helvetica", 20, ""))
    secretKey.pack()
    secretKey.place(y=250, width=300, height=30, relx=0.5, anchor='center')

    submit_button = Button(
        root,
        text='Submit',
        command=lambda: submit(secretKey, "encrypt"),
        bg='#313131',
        fg='#EC625F',
        font=("Helvetica", 24, "")
    )

    submit_button.pack(expand=True)
    submit_button.place(y=320, width=200, relx=0.5, anchor='center')

    back_button = Button(
        root,
        text='Back to Main Page',
        command=back_on_click,
        bg='#313131',
        fg='#DAD4B5',
        font=("Helvetica", 12, "")
    )

    back_button.pack(expand=True)
    back_button.place(y=420, width=200, relx=0.5, anchor='center')
    root.mainloop()


def decrypt_page():

    def back_on_click():
        root.destroy()
        main_page()

    root = Tk()
    root.title("LOGIC CIRCUITS PROJECT")
    root.geometry("400x500")
    root['background'] = '#525252'

    label = Label(root, text="Let's Decrypt a File", font=("Helvetica", 24, "bold"), fg="#EC625F", bg="#525252")
    label.pack()
    label.place(y=50, relx=0.5, anchor='center')

    label2 = Label(root, text="Import your file 👇", font=("Helvetica", 16, ""), fg="#DAD4B5", bg="#525252")
    label2.pack()
    label2.place(y=100, relx=0.5, anchor='center')

    open_button = Button(
        root,
        text='Add file',
        command=lambda: select_file_and_save(""),
        bg='#313131',
        fg='#EC625F',
        font=("Helvetica", 12, "")
    )

    open_button.pack(expand=True)
    open_button.place(y=150, width=120, relx=0.5, anchor='center')

    label2 = Label(root, text="Add your secret key 👇", font=("Helvetica", 16, ""), fg="#DAD4B5", bg="#525252")
    label2.pack()
    label2.place(y=200, relx=0.5, anchor='center')

    secretKey = Entry(root, show="*", font=("Helvetica", 20, ""))
    secretKey.pack()
    secretKey.place(y=250, width=300, height=30, relx=0.5, anchor='center')

    submit_button = Button(
        root,
        text='Submit',
        command=lambda: submit(secretKey, "decrypt"),
        bg='#313131',
        fg='#EC625F',
        font=("Helvetica", 24, "")
    )

    submit_button.pack(expand=True)
    submit_button.place(y=320, width=200, relx=0.5, anchor='center')

    back_button = Button(
        root,
        text='Back to Main Page',
        command=back_on_click,
        bg='#313131',
        fg='#DAD4B5',
        font=("Helvetica", 12, "")
    )

    back_button.pack(expand=True)
    back_button.place(y=420, width=200, relx=0.5, anchor='center')
    root.mainloop()


def main_page():

    def on_click(page):
        root.destroy()
        if page == "encrypt":
            encrypt_page()
        else:
            decrypt_page()

    root = Tk()
    root.title("LOGIC CIRCUITS PROJECT")
    root.geometry("400x500")
    root['background'] = '#525252'

    label = Label(root, text="Welcome", font=("Helvetica", 24, "bold"), fg="#EC625F", bg="#525252")
    label.pack()
    label.place(y=50, relx=0.5, anchor='center')

    enc_button = Button(
        root,
        text='Encrypt a File',
        command=lambda: on_click("encrypt"),
        bg='#313131',
        fg='#EC625F',
        font=("Helvetica", 16, "")
    )

    enc_button.pack(expand=True)
    enc_button.place(y=150, width=250, relx=0.5, anchor='center')

    dec_button = Button(
        root,
        text='Decrypt a File',
        command=lambda: on_click("decrypt"),
        bg='#313131',
        fg='#EC625F',
        font=("Helvetica", 16, "")
    )

    dec_button.pack(expand=True)
    dec_button.place(y=250, width=250, relx=0.5, anchor='center')
    root.mainloop()


main_page()
