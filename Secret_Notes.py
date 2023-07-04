from tkinter import *
import base64
from tkinter import messagebox


# Screen
window = Tk()
window.title('Secret Notes')
window.minsize(width=400, height=650)


def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()


def save_encrypt():
    global file_path, encrypted, file
    title = entry1.get()
    note = text1.get(1.0, END)
    password = entry2.get()
    if len(title) == 0 or len(note) == 0 or len(password) == 0:
        messagebox.showerror("ERROR", "Fill All Information")
    else:
        try:
            encrypted = encode(password, note)
            with open("Secret.txt", 'w') as file:
                alltext = "\n" + title + "\n" + encrypted
                file.write(alltext)
                file.close()
                messagebox.showinfo("Secret Notes", "Succesful")
                entry1.delete(0, END)
                entry2.delete(0, END)
                text1.delete(1.0, END)
        except FileNotFoundError:
            with open("Secret.txt", 'w') as file:
                alltext = "\n" + title + "\n" + encrypted
                file.write(alltext)
                file.close()


def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)


def decryptt():
    note = text1.get(1.0, END)
    password = entry2.get()
    if len(note) == 0 or len(password) == 0:
        messagebox.showerror("ERROR", "Enter Your Password and Note")
    else:
        try:
            decrypted = decode(password, note)
            entry2.delete(0, END)
            text1.delete(1.0, END)
            text1.insert(1.0, decrypted)
        except:
            messagebox.showinfo("ERROR", message="Please Enter encrypted text")


# Labels, Entries, Text and Buttons
topSecret = PhotoImage(file='/top secret.png')
label1 = Label(image=topSecret)
label1.config(width=120, height=120)
label1.pack()
label2 = Label(text='Enter Your Title', font='Helvetica 14 bold')
label2.pack()
entry1 = Entry(width=20)
entry1.focus()
entry1.pack()
label3 = Label(text='Enter Your Secret', font='Helvetica 14 bold')
label3.config(padx=15, pady=15)
label3.pack()
text1 = Text(width=40, height=20)
text1.pack()
label4 = Label(text='Enter Master Key', font='Helvetica 14 bold')
label4.config(pady=10)
label4.pack()
entry2 = Entry(width=20)
entry2.pack()
save_button = Button(text='Save & Encrypt', command=save_encrypt)
save_button.pack()
decrypt_button = Button(text='Decrypt', command=decryptt)
decrypt_button.pack()


window.mainloop()
