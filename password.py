import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import secrets
import string

def generate_password():
    """Generates a secure random password based on user selections."""
    try:
        password_length = int(length_spinbox.get())
        if password_length < 1:
            messagebox.showwarning("Invalid Length", "Password length must be at least 1.")
            return
    except ValueError:
        messagebox.showerror("Invalid Input", "Password length must be a number.")
        return

    char_pool = ''
    if lowercase_var.get():
        char_pool += string.ascii_lowercase
    if uppercase_var.get():
        char_pool += string.ascii_uppercase
    if digits_var.get():
        char_pool += string.digits
    if special_chars_var.get():
        char_pool += string.punctuation

    if not char_pool:
        messagebox.showwarning("No Characters Selected", "Please select at least one character type.")
        return

    password = ''.join(secrets.choice(char_pool) for _ in range(password_length))
    password_entry.config(state='normal')
    password_entry.delete(0, tk.END)
    password_entry.insert(0, password)
    password_entry.config(state='readonly')

def copy_to_clipboard():
    """Copies the generated password to the clipboard."""
    password = password_entry.get()
    if password:
        root.clipboard_clear()
        root.clipboard_append(password)
        messagebox.showinfo("Copied", "Password copied to clipboard!")
    else:
        messagebox.showwarning("No Password", "No password to copy.")

root = tk.Tk()
root.title("Secure Password Generator")
root.geometry("400x300")
root.resizable(False, False)

mainframe = ttk.Frame(root, padding="10 10 10 10")
mainframe.grid(column=0, row=0, sticky=(tk.W, tk.E, tk.N, tk.S))
root.columnconfigure(0, weight=1)
root.rowconfigure(0, weight=1)

lowercase_var = tk.BooleanVar(value=True)
uppercase_var = tk.BooleanVar(value=True)
digits_var = tk.BooleanVar(value=True)
special_chars_var = tk.BooleanVar(value=True)

controls_frame = ttk.LabelFrame(mainframe, text="Password Options", padding="10")
controls_frame.grid(column=0, row=0, sticky=(tk.W, tk.E))

ttk.Label(controls_frame, text="Password Length:").grid(column=0, row=0, sticky=tk.W, pady=5)
length_spinbox = ttk.Spinbox(controls_frame, from_=8, to=32, width=5)
length_spinbox.set(12)
length_spinbox.grid(column=1, row=0, sticky=tk.W)

ttk.Checkbutton(controls_frame, text="Include Lowercase Letters", variable=lowercase_var).grid(column=0, row=1, columnspan=2, sticky=tk.W)
ttk.Checkbutton(controls_frame, text="Include Uppercase Letters", variable=uppercase_var).grid(column=0, row=2, columnspan=2, sticky=tk.W)
ttk.Checkbutton(controls_frame, text="Include Digits", variable=digits_var).grid(column=0, row=3, columnspan=2, sticky=tk.W)
ttk.Checkbutton(controls_frame, text="Include Special Characters", variable=special_chars_var).grid(column=0, row=4, columnspan=2, sticky=tk.W)

output_frame = ttk.Frame(mainframe, padding="10")
output_frame.grid(column=0, row=1, sticky=(tk.W, tk.E), pady=10)

ttk.Button(output_frame, text="Generate Password", command=generate_password).grid(column=0, row=0, pady=5)
ttk.Button(output_frame, text="Copy to Clipboard", command=copy_to_clipboard).grid(column=1, row=0, pady=5, padx=10)

ttk.Label(output_frame, text="Generated Password:").grid(column=0, row=1, columnspan=2, sticky=tk.W, pady=(10, 5))
password_entry = ttk.Entry(output_frame, width=40, state='readonly', font=("Courier", 12))
password_entry.grid(column=0, row=2, columnspan=2, sticky=(tk.W, tk.E))


for child in controls_frame.winfo_children(): 
    child.grid_configure(padx=5, pady=2)
for child in output_frame.winfo_children(): 
    child.grid_configure(padx=5, pady=2)

root.mainloop()