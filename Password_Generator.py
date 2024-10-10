import tkinter as tk
from tkinter import messagebox
import random
import string
import pyperclip

# Function to generate the password
def generate_password():
    length = int(length_entry.get())
    include_uppercase = uppercase_var.get()
    include_lowercase = lowercase_var.get()
    include_numbers = numbers_var.get()
    include_symbols = symbols_var.get()

    if length < 4:
        messagebox.showerror("Error", "Password length must be at least 4 characters.")
        return

    # Create character set based on user options
    character_set = ""
    if include_uppercase:
        character_set += string.ascii_uppercase
    if include_lowercase:
        character_set += string.ascii_lowercase
    if include_numbers:
        character_set += string.digits
    if include_symbols:
        character_set += string.punctuation

    if not character_set:
        messagebox.showerror("Error", "Please select at least one character set.")
        return

    # Generate password with at least one character from each selected set
    password = []
    if include_uppercase:
        password.append(random.choice(string.ascii_uppercase))
    if include_lowercase:
        password.append(random.choice(string.ascii_lowercase))
    if include_numbers:
        password.append(random.choice(string.digits))
    if include_symbols:
        password.append(random.choice(string.punctuation))

    # Fill the rest of the password
    password += random.choices(character_set, k=length - len(password))
    random.shuffle(password)
    
    final_password = ''.join(password)
    password_entry.delete(0, tk.END)
    password_entry.insert(0, final_password)

# Function to copy password to clipboard
def copy_to_clipboard():
    password = password_entry.get()
    if password:
        pyperclip.copy(password)
        messagebox.showinfo("Copied", "Password copied to clipboard!")
    else:
        messagebox.showerror("Error", "No password generated.")

# GUI Application
class PasswordGeneratorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Password Generator")
        self.root.geometry("400x300")

        self.create_widgets()

    def create_widgets(self):
        # Password length label and entry
        tk.Label(self.root, text="Password Length:").grid(row=0, column=0, padx=10, pady=10)
        global length_entry
        length_entry = tk.Entry(self.root)
        length_entry.grid(row=0, column=1, padx=10, pady=10)
        length_entry.insert(0, "12")  # Default length

        # Checkbox options for character sets
        global uppercase_var, lowercase_var, numbers_var, symbols_var
        uppercase_var = tk.BooleanVar(value=True)
        lowercase_var = tk.BooleanVar(value=True)
        numbers_var = tk.BooleanVar(value=True)
        symbols_var = tk.BooleanVar(value=True)

        tk.Checkbutton(self.root, text="Include Uppercase Letters", variable=uppercase_var).grid(row=1, column=0, columnspan=2, padx=10, pady=5)
        tk.Checkbutton(self.root, text="Include Lowercase Letters", variable=lowercase_var).grid(row=2, column=0, columnspan=2, padx=10, pady=5)
        tk.Checkbutton(self.root, text="Include Numbers", variable=numbers_var).grid(row=3, column=0, columnspan=2, padx=10, pady=5)
        tk.Checkbutton(self.root, text="Include Symbols", variable=symbols_var).grid(row=4, column=0, columnspan=2, padx=10, pady=5)

        # Generate Password Button
        generate_button = tk.Button(self.root, text="Generate Password", command=generate_password)
        generate_button.grid(row=5, column=0, columnspan=2, padx=10, pady=10)

        # Password Entry (readonly)
        global password_entry
        password_entry = tk.Entry(self.root, width=30)
        password_entry.grid(row=6, column=0, columnspan=2, padx=10, pady=10)
        password_entry.config(state='normal')  # Allow to insert generated password

        # Copy to Clipboard Button
        copy_button = tk.Button(self.root, text="Copy to Clipboard", command=copy_to_clipboard)
        copy_button.grid(row=7, column=0, columnspan=2, padx=10, pady=10)

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordGeneratorApp(root)
    root.mainloop()