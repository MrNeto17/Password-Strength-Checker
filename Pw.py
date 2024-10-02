import re
import urllib.request
import tkinter as tk
from tkinter import messagebox
import random
import string
import hashlib

# Using a github repository to check if passwords are in most common list
def fetch_common_passwords_from_github():
    url = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt"
    try:
        with urllib.request.urlopen(url) as response:
            passwords = response.read().decode('utf-8').splitlines()  # Read and decode the response
            return passwords
    except Exception as e:
        messagebox.showerror("Error", f"Failed to fetch passwords: {e}")
        return []

#checking if is common
def check_common_password(password):
    common_passwords = fetch_common_passwords_from_github()  # Fetch passwords from GitHub
    if common_passwords:
        is_common = password.lower() in common_passwords
        return is_common
    return False

# Strength parameters
def check_password_strength(password, common_passwords):
    length_error = len(password) < 8
    digit_error = re.search(r"\d", password) is None
    uppercase_error = re.search(r"[A-Z]", password) is None
    lowercase_error = re.search(r"[a-z]", password) is None
    symbol_error = re.search(r"[!@#$%^&*()_+={}\[\]:;\"'|\\<>,.?/~`-]", password) is None
    common_password_error = password.lower() in common_passwords

    errors = {
        "Length": length_error,
        "Digit": digit_error,
        "Uppercase": uppercase_error,
        "Lowercase": lowercase_error,
        "Symbol": symbol_error,
        "Common Password": common_password_error
    }

    if any(errors.values()):
        error_messages = ", ".join([k for k, v in errors.items() if v])
        return False, f"Password is weak! Errors: {error_messages}"
    else:
        return True, "Password is strong!"

# Estimating bruteforce time
def estimate_brute_force_time(password):
    character_set = {
        'lowercase': 26,
        'uppercase': 26,
        'digits': 10,
        'special': 32
    }

    total_characters = sum(character_set.values())
    total_combinations = total_characters ** len(password)

    # Assume a brute-force speed (attempts per second)
    attempts_per_second = 100000  # Change as needed

    # Calculate time to crack in seconds
    time_to_crack_seconds = total_combinations / attempts_per_second

    # Convert seconds into more readable format
    time_to_crack_minutes = time_to_crack_seconds / 60
    time_to_crack_hours = time_to_crack_minutes / 60
    time_to_crack_days = time_to_crack_hours / 24

    return {
        'seconds': time_to_crack_seconds,
        'minutes': time_to_crack_minutes,
        'hours': time_to_crack_hours,
        'days': time_to_crack_days
    }

# Function to generate a random strong password
def generate_password(length=12):
    if length < 8:
        messagebox.showwarning("Warning", "Password length should be at least 8 characters.")
        return ""

    # Include at least one character from each type
    lowercase = random.choice(string.ascii_lowercase)
    uppercase = random.choice(string.ascii_uppercase)
    digit = random.choice(string.digits)
    symbol = random.choice(string.punctuation)

    remaining_length = length - 4  # 4 characters already chosen
    all_characters = string.ascii_letters + string.digits + string.punctuation
    password = lowercase + uppercase + digit + symbol + ''.join(random.choice(all_characters) for _ in range(remaining_length))

    password_list = list(password)
    random.shuffle(password_list)
    return ''.join(password_list)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()  # Hash the password using SHA-256

# saving hash password
def save_password_to_file(password):
    hashed_password = hash_password(password)
    with open("used_passwords.txt", "a") as file:
        file.write(hashed_password + "\n")  # Append the hashed password to the file
    messagebox.showinfo("Success", "Password saved successfully!")

# Function to check if the password hash is in the historic passwords file
def check_historic_password(password):
    hashed_password = hash_password(password)
    try:
        with open("used_passwords.txt", "r") as file:
            if hashed_password in file.read():
                messagebox.showinfo("Check Historic Password", "This password hash already exists in the historic file.")
            else:
                messagebox.showinfo("Check Historic Password", "This password hash does not exist in the historic file.")
    except FileNotFoundError:
        messagebox.showwarning("Warning", "No historic passwords file found.")

# Function to check password from UI
def check_password():
    password = entry_password.get()
    if not password:
        messagebox.showwarning("Input Error", "Please enter a password")
    else:
        common_passwords = fetch_common_passwords_from_github()  # Fetch passwords from GitHub
        if common_passwords:
            is_strong, result = check_password_strength(password, common_passwords)
            result_label.config(text=result, fg="green" if is_strong else "red")

            # Update strength meter based on results
            if is_strong:
                update_strength_meter("strong")
            else:
                # Determine if weak or medium
                if len(password) < 10:
                    update_strength_meter("weak")
                else:
                    update_strength_meter("medium")

            # Estimate and display brute-force time
            time_estimation = estimate_brute_force_time(password)
            time_message = (
                f"Estimated time to crack:\n"
                f"🌟 {time_estimation['seconds']:.2f} seconds\n"
                f"⏳ ~ {time_estimation['minutes']:.2f} minutes\n"
                f"🕒 ~ {time_estimation['hours']:.2f} hours\n"
                f"📅 ~ {time_estimation['days']:.2f} days"
            )
            time_label.config(text=time_message)

# Generate and display a random password
def generate_and_display_password():
    length = int(length_entry.get())
    password = generate_password(length)
    entry_password.delete(0, tk.END)
    entry_password.insert(0, password)

# Function to check if the password is common
def check_if_common():
    password = entry_password.get()
    if not password:
        messagebox.showwarning("Input Error", "Please enter a password")
    else:
        is_common = check_common_password(password)
        if is_common:
            result_label.config(text="Password is common!", fg="red")
        else:
            result_label.config(text="Password is not common.", fg="green")

# Add this function to update the strength meter
def update_strength_meter(strength):
    strength_meter.delete("all")
    if strength == "weak":
        strength_meter.create_rectangle(0, 0, 100, 20, fill="red")
    elif strength == "medium":
        strength_meter.create_rectangle(0, 0, 200, 20, fill="orange")
    elif strength == "strong":
        strength_meter.create_rectangle(0, 0, 300, 20, fill="green")

# Setup Tkinter window
root = tk.Tk()
root.title("Password Strength Checker")
root.geometry("400x600")
root.config(bg="#f4f4f9")  # Set background color

# Header label with larger font
header_label = tk.Label(root, text="Password Strength Checker", font=("Helvetica", 16, "bold"), bg="#f4f4f9", fg="#4a4a4a")
header_label.pack(pady=10, fill='x')  # Fill the header label horizontally

# Create UI elements with custom styles
label = tk.Label(root, text="Enter your password:", font=("Helvetica", 12), bg="#f4f4f9", fg="#333333")
label.pack(pady=5)

# Create frame for password entry
password_frame = tk.Frame(root)
password_frame.pack(pady=5)

# Create rounded entry field for password input
entry_password = tk.Entry(password_frame, show="*", width=30, font=("Helvetica", 10), bd=0, highlightthickness=0)
entry_password.pack(pady=5, padx=10)

# Checkbox to show/hide password
def toggle_password_visibility():
    if show_password_var.get():
        entry_password.config(show="")
    else:
        entry_password.config(show="*")

show_password_var = tk.BooleanVar()
show_password_checkbox = tk.Checkbutton(root, text="Show Password", variable=show_password_var, command=toggle_password_visibility, bg="#f4f4f9", fg="#333333")
show_password_checkbox.pack(pady=5)

# Create rounded entry field for password length input
length_label = tk.Label(root, text="Password Length (min 8):", font=("Helvetica", 12), bg="#f4f4f9", fg="#333333")
length_label.pack(pady=5)
length_entry = tk.Entry(root, width=10, font=("Helvetica", 10), bd=0, highlightthickness=0)  # Made text smaller
length_entry.pack(pady=5)
length_entry.insert(0, "12")  # Default length

# Function to create a rounded button with hover effect
def create_rounded_button(parent, text, command, bg_color="#4a90e2", hover_color="#357ABD"):
    button = tk.Button(parent, text=text, command=command, font=("Helvetica", 12), bg=bg_color, fg="white", relief="flat")
    button.pack(pady=5, padx=10)

    # Bind hover events
    button.bind("<Enter>", lambda e: button.config(bg=hover_color))
    button.bind("<Leave>", lambda e: button.config(bg=bg_color))

    return button

# Improved button colors
check_button = create_rounded_button(root, "Check Strength", check_password, bg_color="#f44336", hover_color="#d9534f")
check_common_button = create_rounded_button(root, "Check Common Password", check_if_common,  bg_color="#2cb85c", hover_color="#3cae4c")
generate_button = create_rounded_button(root, "Generate Password", generate_and_display_password,  bg_color="#2cb85c", hover_color="#3cae4c")
save_button = create_rounded_button(root, "Save Password", lambda: save_password_to_file(entry_password.get()), bg_color="#2cb85c", hover_color="#3cae4c")
check_historic_button = create_rounded_button(root, "Check Historic Password", lambda: check_historic_password(entry_password.get()),  bg_color="#2cb85c", hover_color="#3cae4c")

# Strength meter label
strength_meter_label = tk.Label(root, text="Password Strength:", font=("Helvetica", 12), bg="#f4f4f9", fg="#333333")
strength_meter_label.pack(pady=5)

# Strength meter canvas
strength_meter = tk.Canvas(root, width=300, height=20, bg="#e0e0e0", bd=0, highlightthickness=0)
strength_meter.pack(pady=5)

# Result label for feedback
result_label = tk.Label(root, text="", font=("Helvetica", 12), bg="#f4f4f9", fg="#333333")
result_label.pack(pady=5)

# Time estimation label
time_label = tk.Label(root, text="", font=("Helvetica", 12), bg="#f4f4f9", fg="#333333")
time_label.pack(pady=5)

# Start the Tkinter event loop
root.mainloop()
