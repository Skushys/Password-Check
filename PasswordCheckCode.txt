import hashlib
import requests
import tkinter as tk
from tkinter import messagebox
import re

COMMON_PASSWORDS = {"password", "123456", "letmein", "qwerty", "admin", "welcome"}

def get_sha1_hash(password):
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    return sha1[:5], sha1[5:]

def check_pwned_api(first5, tail):
    try:
        url = f"https://api.pwnedpasswords.com/range/{first5}"
        response = requests.get(url)
        hashes = (line.split(":") for line in response.text.splitlines())
        return any(tail == h for h, _ in hashes)
    except Exception:
        return False  # Fail safe if API check fails

def password_strength(password):
    score = 0
    suggestions = []

    if len(password) >= 12:
        score += 1
    else:
        suggestions.append("Use at least 12 characters.")

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        suggestions.append("Add uppercase letters.")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        suggestions.append("Add lowercase letters.")

    if re.search(r"\d", password):
        score += 1
    else:
        suggestions.append("Include numbers.")

    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 1
    else:
        suggestions.append("Include symbols.")

    if any(word in password.lower() for word in COMMON_PASSWORDS):
        suggestions.append("Avoid common passwords.")

    first5, tail = get_sha1_hash(password)
    breached = check_pwned_api(first5, tail)
    if breached:
        suggestions.append("This password has appeared in a data breach.")

    return score, suggestions

# ------------------ GUI Setup ------------------ #

def check_password():
    pw = entry.get()
    if not pw:
        messagebox.showwarning("Input Error", "Please enter a password.")
        return

    score, tips = password_strength(pw)
    result = f"Password Score: {score}/5\n"
    if tips:
        result += "Suggestions:\n" + "\n".join(f"- {tip}" for tip in tips)
    else:
        result += "Your password looks strong!"

    messagebox.showinfo("Password Check Result", result)

root = tk.Tk()
root.title("Password Strength Checker")
root.geometry("400x180")

tk.Label(root, text="Enter your password:", font=("Segoe UI", 12)).pack(pady=10)
entry = tk.Entry(root, width=35, show="*", font=("Segoe UI", 12))
entry.pack()

tk.Button(root, text="Check Strength", command=check_password, font=("Segoe UI", 10)).pack(pady=15)

root.mainloop()