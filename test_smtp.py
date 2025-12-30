import smtplib
import os
import sys

# Simulation of what's in the app and env
email = "user49856@protonmail.com"
password = "6o6fku77"
smtp_server = "smtp.gmail.com"
smtp_port = 587

print(f"Testing SMTP connection to {smtp_server}:{smtp_port}")
print(f"User: {email}")
print(f"Pass: {'*' * len(password)}")

try:
    server = smtplib.SMTP(smtp_server, smtp_port)
    server.starttls()
    print("TLS started. Attempting login...")
    server.login(email, password)
    print("Login SUCCESS!")
    server.quit()
    sys.exit(0)
except Exception as e:
    print(f"Login FAILED: {e}")
    sys.exit(1)
