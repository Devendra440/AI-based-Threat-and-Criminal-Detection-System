import smtplib
import os
from dotenv import load_dotenv
import sys

# Force reload of .env
load_dotenv(override=True)

sender = os.getenv('SENDER_EMAIL')
password = os.getenv('SENDER_PASSWORD')
receiver = os.getenv('RECEIVER_EMAIL')

print(f"Attempting login with:")
print(f"Sender: {sender}")
if password:
    print(f"Password: {'*' * len(password)}")
else:
    print("Password: <Not Set>")

if not sender or not password:
    print("Error: Missing credentials in .env file.")
    sys.exit(1)

try:
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    print("Connecting to Gmail SMTP...")
    server.login(sender, password)
    print("✅ Login SUCCESS! Credentials are valid.")
    server.quit()
except Exception as e:
    print(f"❌ Login FAILED: {e}")
