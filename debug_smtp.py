import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

load_dotenv(override=True)

sender = os.getenv('SENDER_EMAIL')
password = os.getenv('SENDER_PASSWORD')
receiver = os.getenv('RECEIVER_EMAIL')

print(f"Testing SMTP with:")
print(f"Sender: {sender}")
print(f"Receiver: {receiver}")

try:
    msg = MIMEMultipart()
    msg['From'] = sender
    msg['To'] = receiver
    msg['Subject'] = "Final Connection Check"
    msg.attach(MIMEText("This is a test to verify the app's backend SMTP logic.", 'plain'))

    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.set_debuglevel(1)
    server.starttls()
    server.login(sender, password)
    server.send_message(msg)
    server.quit()
    print("\nSUCCESS: Email sent!")
except Exception as e:
    print(f"\nFAILURE: {e}")
