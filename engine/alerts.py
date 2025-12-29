import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage
import os

class AlertSystem:
    def __init__(self, smtp_server='smtp.gmail.com', smtp_port=587):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.sender_email = os.getenv('SENDER_EMAIL')
        self.sender_password = os.getenv('SENDER_PASSWORD')
        self.receiver_email = os.getenv('RECEIVER_EMAIL')

    def send_email_alert(self, threat_details, image_path=None):
        if not self.sender_email or not self.sender_password or not self.receiver_email:
            print("Email credentials not configured. Skipping email alert.")
            return False

        try:
            msg = MIMEMultipart()
            msg['From'] = self.sender_email
            msg['To'] = self.receiver_email
            msg['Subject'] = f"SECURITY ALERT: {threat_details['type']} Detected"

            body = f"""
            Urgent Security Alert!
            
            Threat Type: {threat_details['type']}
            Confidence: {threat_details['confidence']:.2f}
            Time: {threat_details['time']}
            Location: Primary Feed
            
            Please check the dashboard immediately for more details.
            """
            msg.attach(MIMEText(body, 'plain'))

            if image_path and os.path.exists(image_path):
                with open(image_path, 'rb') as f:
                    img_data = f.read()
                image = MIMEImage(img_data, name=os.path.basename(image_path))
                msg.attach(image)

            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()
            server.login(self.sender_email, self.sender_password)
            server.send_message(msg)
            server.quit()
            return True
        except Exception as e:
            print(f"Error sending email: {e}")
            return False
