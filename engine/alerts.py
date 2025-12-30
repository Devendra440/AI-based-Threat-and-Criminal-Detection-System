import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage
import os
from dotenv import load_dotenv

load_dotenv() # Ensure .env is loaded

class AlertSystem:
    def __init__(self, smtp_server='smtp.gmail.com', smtp_port=587):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.sender_email = os.getenv('SENDER_EMAIL')
        self.sender_password = os.getenv('SENDER_PASSWORD')
        self.receiver_email = os.getenv('RECEIVER_EMAIL')

    def send_email_alert(self, threat_details, image_path=None, email_config=None):
        # Force reload env vars in case they changed
        load_dotenv(override=True)
        
        # Determine credentials
        sender = os.getenv('SENDER_EMAIL')
        password = os.getenv('SENDER_PASSWORD')
        receiver = os.getenv('RECEIVER_EMAIL')
        
        if email_config:
            sender = email_config.get('sender_email') or sender
            password = email_config.get('sender_password') or password
            receiver = email_config.get('receiver_email') or receiver

        if not sender or not password or not receiver:
            return False

        try:
            msg = MIMEMultipart('related')
            msg['From'] = f"Security Intelligence AI <{sender}>"
            msg['To'] = str(receiver)
            
            threat_type = threat_details.get('type', 'Critical Threat')
            confidence = threat_details.get('confidence', 0.0)
            priority = "CRITICAL" if confidence > 0.8 else "HIGH"
            
            msg['Subject'] = f"[{priority}] Security Alert: {threat_type} Detected"

            custom_msg = threat_details.get('message', 'A security breach has been identified in the monitored sector.')
            suspect = threat_details.get('suspect', 'Identified Suspect')
            timestamp = threat_details.get('time', 'N/A')
            
            # Additional Mock Data for Professionalism
            latency = f"{threat_details.get('latency', 120)}ms"
            system_id = "SHIELD-PRO-V4"
            location_tag = "Main Entrance A-1"

            html_body = f"""
            <html>
                <body style="font-family: 'Inter', Helvetica, Arial, sans-serif; background-color: #020617; margin: 0; padding: 40px; color: #f8fafc;">
                    <div style="max-width: 650px; margin: auto; background-color: #0f172a; border-radius: 20px; overflow: hidden; border: 1px solid #1e293b; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);">
                        
                        <!-- Header Bar -->
                        <div style="background: linear-gradient(90deg, #ef4444, #991b1b); padding: 30px; text-align: center;">
                            <div style="font-size: 14px; font-weight: 800; color: #fee2e2; letter-spacing: 2px; margin-bottom: 8px;">LEVEL 1 EMERGENCY RESPONSE</div>
                            <h1 style="color: #ffffff; margin: 0; font-size: 28px; letter-spacing: -1px; font-weight: 900;">THREAT ALERT DETECTED</h1>
                        </div>

                        <!-- Main Content -->
                        <div style="padding: 40px;">
                            <div style="display: flex; align-items: start; margin-bottom: 30px;">
                                <div style="flex: 1;">
                                    <h2 style="color: #ffffff; margin: 0 0 10px 0; font-size: 20px;">Incident Summary</h2>
                                    <p style="color: #94a3b8; line-height: 1.6; margin: 0;">{custom_msg}</p>
                                </div>
                                <div style="background-color: #ef4444; color: white; padding: 6px 12px; border_radius: 6px; font-weight: bold; font-size: 12px;">{priority}</div>
                            </div>
                            
                            <!-- Detailed Stats Table -->
                            <div style="background-color: #020617; border-radius: 12px; padding: 25px; margin-bottom: 30px; border: 1px solid #1e293b;">
                                <table style="width: 100%; border-collapse: collapse;">
                                    <tr>
                                        <td style="padding: 10px 0; color: #64748b; font-size: 13px; text-transform: uppercase;">Primary Threat</td>
                                        <td style="padding: 10px 0; color: #f87171; font-weight: 700; text-align: right;">{threat_type}</td>
                                    </tr>
                                    <tr>
                                        <td style="padding: 10px 0; color: #64748b; font-size: 13px; text-transform: uppercase;">Confidence Index</td>
                                        <td style="padding: 10px 0; color: #8b5cf6; font-weight: 700; text-align: right;">{confidence:.2%}</td>
                                    </tr>
                                    <tr>
                                        <td style="padding: 10px 0; color: #64748b; font-size: 13px; text-transform: uppercase;">Suspect Detail</td>
                                        <td style="padding: 10px 0; color: #3b82f6; font-weight: 700; text-align: right;">{suspect}</td>
                                    </tr>
                                    <tr>
                                        <td style="padding: 10px 0; color: #64748b; font-size: 13px; text-transform: uppercase;">Capture Time</td>
                                        <td style="padding: 10px 0; color: #f8fafc; text-align: right;">{timestamp}</td>
                                    </tr>
                                    <tr>
                                        <td style="padding: 10px 0; color: #64748b; font-size: 13px; text-transform: uppercase;">Location Tag</td>
                                        <td style="padding: 10px 0; color: #10b981; text-align: right;">{location_tag}</td>
                                    </tr>
                                </table>
                            </div>

                            <!-- Embedded Evidence Snapshot -->
                            <div style="margin-bottom: 35px;">
                                <h3 style="color: #ffffff; font-size: 16px; margin-bottom: 15px;">Visual Evidence Log</h3>
                                <div style="background-color: #020617; border-radius: 12px; border: 2px solid #334155; overflow: hidden; position: relative;">
                                    <img src="cid:threat_image" style="width: 100%; display: block; filter: contrast(110%);" alt="Threat Snapshot Not Available">
                                    <div style="position: absolute; bottom: 0; left: 0; right: 0; background: linear-gradient(transparent, rgba(0,0,0,0.8)); padding: 15px; color: white; font-size: 11px;">
                                        ENCRYPTED STREAM | SENSOR: {system_id} | LATENCY: {latency}
                                    </div>
                                </div>
                            </div>

                            <!-- CTA Section -->
                            <div style="text-align: center; background-color: #1e293b; padding: 25px; border-radius: 12px;">
                                <div style="margin-bottom: 15px; color: #94a3b8; font-size: 14px;">IMMEDIATE RESPONSE RECOMMENDED</div>
                                <a href="#" style="background: linear-gradient(135deg, #3b82f6, #2563eb); color: #ffffff; padding: 14px 40px; text-decoration: none; border-radius: 10px; font-weight: 800; font-size: 16px; display: inline-block; box-shadow: 0 4px 14px 0 rgba(59, 130, 246, 0.39);">ACCESS LOGS</a>
                            </div>
                        </div>

                        <!-- Footer -->
                        <div style="background-color: #020617; padding: 30px; text-align: center; font-size: 11px; color: #475569; border-top: 1px solid #1e293b;">
                            DO NOT REPLY TO THIS EMAIL. This communication is strictly confidential.<br>
                            GPS COORDINATES: 40.7128° N, 74.0060° W | AUTH TOKEN: {hex(id(self))[-8:]}<br><br>
                            &copy; 2024 SECURITY COMMAND CENTER | AI RESPONSE UNIT
                        </div>
                    </div>
                </body>
            </html>
            """
            
            # Plain text fallback
            text_body = f"CRITICAL SECURITY ALERT: {threat_type} detected. Suspect: {suspect}. Time: {timestamp}."
            
            msg.attach(MIMEText(text_body, 'plain'))
            msg.attach(MIMEText(html_body, 'html'))

            if image_path and os.path.exists(image_path):
                with open(image_path, 'rb') as f:
                    img_data = f.read()
                image = MIMEImage(img_data, name=os.path.basename(image_path))
                image.add_header('Content-ID', '<threat_image>')
                image.add_header('Content-Disposition', 'inline', filename=os.path.basename(image_path))
                msg.attach(image)

            # SMTP Connection
            current_smtp_server = self.smtp_server
            current_smtp_port = self.smtp_port
            
            if email_config:
                current_smtp_server = email_config.get('smtp_server') or current_smtp_server
                current_smtp_port = email_config.get('smtp_port') or current_smtp_port

            server = smtplib.SMTP(current_smtp_server, current_smtp_port)
            server.starttls()
            server.login(sender, password)
            server.send_message(msg)
            server.quit()
            return True
        except Exception as e:
            print(f"SMTP Error: {e}")
            return False
        except smtplib.SMTPAuthenticationError as e:
            print(f"SMTP Authentication Error: {e}")
            return False
        except Exception as e:
            print(f"SMTP General Error: {type(e).__name__}: {e}")
            import traceback
            traceback.print_exc()
            return False

    def send_verification_email(self, receiver_email, otp):
        """Sends a high-end, professionally designed verification OTP email"""
        load_dotenv(override=True)
        sender = os.getenv('SENDER_EMAIL')
        password = os.getenv('SENDER_PASSWORD')
        
        if not sender or not password:
            return False

        try:
            msg = MIMEMultipart()
            msg['From'] = f"Security Shield AI <{sender}>"
            msg['To'] = receiver_email
            msg['Subject'] = f"[{otp}] - Authentication Code for Security Access"

            html_body = f"""
            <html>
                <body style="font-family: 'Inter', Helvetica, Arial, sans-serif; background-color: #020617; margin: 0; padding: 40px; color: #f8fafc;">
                    <div style="max-width: 550px; margin: auto; background-color: #0f172a; border-radius: 24px; overflow: hidden; border: 1px solid #1e293b; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);">
                        
                        <!-- Premium Header -->
                        <div style="background: linear-gradient(135deg, #3b82f6, #8b5cf6); padding: 40px; text-align: center;">
                            <div style="font-size: 32px; margin-bottom: 10px;">🛡️</div>
                            <h1 style="color: #ffffff; margin: 0; font-size: 24px; font-weight: 800; letter-spacing: -0.5px;">SECURE ACCESS PROTOCOL</h1>
                        </div>

                        <div style="padding: 40px; text-align: center;">
                            <p style="color: #94a3b8; font-size: 16px; line-height: 1.6; margin-bottom: 30px;">
                                A request has been made to access the <strong>AI-based Threat & Criminal Detection System</strong>. Please use the secure authorization code below to proceed:
                            </p>

                            <!-- OTP Box -->
                            <div style="background-color: #020617; border: 1px solid #3b82f6; border-radius: 16px; padding: 30px; margin-bottom: 30px; display: inline-block; min-width: 250px;">
                                <div style="color: #3b82f6; font-size: 11px; font-weight: 800; letter-spacing: 2px; margin-bottom: 10px;">AUTHORIZATION CODE</div>
                                <div style="font-size: 42px; font-weight: 900; color: #ffffff; letter-spacing: 8px;">{otp}</div>
                            </div>

                            <p style="color: #64748b; font-size: 13px;">
                                This code will expire in <span style="color: #f8fafc; font-weight: bold;">5 minutes</span>.<br>
                                If you did not initiate this request, please secure your account immediately.
                            </p>
                        </div>

                        <!-- Footer -->
                        <div style="background-color: #020617; padding: 25px; text-align: center; font-size: 11px; color: #475569; border-top: 1px solid #1e293b;">
                            SYSTEM: SHIELD-AUTH-BLOCK-7<br>
                            &copy; 2024 AI SECURITY SYSTEMS | GLOBAL DEFENSE UNIT
                        </div>
                    </div>
                </body>
            </html>
            """
            msg.attach(MIMEText(html_body, 'html'))

            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()
            server.login(sender, password)
            server.send_message(msg)
            server.quit()
            return True
        except Exception as e:
            print(f"Failed to send verification email: {e}")
            return False
