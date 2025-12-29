# AI-Based Threat and Criminal Detection System 🛡️

Advanced real-time surveillance system designed to detect weapons and recognize individuals against a criminal database.

## Features
- **Real-time Weapon Detection**: Uses YOLOv8 to identify potential threats (knives, etc.).
- **Face Recognition**: Matches individuals against a secure criminal database using DeepFace (VGG-Face).
- **Instant Alerts**: Logs threats and sends email notifications to authorities.
- **Secure Dashboard**: Premium Streamlit-based UI for monitoring and database management.
- **Evidence Logging**: Automatically captures and stores images of detected threats.

## Tech Stack
- **AI Models**: YOLOv8 (Ultralytics), DeepFace (VGG-Face, FaceNet)
- **Frameworks**: Streamlit (Dashboard), OpenCV (Image Processing)
- **Database**: SQLite
- **Language**: Python 3.9+

## Setup Instructions
1. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
2. **Configuration**:
   - Update the `.env` file with your email credentials for alert notifications.
   - For Gmail, use an [App Password](https://myaccount.google.com/apppasswords).
3. **Running the System**:
   ```bash
   streamlit run app.py
   ```

## Folder Structure
- `engine/`: Detection, recognition, and database logic.
- `data/criminals/`: Store images of known criminals here (named as `Name.jpg`).
- `data/evidence/`: Automatically stores images of detected threats.
- `models/`: Place custom YOLO weights (`weapon_detection.pt`) here.
- `styles/`: Custom CSS for the premium dashboard look.

## Future Enhancements
- Behavior analysis and crowd violence detection.
- Mobile alert app integration.
- Cloud-based deployment for large-scale surveillance.
- Emotion and voice-based threat detection.
