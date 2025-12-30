# AI-Based Threat and Criminal Detection System 🛡️

Advanced real-time surveillance system designed to detect weapons and recognize individuals against a criminal database using state-of-the-art AI.

## 🚀 Recent Upgrades
- **Zero-Shot Threat Detection**: Now uses **YOLO-World** to detect a vast range of weapons (Guns, Pistols, Rifles, Machetes, etc.) without needing custom training.
- **High-Accuracy Recognition**: Upgraded to **Facenet512** for precise identification.
- **Fast Performance**: Optimized with **MediaPipe** face detection and intelligent frame-skipping.
- **Enterprise Alerts**: Professional HTML email alerts with embedded evidence snapshots.
- **Cloud Backend**: Migrated to **MongoDB Atlas** for secure, scalable data storage.

## ## Features
- **Real-time Surveillance**: Multi-threaded live monitoring with minimal latency.
- **Criminal Identification**: Automated matching against a managed database.
- **Dynamic Threat Vocabulary**: Capable of detecting 25+ types of weapons and dangerous objects.
- **Premium UI**: "Nightshade & Crystal" themed dashboard with advanced analytics.
- **Automated Evidence**: Captures snapshots of every single detected threat.

## ## Tech Stack
- **AI Models**: YOLO-World (v8n), Facenet512, MediaPipe.
- **Framework**: Streamlit, OpenCV.
- **Database**: MongoDB Atlas (Multi-Cloud).
- **Communication**: SMTP with Enterprise HTML Templates.

## ## Setup Instructions
1. **Repository Installation**:
   ```bash
   git clone <repo-url>
   cd "AI-based Threat and Criminal Detection System"
   pip install -r requirements.txt
   ```
2. **Environment Configuration**:
   Create a `.env` file or set Streamlit Secrets with:
   - `MONGO_URI`: Your MongoDB connection string.
   - `SENDER_EMAIL`: Email for sending alerts.
   - `SENDER_PASSWORD`: App password for the sender email.
   - `RECEIVER_EMAIL`: Destination email for alerts.

3. **Execution**:
   ```bash
   streamlit run app.py
   ```

## ☁️ Streamlit Cloud Deployment
To deploy this project to Streamlit Cloud:
1. Push this code to a public/private GitHub repository.
2. Connect your GitHub account to [Streamlit Cloud](https://share.streamlit.io/).
3. Add the following keys to your **Streamlit Secrets** (Advanced Settings):
   ```toml
   MONGO_URI = "your_mongodb_uri"
   SENDER_EMAIL = "your_email"
   SENDER_PASSWORD = "your_app_password"
   RECEIVER_EMAIL = "dest_email"
   ```
4. Deploy the `app.py` file.

## ## Folder Structure
- `engine/`: Core detection, recognition, and SMTP alert logic.
- `data/criminals/`: Local cache for criminal images.
- `styles/`: Premium CSS stylings.
- `models/`: (Ignored) Auto-downloads required AI weights.

---
&copy; 2024 AI Security Command Center. All Rights Reserved.
