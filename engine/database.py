import sqlite3
import os
from datetime import datetime

class CriminalDatabase:
    def __init__(self, db_path='data/security_system.db'):
        self.db_path = db_path
        self.init_db()

    def init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Criminals table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS criminals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                age INTEGER,
                crime_type TEXT,
                threat_level TEXT,
                image_path TEXT,
                last_seen DATETIME
            )
        ''')
        
        # Alerts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME,
                threat_type TEXT,
                confidence REAL,
                image_evidence_path TEXT,
                status TEXT
            )
        ''')
        
        conn.commit()
        conn.close()

    def add_criminal(self, name, age, crime_type, threat_level, image_path):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO criminals (name, age, crime_type, threat_level, image_path)
            VALUES (?, ?, ?, ?, ?)
        ''', (name, age, crime_type, threat_level, image_path))
        conn.commit()
        conn.close()

    def log_alert(self, threat_type, confidence, image_evidence_path):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute('''
            INSERT INTO alerts (timestamp, threat_type, confidence, image_evidence_path, status)
            VALUES (?, ?, ?, ?, ?)
        ''', (timestamp, threat_type, confidence, image_evidence_path, 'UNREAD'))
        conn.commit()
        conn.close()
        self.log_to_csv(timestamp, threat_type, confidence, image_evidence_path)

    def log_to_csv(self, timestamp, threat_type, confidence, image_path):
        import csv
        log_file = 'data/detection_log.csv'
        file_exists = os.path.isfile(log_file)
        with open(log_file, mode='a', newline='') as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow(['Timestamp', 'Threat Type', 'Confidence', 'Image Path'])
            writer.writerow([timestamp, threat_type, f"{confidence:.2%}", image_path])

    def get_all_criminals(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM criminals')
        rows = cursor.fetchall()
        conn.close()
        return rows

    def get_alerts(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM alerts ORDER BY timestamp DESC')
        rows = cursor.fetchall()
        conn.close()
        return rows

    def delete_criminal(self, criminal_id):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        # Get image path before deleting
        cursor.execute('SELECT image_path FROM criminals WHERE id = ?', (criminal_id,))
        row = cursor.fetchone()
        image_path = row[0] if row else None
        
        cursor.execute('DELETE FROM criminals WHERE id = ?', (criminal_id,))
        conn.commit()
        conn.close()
        return image_path
