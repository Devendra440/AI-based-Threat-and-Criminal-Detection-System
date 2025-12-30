import os
from datetime import datetime
import pymongo
from pymongo import MongoClient
import certifi

class CriminalDatabase:
    def __init__(self):
        # Load URI from env or use the provided one directly as fallback
        self.mongo_uri = os.getenv('MONGO_URI')
        if not self.mongo_uri:
             # Fallback if env var update hasn't propagated immediately in session
             self.mongo_uri = "mongodb+srv://pinnamguptha1234_db_user:rqYA93teJ6BfeEYv@cluster0.fv1skfs.mongodb.net/?appName=Cluster0"
        
        self.init_db()

    def init_db(self):
        try:
            # Using certifi for SSL certificate verification to avoid common connection errors
            self.client = MongoClient(self.mongo_uri, tlsCAFile=certifi.where())
            self.db = self.client['security_system_db']
            
            # Collections
            self.criminals = self.db['criminals']
            self.alerts = self.db['alerts']
            self.users = self.db['users']
            
            # Create indexes for unique fields
            self.users.create_index("username", unique=True)
            
            print("Connected to MongoDB Atlas successfully.")
        except Exception as e:
            print(f"Failed to connect to MongoDB: {e}")
            raise e

    def add_criminal(self, name, age, crime_type, threat_level, image_path):
        try:
            criminal_data = {
                "name": name, 
                "age": age, 
                "crime_type": crime_type, 
                "threat_level": threat_level, 
                "image_path": image_path,
                "last_seen": datetime.now()
            }
            self.criminals.insert_one(criminal_data)
        except Exception as e:
            print(f"Error adding criminal: {e}")

    def log_alert(self, threat_type, confidence, image_evidence_path):
        try:
            timestamp = datetime.now()
            alert_data = {
                "timestamp": timestamp,
                "threat_type": threat_type,
                "confidence": confidence,
                "image_evidence_path": image_evidence_path,
                "status": "UNREAD"
            }
            self.alerts.insert_one(alert_data)
            self.log_to_csv(timestamp.strftime('%Y-%m-%d %H:%M:%S'), threat_type, confidence, image_evidence_path)
        except Exception as e:
            print(f"Error logging alert: {e}")

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
        try:
            # Convert Cursor to list; format usually expected as tuples for legacy compatibility in app?
            # The app seems to use standard list access. Let's return list of dicts.
            # Wait, the app uses len() on it in line 803. List of dicts works fine.
            return list(self.criminals.find())
        except Exception as e:
            print(f"Error fetching criminals: {e}")
            return []

    def get_alerts(self):
        try:
            # Return raw alert dicts, but note the app expects tuples in line 1162 (alert[2], alert[5]).
            # We MUST maintain compatibility with the app's tuple indexing if we don't change the app.
            # App reads: alert[1](time), alert[2](threat), alert[3](conf), alert[5](status)
            # Tuple map based on SQLite: (id, timestamp, threat_type, confidence, image, status)
            
            alerts = list(self.alerts.find().sort("timestamp", -1))
            formatted_alerts = []
            for a in alerts:
                # Format timestamp string if needed, or keep object
                ts = a['timestamp'].strftime('%Y-%m-%d %H:%M:%S') if isinstance(a['timestamp'], datetime) else str(a['timestamp'])
                formatted_alerts.append((
                    str(a['_id']),
                    ts,
                    a['threat_type'],
                    a['confidence'],
                    a['image_evidence_path'],
                    a.get('status', 'UNREAD')
                ))
            return formatted_alerts
        except Exception as e:
            print(f"Error fetching alerts: {e}")
            return []

    def delete_criminal(self, criminal_id):
        try:
            # ID in Mongo is ObjectId, but app might pass string or int. 
            # If migrating from SQLite, IDs might be ints.
            # For now, let's try to delete by matching _id or 'id' field if we migrated data.
            # Since this is a fresh connection, we assume new data uses _id.
            from bson.objectid import ObjectId
            
            # Find first to get image path
            query = {"_id": ObjectId(criminal_id)} if isinstance(criminal_id, str) and len(criminal_id) == 24 else {"original_id": criminal_id}
            
            criminal = self.criminals.find_one(query)
            if criminal:
                self.criminals.delete_one(query)
                return criminal.get('image_path')
            return None
        except Exception as e:
            print(f"Error deleting criminal: {e}")
            return None

    # User Management Methods
    def register_user(self, username, password, receiver_email, sender_email=None, sender_password=None):
        try:
            user_data = {
                "username": username,
                "password": password,
                "receiver_email": receiver_email,
                "sender_email": sender_email,
                "sender_password": sender_password
            }
            self.users.insert_one(user_data)
            return True
        except pymongo.errors.DuplicateKeyError:
            return False
        except Exception as e:
            print(f"Registration error: {e}")
            return False

    def authenticate_user(self, username, password):
        try:
            user = self.users.find_one({"username": username, "password": password})
            if user:
                return {
                    'id': str(user['_id']),
                    'username': user['username'],
                    'password': user['password'],
                    'receiver_email': user['receiver_email'],
                    'sender_email': user.get('sender_email'),
                    'sender_password': user.get('sender_password')
                }
            return None
        except Exception as e:
            print(f"Auth error: {e}")
            return None

    def user_exists(self, username):
        return self.users.find_one({"username": username}) is not None
