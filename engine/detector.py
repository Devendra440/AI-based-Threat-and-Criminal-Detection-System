import cv2
import numpy as np
import os

class ThreatDetector:
    def __init__(self, model_path='models/weapon_detection.pt'):
        try:
            from ultralytics import YOLO, YOLOWorld
            
            # Check if custom model exists
            if os.path.exists(model_path):
                print(f"Loading custom weapon detection model: {model_path}")
                self.weapon_model = YOLO(model_path)
                self.model_type = 'custom'
            else:
                # UPGRADE: Using Nano version for much faster real-time detection
                print("Using YOLO-World Nano for high-speed threat detection.")
                try:
                    # Using 'v8n' instead of 'v8s' for lower latency
                    self.weapon_model = YOLOWorld('yolov8n-worldv2.pt')
                    
                    # Expanded comprehensive vocabulary for various threat types
                    self.threat_classes = [
                        "handgun", "pistol", "revolver", "rifle", "shotgun", "machine gun",
                        "knife", "dagger", "machete", "sword", "axe", "hatchet",
                        "baseball bat", "crowbar", "hammer", "wrench", "chainsaw",
                        "scissors", "screwdriver", "razor", "blade", "bomb", "explosive",
                        "molotov cocktail", "grenade", "pepper spray", "taser"
                    ]
                    
                    self.weapon_model.set_classes(self.threat_classes)
                    self.model_type = 'world'
                except Exception as e:
                    print(f"YOLO-World failed: {e}. Falling back to standard YOLOv8n.")
                    self.weapon_model = YOLO('yolov8n.pt')
                    self.model_type = 'coco'
                    
            # Define threat classes for COCO fallback (Standard YOLOv8n classes)
            if self.model_type == 'coco':
                # Including more potential threat-related COCO classes
                # 34: baseball bat, 39: bottle, 43: knife, 76: scissors, 35: glove? No.
                # 0: person (we don't want to alert on all people here, but could be useful)
                self.target_classes = [34, 39, 43, 76] 
            else:
                self.target_classes = None
        except Exception as e:
            print(f"Error initializing detector: {e}")
            self.weapon_model = None

    def detect_weapons(self, frame, conf=0.25, return_all=False):
        if not self.weapon_model:
            return []
            
        try:
            # Run inference
            if self.model_type == 'coco':
                results = self.weapon_model(frame, verbose=False, conf=conf, imgsz=640, classes=self.target_classes)
            else:
                results = self.weapon_model(frame, verbose=False, conf=conf, imgsz=640)
                
            detections = []
            
            # Additional keywords for filtering if using non-world models
            threat_keywords = [
                'knife', 'scissors', 'bat', 'gun', 'pistol', 'rifle', 'weapon', 
                'firearm', 'blade', 'dagger', 'sword', 'hammer', 'machete', 'handgun',
                'shotgun', 'revolver', 'crowbar', 'wrench', 'axe', 'hatchet', 'razor',
                'bomb', 'grenade', 'explosive', 'taser', 'chainsaw'
            ]
            
            for r in results:
                boxes = r.boxes
                for box in boxes:
                    cls_id = int(box.cls[0])
                    cls_name = self.weapon_model.names[cls_id].lower()
                    score = float(box.conf[0])
                    
                    is_threat = False
                    
                    if self.model_type == 'world':
                        # In world mode, all set classes are threats
                        is_threat = True
                    elif self.model_type == 'coco':
                        # Fixed coco classes are already filtered
                        is_threat = True 
                    else:
                        # For custom models, check against our expansive keyword list
                        is_threat = any(t in cls_name for t in threat_keywords) or 'weapon' in cls_name
                    
                    if is_threat or return_all:
                        x1, y1, x2, y2 = box.xyxy[0].tolist()
                        detections.append({
                            'label': cls_name.upper(),
                            'confidence': score,
                            'bbox': [int(x1), int(y1), int(x2), int(y2)],
                            'is_threat': is_threat
                        })
                        
            return detections
        except Exception as e:
            print(f"Detection error: {e}")
            return []

class FaceRecognizer:
    def __init__(self, db_path='data/criminals'):
        self.db_path = db_path
        # Use more advanced models
        self.recognition_model = 'Facenet512' # High accuracy
        # SWITCH: Using 'mediapipe' for faster detection with good accuracy
        self.detection_backend = 'mediapipe' 
        
        if not os.path.exists(self.db_path):
            os.makedirs(self.db_path)

    def identify_face(self, face_image):
        from deepface import DeepFace
        try:
            # Check if database has images
            image_extensions = ('.jpg', '.jpeg', '.png')
            has_images = any(f.lower().endswith(image_extensions) for f in os.listdir(self.db_path))
            
            if not has_images:
                return None

            # Efficient search with improved model
            # Use distance_metric='cosine' as it's standard for Facenet
            results = DeepFace.find(img_path=face_image, 
                                    db_path=self.db_path, 
                                    enforce_detection=False, 
                                    model_name=self.recognition_model, 
                                    distance_metric='cosine',
                                    detector_backend=self.detection_backend,
                                    silent=True)
            
            if len(results) > 0 and not results[0].empty:
                match = results[0].iloc[0]
                identity = match['identity']
                name = os.path.basename(identity).split('.')[0]
                name = name.replace('\\', '/').split('/')[-1]
                
                cosine = match[f'{self.recognition_model}_cosine']
                confidence = 1 - cosine
                
                return {'name': name, 'confidence': confidence}
            
            return None
        except Exception as e:
            print(f"Face recognition error: {e}")
            return None

    def detect_faces(self, frame):
        from deepface import DeepFace
        try:
            # Mediapipe is much faster than retinaface for real-time applications
            faces = DeepFace.extract_faces(img_path=frame, 
                                          enforce_detection=False, 
                                          detector_backend=self.detection_backend,
                                          align=True)
            return faces
        except Exception as e:
            print(f"Face detection error: {e}")
            return []


