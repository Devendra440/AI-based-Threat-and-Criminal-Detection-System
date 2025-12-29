import cv2
import numpy as np
import os

class ThreatDetector:
    def __init__(self, model_path='models/weapon_detection.pt'):
        from ultralytics import YOLO
        # Check if model exists, if not use yolov8n as placeholder or download
        if not os.path.exists(model_path):
            print(f"Model {model_path} not found. using yolov8n.pt as baseline.")
            self.weapon_model = YOLO('yolov8n.pt') 
        else:
            self.weapon_model = YOLO(model_path)
            
        # Common threat classes in COCO: knife
        # If using a custom model, classes would be 'gun', 'knife', etc.
        self.threat_classes = ['knife', 'scissors'] 
        
    def detect_weapons(self, frame, return_all=False):
        # YOLOv8 handles resizing internally more reliably
        results = self.weapon_model(frame, verbose=False, conf=0.15, imgsz=640)
        detections = []
        
        # Expanded threat list (COCO classes + potential matches)
        # Added 'bottle' (potential cocktail), 'umbrella' (long weapon proxy)
        threat_list = [
            'knife', 'scissors', 'baseball bat', 'fork', 'fire extinguisher',
            'tools', 'blade', 'gun', 'weapon', 'handgun', 'pistol', 'rifle', 
            'bottle', 'umbrella', 'hammer', 'screwdriver'
        ]
        
        for r in results:
            boxes = r.boxes
            for box in boxes:
                cls_id = int(box.cls[0])
                cls_name = self.weapon_model.names[cls_id].lower()
                conf = float(box.conf[0])
                
                # Check for threats
                # Lowered strictness for proxies (cell phone/remote) to make testing easier
                is_threat = any(t in cls_name for t in threat_list) or \
                           (cls_name == 'remote' and conf > 0.35) or \
                           (cls_name == 'cell phone' and conf > 0.35)

                if is_threat or return_all:
                    # Get boxes (already scaled to original resolution by YOLO)
                    x1, y1, x2, y2 = box.xyxy[0].tolist()
                    detections.append({
                        'label': cls_name.upper(),
                        'confidence': conf,
                        'bbox': [int(x1), int(y1), int(x2), int(y2)],
                        'is_threat': is_threat
                    })
        return detections

class FaceRecognizer:
    def __init__(self, db_path='data/criminals'):
        self.db_path = db_path
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

            # img_path can be the cropped face numpy array
            results = DeepFace.find(img_path=face_image, 
                                    db_path=self.db_path, 
                                    enforce_detection=False, # Already cropped
                                    model_name='VGG-Face', 
                                    distance_metric='cosine',
                                    silent=True)
            
            if len(results) > 0 and not results[0].empty:
                match = results[0].iloc[0]
                identity = match['identity']
                name = os.path.basename(identity).split('.')[0]
                cosine = match['VGG-Face_cosine']
                return {'name': name, 'confidence': 1 - cosine}
            
            return None
        except Exception as e:
            print(f"Face recognition error: {e}")
            return None

    def detect_faces(self, frame):
        from deepface import DeepFace
        try:
            # Detect faces - lower strictness for better real-world detection
            faces = DeepFace.extract_faces(img_path=frame, 
                                          enforce_detection=False, 
                                          detector_backend='opencv')
            return faces
        except:
            return []
