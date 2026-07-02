"""Optional AI object detection for snapshots using OpenCV Haar Cascades."""

import os

try:
    import cv2
    OPENCV_AVAILABLE = True
except ImportError:
    OPENCV_AVAILABLE = False

def detect_objects_in_snapshot(image_path, detect_face=True, detect_person=True):
    """Analyzes a saved camera snapshot for faces or persons using OpenCV.
    
    If OpenCV is installed and the XML cascade files are found, it draws
    bounding boxes around detected entities, saves the annotated image,
    and returns a list of detected threat tags.
    
    Returns:
        List of strings indicating detected objects (e.g., ["face", "person"]).
    """
    if not OPENCV_AVAILABLE:
        return []
    
    if not os.path.exists(image_path):
        return []

    if not detect_face and not detect_person:
        return []

    try:
        # Load pre-trained Haar Cascades from cv2 package or standard system folders
        cv2_data_dir = getattr(cv2, "data", None)
        if cv2_data_dir and hasattr(cv2_data_dir, "haarcascades"):
            face_cascade_file = os.path.join(cv2_data_dir.haarcascades, "haarcascade_frontalface_default.xml")
            body_cascade_file = os.path.join(cv2_data_dir.haarcascades, "haarcascade_fullbody.xml")
        else:
            # Fallback for systems where cv2 is installed via system package manager
            fallback_dir = "/usr/share/opencv4/haarcascades/"
            face_cascade_file = os.path.join(fallback_dir, "haarcascade_frontalface_default.xml")
            body_cascade_file = os.path.join(fallback_dir, "haarcascade_fullbody.xml")
            
        if not os.path.exists(face_cascade_file) or not os.path.exists(body_cascade_file):
            # Try home dir or local fallback search if still missing
            fallback_dir = "/usr/share/opencv/haarcascades/"
            face_cascade_file = os.path.join(fallback_dir, "haarcascade_frontalface_default.xml")
            body_cascade_file = os.path.join(fallback_dir, "haarcascade_fullbody.xml")
            
        if not os.path.exists(face_cascade_file) or not os.path.exists(body_cascade_file):
            return []

        face_cascade = cv2.CascadeClassifier(face_cascade_file)
        body_cascade = cv2.CascadeClassifier(body_cascade_file)

        # Read image
        img = cv2.imread(image_path)
        if img is None:
            return []

        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        
        detections = []
        
        # Detect full bodies (people)
        if detect_person:
            bodies = body_cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=3, minSize=(30, 70))
            for (x, y, w, h) in bodies:
                # Draw fuchsia box (BGR color: Fuchsia is #d946ef -> BGR is (239, 70, 217))
                cv2.rectangle(img, (x, y), (x + w, y + h), (239, 70, 217), 2)
                cv2.putText(img, "SUSPECTED PERSON", (x, y - 5), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (239, 70, 217), 1)
                detections.append("person")
            
        # Detect faces
        if detect_face:
            faces = face_cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(30, 30))
            for (x, y, w, h) in faces:
                # Draw cyan box (BGR color: Cyan is #06b6d4 -> BGR is (212, 182, 6))
                cv2.rectangle(img, (x, y), (x + w, y + h), (212, 182, 6), 2)
                cv2.putText(img, "FACE", (x, y - 5), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (212, 182, 6), 1)
                detections.append("face")

        # Save the annotated image back if we found any objects
        if detections:
            cv2.imwrite(image_path, img)

        return detections
    except Exception as e:
        print(f"[AI ANALYSIS ERROR] {e}")
        return []
