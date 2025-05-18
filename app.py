import os
import random
import string
from flask import Flask, request, render_template, jsonify
from flask_mail import Mail, Message
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import cv2
import os
import time
import pandas as pd
from flask import Flask, render_template, Response
from ultralytics import YOLO
# Add this at the top of your main_app.py
from flask import jsonify
import base64
from datetime import datetime
from flask import Flask, request, jsonify, Response
import numpy as np
from io import BytesIO
from PIL import Image

# Global variable to store alerts
alerts = []



# Load environment variables
load_dotenv()

from flask import Flask
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # This will allow all domains to access your API

# MongoDB connection
client = MongoClient(os.getenv("MONGO_URI"))
db = client["ExamSecure"]
users_collection = db["users"]

# Flask-Mail configuration
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = os.getenv("EMAIL_USER")
app.config["MAIL_PASSWORD"] = os.getenv("EMAIL_PASS")
mail = Mail(app)

# Store OTPs in memory (for demo purposes)
otp_store = {}

# Generate a 6-digit OTP
def generate_otp():
    return "".join(random.choices(string.digits, k=6))

# Register user
@app.route("/register", methods=["POST"])
def register():
    data = request.json
    email = data.get("email")
    password = data.get("password")
    role = data.get("role")

    if not email or not password or not role:
        return jsonify({"error": "Email, password, and role are required"}), 400

    if users_collection.find_one({"email": email}):
        return jsonify({"error": "Email is already registered"}), 400

    # Validate password strength
    if len(password) < 8 or not any(c.isupper() for c in password) or not any(c.islower() for c in password) or not any(c.isdigit() for c in password):
        return jsonify({"error": "Password must be at least 8 characters with uppercase, lowercase, and a number"}), 400

    hashed_password = generate_password_hash(password)
    users_collection.insert_one({"email": email, "password": hashed_password, "role": role})

    otp = generate_otp()
    otp_store[email] = otp

    msg = Message("Your OTP for Registration", sender=app.config["MAIL_USERNAME"], recipients=[email])
    msg.body = f"Your OTP is: {otp}. It will expire in 10 minutes."
    mail.send(msg)

    return jsonify({"message": "User registered. Please check your email for OTP"}), 200

# Verify OTP for registration
@app.route("/verify-registration-otp", methods=["POST"])
def verify_registration_otp():
    data = request.json
    email, otp = data.get("email"), data.get("otp")

    if otp_store.get(email) == otp:
        del otp_store[email]
        return jsonify({"message": "OTP verified successfully"}), 200
    return jsonify({"error": "Invalid OTP"}), 400

# Login
@app.route("/login", methods=["POST"])
def login():
    data = request.json
    email, password, role = data.get("email"), data.get("password"), data.get("role")

    user = users_collection.find_one({"email": email})
    if not user or not check_password_hash(user["password"], password) or user["role"] != role:
        return jsonify({"error": "Invalid credentials"}), 400

    otp = generate_otp()
    otp_store[email] = otp

    msg = Message("Your OTP for Authentication", sender=app.config["MAIL_USERNAME"], recipients=[email])
    msg.body = f"Your OTP is: {otp}. It will expire in 10 minutes."
    mail.send(msg)

    return jsonify({"message": "Credentials verified. OTP sent"}), 200

# Function to get user role from MongoDB
def get_user_role_from_db(email):
    user = users_collection.find_one({"email": email})
    return user["role"] if user else None

def otp_is_valid(email, otp):
    return otp_store.get(email) == otp


# Verify OTP for login
@app.route('/verify-login-otp', methods=['POST'])
def verify_login_otp():
    data = request.json
    email = data.get("email")
    otp = data.get("otp")

    if otp_is_valid(email, otp):  # Check if OTP is valid
        user_role = get_user_role_from_db(email)  # Fetch user role
        return jsonify({"message": "OTP verified", "role": user_role}), 200
    else:
        return jsonify({"error": "Invalid OTP"}), 400



# Forgot Password: Send OTP
@app.route("/send-otp-for-password", methods=["POST"])
def send_otp_for_password():
    data = request.json
    email = data.get("email")

    if not users_collection.find_one({"email": email}):
        return jsonify({"error": "Email not found"}), 404

    otp = generate_otp()
    otp_store[email] = otp

    msg = Message("Your OTP for Password Reset", sender=app.config["MAIL_USERNAME"], recipients=[email])
    msg.body = f"Your OTP is: {otp}. It will expire in 10 minutes."
    mail.send(msg)

    return jsonify({"message": "OTP sent successfully"}), 200

# Verify OTP for password reset
@app.route("/verify-otp-for-password", methods=["POST"])
def verify_otp_for_password():
    data = request.json
    email, otp = data.get("email"), data.get("otp")

    if otp_store.get(email) == otp:
        return jsonify({"message": "OTP verified successfully"}), 200
    return jsonify({"error": "Invalid OTP"}), 400

# Update password
@app.route("/update-password", methods=["POST"])
def update_password():
    data = request.json
    email, new_password, confirm_password, otp = data.get("email"), data.get("newPassword"), data.get("confirmNewPassword"), data.get("otp")

    if otp_store.get(email) != otp:
        return jsonify({"error": "Invalid OTP"}), 400

    user = users_collection.find_one({"email": email})
    if not user:
        return jsonify({"error": "Email not found"}), 404

    if new_password != confirm_password:
        return jsonify({"error": "Passwords do not match"}), 400

    if len(new_password) < 8 or not any(c.isupper() for c in new_password) or not any(c.islower() for c in new_password) or not any(c.isdigit() for c in new_password):
        return jsonify({"error": "Password must be at least 8 characters with uppercase, lowercase, and a number"}), 400

    hashed_password = generate_password_hash(new_password)
    users_collection.update_one({"email": email}, {"$set": {"password": hashed_password}})

    del otp_store[email]  # Clear OTP
    return jsonify({"message": "Password reset successfully"}), 200

# Render templates for different pages
@app.route('/')
def index():
    return render_template('index.html')  

@app.route('/login')
def login_page():
    return render_template('sign in.html')  

@app.route('/register')
def register_page():
    return render_template('signup.html')  

@app.route('/administrator')
def administator():
    return render_template('administrator.html') 

@app.route('/staff')
def staff():
    return render_template('staff.html') 


@app.route('/watchlive')
def watchlive():
    return render_template('live_stream.html') 

@app.route('/anomalies')
def anomalies():
    return render_template('anomalies.html') 

@app.route('/examsched')
def examsched():
    return render_template('exam-sched.html') 


@app.route('/staffexamsched')
def staffexamsched():
    return render_template('staff_exam_schedule.html') 

@app.route('/signout')
def signout():
    return render_template('index.html') 

@app.route('/reset')
def reset():
    return render_template('forgot-password.html') 


# Load YOLO model
model = YOLO("yolov8_trained_model.pt")
print("Model classes:", model.names)

# Setup directories
save_directory = "static\cheating_frames"
log_file = "static\detection_log.csv"
os.makedirs(save_directory, exist_ok=True)


# Confidence threshold
confidence_threshold = 0.4

# Cooldown time to avoid redundant detections
cooldown_time = 5
last_detection_time = {}

df = pd.read_csv(log_file)


# Detection ID counter
detection_id = len(df) + 1


@app.route('/process_frame', methods=['POST'])
def process_frame():
    global detection_id, alerts
    
    if not request.json or 'frame' not in request.json:
        return jsonify({"error": "No frame data provided"}), 400
    
    try:
        # Get the base64 string without the data URL prefix if present
        frame_data = request.json['frame']
        if frame_data.startswith('data:image'):
            frame_data = frame_data.split(',')[1]
        
        # Decode the base64 image
        try:
            frame_bytes = base64.b64decode(frame_data)
            nparr = np.frombuffer(frame_bytes, np.uint8)
            frame = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
            
            if frame is None or frame.size == 0:
                app.logger.error("Decoded frame is empty or invalid")
                return jsonify({"error": "Invalid image data"}), 400
                
        except Exception as decode_error:
            app.logger.error(f"Image decoding error: {str(decode_error)}")
            return jsonify({"error": "Image decoding failed"}), 400
        
        # Create a copy for annotation
        annotated_frame = frame.copy()
        
        # Run YOLO inference
        results = model(frame)
        detections = []
        
        for box in results[0].boxes:
            x1, y1, x2, y2 = map(int, box.xyxy[0])
            confidence = box.conf[0].item()
            class_id = int(box.cls[0].item())
            class_name = model.names[class_id]

            # Draw bounding box and label
            color = (0, 255, 0)  # Green
            cv2.rectangle(annotated_frame, (x1, y1), (x2, y2), color, 2)
            label = f"{class_name} {confidence:.2f}"
            cv2.putText(annotated_frame, label, (x1, y1 - 10), 
                       cv2.FONT_HERSHEY_SIMPLEX, 0.5, color, 2)

            if class_name != "normal" and confidence > confidence_threshold:
                current_time = time.time()
                
                if (class_name not in last_detection_time or 
                    (current_time - last_detection_time[class_name]) > cooldown_time):
                    
                    last_detection_time[class_name] = current_time
                    
                    # Save original frame for evidence
                    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
                    filename = f"{class_name}_{timestamp}.jpg"
                    filepath = os.path.join(save_directory, filename)
                    cv2.imwrite(filepath, frame[y1:y2, x1:x2])
                    
                    alert_msg = f"Cheating detected: {class_name} with confidence {confidence:.2f}"
                    alerts.append(alert_msg)
                    
                    detections.append({
                        "class_name": class_name,
                        "confidence": confidence,
                        "bbox": [x1, y1, x2, y2],
                        "timestamp": timestamp
                    })

        # Encode the annotated frame to send back
        success, buffer = cv2.imencode('.jpg', annotated_frame)
        if not success:
            raise Exception("Could not encode annotated frame")
            
        encoded_frame = base64.b64encode(buffer).decode('utf-8')
        
        return jsonify({
            "status": "success",
            "detections": detections,
            "annotated_frame": encoded_frame,
            "timestamp": datetime.now().isoformat()
        })
    
    except Exception as e:
        app.logger.error(f"Error processing frame: {str(e)}")
        return jsonify({"error": str(e)}), 500



@app.route('/alerts')
def get_alerts():
    """Return the list of alerts and clear them if requested"""
    clear = request.args.get('clear', '').lower() == 'true'
    global alerts
    
    response_alerts = alerts.copy()
    
    if clear:
        alerts = []  # Clear alerts after sending
    
    return jsonify(response_alerts)


# For Render deployment
if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)