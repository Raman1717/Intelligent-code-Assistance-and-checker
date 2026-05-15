from flask import Flask, request, jsonify 
import cv2
import numpy as np
from tensorflow.keras.models import load_model
from flask_cors import CORS
import mysql.connector
from mysql.connector import Error

app = Flask(__name__)
CORS(app)

# Database configuration
db_config = {
    'host': 'localhost',
    'database': 'BrainTumorDB', 
    'user': 'root',
    'password': 'Raman@mysql'
}

# Load trained model
model = load_model("vgg19_model_03.h5")

def create_db_connection():
    try:
        connection = mysql.connector.connect(**db_config)
        return connection
    except Error as e:
        print(f"Error connecting to MySQL: {e}")
        return None

def generate_next_patient_id():
    connection = create_db_connection()
    if connection is None:
        return None
    try:
        cursor = connection.cursor()
        cursor.execute("SELECT patient_id FROM patients ORDER BY patient_id DESC LIMIT 1")
        result = cursor.fetchone()
        if result:
            last_id = result[0]
            number = int(last_id.split('_')[1]) + 1
        else:
            number = 1
        return f"P_{number:02d}"
    except Error as e:
        print(f"Error fetching patient_id: {e}")
        return None
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

def insert_patient_data(data):
    connection = create_db_connection()
    if connection is None:
        return False
    try:
        cursor = connection.cursor()
        query = """
        INSERT INTO patients 
        (patient_id, name, phone, age, blood_type, tumor_result, confidence_score) 
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        cursor.execute(query, (
            data['patient_id'],
            data['name'],
            data['phone'],
            data['age'],
            data['blood_type'],
            data['tumor_result'],
            data['confidence_score']
        ))
        connection.commit()
        return True
    except Error as e:
        print(f"Error inserting data: {e}")
        return False
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

def crop_brain_tumor(image):
    try:
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        gray = cv2.GaussianBlur(gray, (5, 5), 0)
        thres = cv2.threshold(gray, 45, 255, cv2.THRESH_BINARY)[1]
        thres = cv2.erode(thres, None, iterations=2)
        thres = cv2.dilate(thres, None, iterations=2)

        cnts, _ = cv2.findContours(thres.copy(), cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        if not cnts:
            return None
        c = max(cnts, key=cv2.contourArea)
        x, y, w, h = cv2.boundingRect(c)
        return image[y:y+h, x:x+w]
    except Exception as e:
        print("Error in cropping:", e)
        return None

@app.route("/predict", methods=["POST"])
def predict():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No selected file"}), 400

    try:
        name = request.form.get("name", "").strip()
        phone = request.form.get("phn", "").strip()
        age = request.form.get("age", "").strip()
        blood_type = request.form.get("bloodType", "").strip()

        if not all([name, phone, age, blood_type]):
            return jsonify({"error": "All patient information fields are required"}), 400

        image_bytes = file.read()
        np_image = np.frombuffer(image_bytes, np.uint8)
        image = cv2.imdecode(np_image, cv2.IMREAD_COLOR)

        if image is None:
            return jsonify({"error": "Invalid image format"}), 400

        image = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
        cropped_img = crop_brain_tumor(image)

        patient_id = generate_next_patient_id()
        if not patient_id:
            return jsonify({"error": "Failed to generate patient ID"}), 500

        if cropped_img is None:
            result = "Tumor -ve"
            confidence = "100%"
        else:
            resized_img = cv2.resize(cropped_img, (240, 240))
            resized_img = resized_img / 255.0
            resized_img = np.expand_dims(resized_img, axis=0)
            prediction = model.predict(resized_img)[0]
            confidence_neg = float(prediction[0]) * 100
            confidence_pos = float(prediction[1]) * 100
            if np.argmax(prediction) == 0:
                result = "Tumor -ve"
                confidence = f"{confidence_neg:.2f}%"
            else:
                result = "Tumor +ve"
                confidence = f"{confidence_pos:.2f}%"

        db_data = {
            "patient_id": patient_id,
            "name": name,
            "phone": phone,
            "age": int(age),
            "blood_type": blood_type,
            "tumor_result": result,
            "confidence_score": confidence
        }
        insert_patient_data(db_data)

        response_data = {
            "patient_id": patient_id,
            "prediction": result,
            "confidence": confidence,
            "name": name,
            "phone": phone,
            "age": age,
            "blood_type": blood_type
        }
        return jsonify(response_data), 200

    except Exception as e:
        print("Error:", str(e))
        return jsonify({"error": "Internal server error"}), 500

if __name__ == "__main__":
    app.run(debug=True)