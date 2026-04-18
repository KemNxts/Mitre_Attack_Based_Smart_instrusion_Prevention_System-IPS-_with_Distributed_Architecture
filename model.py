import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
import joblib
import os
from preprocess import IPSPreprocessor

def generate_synthetic_data(samples=3000): # Increased samples for better accuracy
    np.random.seed(42)
    data = []
    
    # Attack Types: Normal, DoS, Brute Force, Port Scan, Bot, Web Attack
    attack_types = ['Normal', 'DoS', 'Brute Force', 'Port Scan', 'Bot', 'Web Attack']
    
    for _ in range(samples):
        attack = np.random.choice(attack_types)
        
        if attack == 'Normal':
            req_rate = np.random.uniform(1, 40)
            failed_logins = 0
            packet_size = np.random.uniform(200, 600)
            duration = np.random.uniform(1, 5)
            protocol = np.random.choice(['TCP', 'UDP', 'HTTP'])
        elif attack == 'DoS':
            req_rate = np.random.uniform(1500, 3000) # Clearly separated
            failed_logins = 0
            packet_size = np.random.uniform(1000, 1500)
            duration = np.random.uniform(0.01, 0.5)
            protocol = 'TCP'
        elif attack == 'Brute Force':
            req_rate = np.random.uniform(10, 80)
            failed_logins = np.random.randint(1, 40) # Broader range for distributed
            packet_size = np.random.uniform(300, 500)
            duration = np.random.uniform(0.5, 3)
            protocol = 'TCP'
        elif attack == 'Port Scan':
            req_rate = np.random.uniform(100, 500)
            failed_logins = 0
            packet_size = np.random.uniform(40, 100)
            duration = np.random.uniform(0.01, 0.2)
            protocol = 'TCP'
        elif attack == 'Bot':
            req_rate = np.random.uniform(400, 800)
            failed_logins = np.random.randint(0, 5) # Align with bot_attacker.py (0-2)
            packet_size = np.random.uniform(500, 1200)
            duration = np.random.uniform(1, 5)
            protocol = np.random.choice(['TCP', 'UDP'])
        elif attack == 'Web Attack':
            req_rate = np.random.uniform(5, 50)
            failed_logins = 0
            packet_size = np.random.uniform(1500, 4000) # Large payloads (SQLi)
            duration = np.random.uniform(1, 4)
            protocol = 'HTTP'
            
        data.append({
            'request_rate': req_rate,
            'failed_logins': failed_logins,
            'packet_size': packet_size,
            'duration': duration,
            'protocol': protocol,
            'label': attack
        })
        
    return pd.DataFrame(data)

def train_model():
    print("Generating distinct synthetic training data...")
    df = generate_synthetic_data(5000)
    
    preprocessor = IPSPreprocessor()
    X = preprocessor.preprocess(df, training=True)
    y = df['label']
    
    print("Training Random Forest Classifier...")
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X, y)
    
    if not os.path.exists('models'): os.makedirs('models')
    joblib.dump(model, 'models/ips_model.joblib')
    print("Model saved to models/ips_model.joblib")
    return model

def get_prediction(data):
    # This is kept for backward compatibility if needed, 
    # but server.py now uses GLOBAL_MODEL for performance.
    model_path = os.path.join('models', 'ips_model.joblib')
    if not os.path.exists(model_path):
        train_model()
    model = joblib.load(model_path)
    preprocessor = IPSPreprocessor()
    X = preprocessor.preprocess(data)
    prediction = model.predict(X)[0]
    probabilities = model.predict_proba(X)[0]
    confidence = float(np.max(probabilities))
    return prediction, confidence

if __name__ == "__main__":
    train_model()
