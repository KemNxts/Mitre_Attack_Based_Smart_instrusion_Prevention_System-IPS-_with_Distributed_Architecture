import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
import joblib
import os
from preprocess import IPSPreprocessor

def generate_synthetic_data(samples=1000):
    np.random.seed(42)
    data = []
    
    # Attack Types: Normal, DoS, Brute Force, Port Scan, Bot, Web Attack
    attack_types = ['Normal', 'DoS', 'Brute Force', 'Port Scan', 'Bot', 'Web Attack']
    
    for _ in range(samples):
        attack = np.random.choice(attack_types)
        
        if attack == 'Normal':
            req_rate = np.random.uniform(1, 10)
            failed_logins = 0
            packet_size = np.random.uniform(50, 500)
            duration = np.random.uniform(0.1, 5)
            protocol = np.random.choice(['TCP', 'UDP'])
        elif attack == 'DoS':
            req_rate = np.random.uniform(100, 1000)
            failed_logins = 0
            packet_size = np.random.uniform(1000, 5000)
            duration = np.random.uniform(10, 60)
            protocol = 'TCP'
        elif attack == 'Brute Force':
            req_rate = np.random.uniform(10, 50)
            failed_logins = np.random.randint(5, 50)
            packet_size = np.random.uniform(100, 300)
            duration = np.random.uniform(5, 30)
            protocol = 'TCP'
        elif attack == 'Port Scan':
            req_rate = np.random.uniform(50, 200)
            failed_logins = 0
            packet_size = np.random.uniform(40, 64)
            duration = np.random.uniform(1, 10)
            protocol = 'TCP'
        elif attack == 'Bot':
            req_rate = np.random.uniform(5, 20)
            failed_logins = 0
            packet_size = np.random.uniform(100, 200)
            duration = np.random.uniform(3600, 86400) # Long duration
            protocol = 'UDP'
        elif attack == 'Web Attack':
            req_rate = np.random.uniform(1, 5)
            failed_logins = 0
            packet_size = np.random.uniform(500, 1500)
            duration = np.random.uniform(0.5, 2)
            protocol = 'TCP'
            
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
    print("Generating synthetic data...")
    df = generate_synthetic_data(2000)
    
    preprocessor = IPSPreprocessor()
    X = preprocessor.preprocess(df, training=True)
    y = df['label']
    
    print("Training Random Forest model...")
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X, y)
    
    model_path = os.path.join('models', 'ips_model.joblib')
    joblib.dump(model, model_path)
    print(f"Model saved to {model_path}")
    return model

def get_prediction(data):
    model_path = os.path.join('models', 'ips_model.joblib')
    if not os.path.exists(model_path):
        train_model()
        
    model = joblib.load(model_path)
    preprocessor = IPSPreprocessor()
    X = preprocessor.preprocess(data)
    
    prediction = model.predict(X)[0]
    return prediction

if __name__ == "__main__":
    train_model()
