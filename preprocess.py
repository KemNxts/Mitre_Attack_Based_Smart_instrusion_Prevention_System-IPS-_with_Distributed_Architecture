import pandas as pd
from sklearn.preprocessing import StandardScaler
import joblib
import os

class IPSPreprocessor:
    def __init__(self):
        self.scaler = StandardScaler()
        self.protocol_map = {'TCP': 0, 'UDP': 1, 'ICMP': 2}
        self.model_dir = 'models'
        
    def encode_protocol(self, protocol):
        return self.protocol_map.get(protocol.upper(), 0)

    def preprocess(self, data, training=False):
        # Convert to DataFrame if it's a dict
        if isinstance(data, dict):
            df = pd.DataFrame([data])
        else:
            df = data.copy()
            
        # Encode protocol
        if 'protocol' in df.columns:
            df['protocol'] = df['protocol'].apply(self.encode_protocol)
            
        # Select features
        features = ['request_rate', 'failed_logins', 'packet_size', 'duration', 'protocol']
        X = df[features]
        
        # Scaling
        if training:
            X_scaled = self.scaler.fit_transform(X)
            # Save scaler for future use
            if not os.path.exists(self.model_dir):
                os.makedirs(self.model_dir)
            joblib.dump(self.scaler, os.path.join(self.model_dir, 'scaler.joblib'))
        else:
            # Load scaler if it exists
            scaler_path = os.path.join(self.model_dir, 'scaler.joblib')
            if os.path.exists(scaler_path):
                scaler = joblib.load(scaler_path)
                X_scaled = scaler.transform(X)
            else:
                X_scaled = X # Fallback (should not happen in production)
                
        return X_scaled
