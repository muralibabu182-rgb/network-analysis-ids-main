import os
import warnings
import numpy as np
import pandas as pd
import joblib
import streamlit as st

# Suppress TensorFlow warnings
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'

# Suppress warnings
warnings.filterwarnings('ignore', category=UserWarning)
warnings.filterwarnings('ignore', category=FutureWarning)
warnings.filterwarnings('ignore', category=DeprecationWarning)

# Import TensorFlow with error handling
try:
    import tensorflow as tf
    tf.get_logger().setLevel('ERROR')
    from tensorflow.keras.models import load_model
except ImportError as e:
    st.error(f"TensorFlow import error: {e}")
    st.stop()

# Model paths
MODEL_PATH = "./models/ids_model1.1.h5"
SCALER_PATH = "./models/scaler.pkl"
ENCODER_PATH = "./models/encoder.pkl"

def check_model_files():
    """Check if all required model files exist"""
    missing_files = []
    if not os.path.exists(MODEL_PATH):
        missing_files.append(MODEL_PATH)
    if not os.path.exists(SCALER_PATH):
        missing_files.append(SCALER_PATH)
    if not os.path.exists(ENCODER_PATH):
        missing_files.append(ENCODER_PATH)
    return missing_files

@st.cache_resource
def load_ids_model():
    """Load the IDS model, scaler, and encoder"""
    try:
        model = load_model(MODEL_PATH)
        scaler = joblib.load(SCALER_PATH)
        encoder = joblib.load(ENCODER_PATH)
        return model, scaler, encoder
    except Exception as e:
        st.error(f"Error loading model: {e}")
        return None, None, None

def run_detection_on_flows(df_flows, ids_features):
    """Run intrusion detection on flow features"""
    model, scaler, encoder = load_ids_model()
    
    # Check if model loading failed
    if model is None or scaler is None or encoder is None:
        return pd.DataFrame(), "Model loading failed. Please check the model files."
    
    if df_flows.empty:
        return pd.DataFrame(), "No flow features to analyze."
    
    # Check minimum flow requirement (30 flows)
    if len(df_flows) < 30:
        return pd.DataFrame(), f"Insufficient data for reliable detection. Need at least 30 flows, but only {len(df_flows)} flows available. Please capture more network traffic."
    
    missing = [col for col in ids_features if col not in df_flows.columns]
    if missing:
        return pd.DataFrame(), f"Missing required features: {missing}"
    
    try:
        X_scaled = scaler.transform(df_flows[ids_features])
        preds = model.predict(X_scaled)
        y_pred = np.argmax(preds, axis=1)
        labels = encoder.inverse_transform(y_pred)
        df_result = df_flows.copy()
        df_result['Prediction'] = labels
        return df_result, None
    except Exception as e:
        return pd.DataFrame(), f"Error during prediction: {e}"
