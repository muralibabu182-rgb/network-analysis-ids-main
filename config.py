import os

# Model paths
MODEL_PATH = "./models/ids_model1.1.h5"
SCALER_PATH = "./models/scaler.pkl"
ENCODER_PATH = "./models/encoder.pkl"

# IDS Features
IDS_FEATURES = [
    'Fwd Seg Size Min', 'Init Fwd Win Bytes', 'Bwd Packets/s',
    'Fwd Packet Length Max', 'Bwd Header Length', 'Fwd Header Length',
    'Subflow Fwd Bytes', 'Fwd Packets Length Total',
    'Fwd Packet Length Std', 'Total Backward Packets',
    'Fwd Packet Length Mean', 'Flow IAT Mean', 'Subflow Bwd Packets',
    'Avg Fwd Segment Size', 'Flow Bytes/s', 'Packet Length Mean',
    'Fwd Act Data Packets', 'Flow IAT Max', 'Flow Packets/s',
    'Flow Duration'
]

# Page configuration
PAGE_CONFIG = {
    'page_title': "Advanced Network IDS Dashboard",
    'page_icon': "🛡️",
    'layout': "wide",
    'initial_sidebar_state': "expanded"
}

# Flow analysis settings
FLOW_SETTINGS = {
    'flow_timeout': 10,
    'max_packets': 10000
}

# Detection settings
DETECTION_SETTINGS = {
    'min_flows_required': 30
}

# Export formats
EXPORT_FORMATS = ["CSV", "JSON", "Excel"]
