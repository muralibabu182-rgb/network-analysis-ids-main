import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from scapy.all import sniff, IP, TCP, UDP
import threading
import time
from datetime import datetime, timedelta
import logging
from collections import defaultdict
import numpy as np
import joblib
import warnings
import os
import io

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

import base64
from io import BytesIO

# ---- PAGE CONFIGURATION ---- #
st.set_page_config(
    page_title="Advanced Network IDS Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ---- CUSTOM CSS FOR PROFESSIONAL STYLING ---- #
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(90deg, #1e3c72 0%, #2a5298 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        text-align: center;
        margin-bottom: 2rem;
    }
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        text-align: center;
        margin: 0.5rem 0;
    }
    .alert-box {
        background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        text-align: center;
        margin: 1rem 0;
        animation: pulse 2s infinite;
    }
    .success-box {
        background: linear-gradient(135deg, #00b894 0%, #00a085 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        text-align: center;
        margin: 1rem 0;
    }
    @keyframes pulse {
        0% { opacity: 1; }
        50% { opacity: 0.8; }
        100% { opacity: 1; }
    }
    .sidebar .sidebar-content {
        background: linear-gradient(180deg, #2c3e50 0%, #34495e 100%);
    }
</style>
""", unsafe_allow_html=True)

# ---- IDS MODEL SETUP ---- #
MODEL_PATH = "ids_model1.1.h5"
SCALER_PATH = "scaler.pkl"
ENCODER_PATH = "label_encoder.pkl"

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

# ---- ENHANCED PACKET PROCESSOR ---- #
class EnhancedPacketProcessor:
    def __init__(self):
        self.protocol_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
        self.packet_data = []
        self.start_time = datetime.now()
        self.lock = threading.Lock()
        self.flow_cache = defaultdict(list)
        self.flow_features = []
        self.flow_timeout = 10
        self.attack_detections = []
        self.total_packets = 0
        self.suspicious_flows = 0

    def get_protocol_name(self, proto_num):
        return self.protocol_map.get(proto_num, f'OTHER({proto_num})')

    def get_flow_key(self, packet):
        try:
            ip = packet[IP]
            proto = 'TCP' if TCP in packet else 'UDP' if UDP in packet else 'OTHER'
            sport = packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else 0
            dport = packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else 0
            if (ip.src, sport) <= (ip.dst, dport):
                return (ip.src, ip.dst, sport, dport, proto)
            else:
                return (ip.dst, ip.src, dport, sport, proto)
        except Exception as e:
            logging.warning(f"Flow key error: {e}")
            return None

    def process_packet(self, packet):
        try:
            if IP in packet:
                now = datetime.now()
                with self.lock:
                    self.total_packets += 1
                    pkt = {
                        'timestamp': now,
                        'source': packet[IP].src,
                        'destination': packet[IP].dst,
                        'protocol': self.get_protocol_name(packet[IP].proto),
                        'size': len(packet),
                        'time_relative': (now - self.start_time).total_seconds()
                    }
                    if TCP in packet:
                        pkt.update({
                            'src_port': packet[TCP].sport,
                            'dst_port': packet[TCP].dport,
                            'tcp_flags': packet[TCP].flags
                        })
                        hdr_len = packet[TCP].dataofs * 4
                    elif UDP in packet:
                        pkt.update({
                            'src_port': packet[UDP].sport,
                            'dst_port': packet[UDP].dport
                        })
                        hdr_len = 8
                    else:
                        hdr_len = 0
                    self.packet_data.append(pkt)
                    if len(self.packet_data) > 10000:
                        self.packet_data = self.packet_data[-10000:]
                    self.add_to_flow(packet, now, hdr_len)
        except Exception as e:
            logging.error(f"Error processing packet: {e}")

    def add_to_flow(self, packet, timestamp, hdr_len=0):
        key = self.get_flow_key(packet)
        if key is None:
            return
        direction = 'fwd' if packet[IP].src == key[0] else 'bwd'
        src_ip = packet[IP].src
        src_port = packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else 0
        if (src_ip, src_port) == (key[0], key[2]):
            direction = 'fwd'
        else:
            direction = 'bwd'
        flow = self.flow_cache[key]
        flow.append({
            'timestamp': timestamp,
            'size': len(packet),
            'direction': direction,
            'header_len': hdr_len
        })
        if len(flow) > 1:
            duration = (timestamp - flow[0]['timestamp']).total_seconds()
            if duration > self.flow_timeout:
                self.compute_flow_features(key)
        if len(flow) == 1 and TCP in packet and packet[IP].src == key[0]:
            self.flow_cache[key][0]['init_win_bytes'] = packet[TCP].window

    def compute_flow_features(self, key):
        try:
            flow = self.flow_cache[key]
            if not flow:
                return
            times = [p['timestamp'] for p in flow]
            duration = (times[-1] - times[0]).total_seconds() if len(times) > 1 else 0.0001
            iats = [(times[i] - times[i-1]).total_seconds() for i in range(1, len(times))]
            fwd_sizes = [p['size'] for p in flow if p['direction'] == 'fwd']
            bwd_sizes = [p['size'] for p in flow if p['direction'] == 'bwd']
            fwd_hdrs = [p['header_len'] for p in flow if p['direction'] == 'fwd']
            bwd_hdrs = [p['header_len'] for p in flow if p['direction'] == 'bwd']
            init_win = flow[0].get('init_win_bytes', 0)
            
            # Ensure all calculations are safe
            features = {
                'Flow Duration': float(duration),
                'Total Backward Packets': int(len(bwd_sizes)),
                'Fwd Packet Length Mean': float(np.mean(fwd_sizes) if fwd_sizes else 0),
                'Fwd Packet Length Std': float(np.std(fwd_sizes) if fwd_sizes else 0),
                'Fwd Packet Length Max': float(max(fwd_sizes) if fwd_sizes else 0),
                'Fwd Packets Length Total': float(sum(fwd_sizes)),
                'Fwd Seg Size Min': float(min(fwd_sizes) if fwd_sizes else 0),
                'Fwd Header Length': float(sum(fwd_hdrs)),
                'Bwd Header Length': float(sum(bwd_hdrs)),
                'Flow Bytes/s': float((sum(fwd_sizes) + sum(bwd_sizes)) / duration),
                'Flow Packets/s': float(len(flow) / duration),
                'Packet Length Mean': float(np.mean(fwd_sizes + bwd_sizes)),
                'Init Fwd Win Bytes': float(init_win),
                'Avg Fwd Segment Size': float(np.mean(fwd_sizes) if fwd_sizes else 0),
                'Bwd Packets/s': float(len(bwd_sizes) / duration if duration > 0 else 0),
                'Flow IAT Mean': float(np.mean(iats) if iats else 0),
                'Flow IAT Max': float(max(iats) if iats else 0),
                'Subflow Fwd Bytes': float(sum(fwd_sizes)),
                'Subflow Bwd Packets': int(len(bwd_sizes)),
                'Fwd Act Data Packets': int(len([p for p in flow if p['direction'] == 'fwd' and p['size'] > 0]))
            }
            
            # Verify all expected features are present
            for feature_name in IDS_FEATURES:
                if feature_name not in features:
                    features[feature_name] = 0.0
            
            self.flow_features.append(features)
            del self.flow_cache[key]
        except Exception as e:
            # Log error but don't crash the app
            print(f"Error computing flow features: {e}")
            if key in self.flow_cache:
                del self.flow_cache[key]

    def get_dataframe(self):
        with self.lock:
            return pd.DataFrame(self.packet_data)

    def get_flow_feature_dataframe(self):
        try:
            if not self.flow_features:
                return pd.DataFrame()
            
            # Ensure all features have the same keys
            expected_keys = set(IDS_FEATURES)
            cleaned_features = []
            
            for feature in self.flow_features:
                # Create a clean feature dict with all expected keys
                clean_feature = {}
                for key in expected_keys:
                    clean_feature[key] = feature.get(key, 0.0)  # Default to 0.0 if missing
                cleaned_features.append(clean_feature)
            
            return pd.DataFrame(cleaned_features)
        except Exception as e:
            st.error(f"Error creating flow features DataFrame: {e}")
            return pd.DataFrame()

    def get_statistics(self):
        df = self.get_dataframe()
        df_flows = self.get_flow_feature_dataframe()
        return {
            'total_packets': len(df),
            'total_flows': len(df_flows),
            'unique_sources': df['source'].nunique() if not df.empty else 0,
            'unique_destinations': df['destination'].nunique() if not df.empty else 0,
            'protocols': df['protocol'].value_counts().to_dict() if not df.empty else {},
            'avg_packet_size': df['size'].mean() if not df.empty else 0,
            'total_bytes': df['size'].sum() if not df.empty else 0
        }

# ---- SHARED STATE ---- #
@st.cache_resource
def get_processor():
    processor = EnhancedPacketProcessor()
    return processor

# ---- PACKET CAPTURE THREAD ---- #
def start_sniffing(processor, stop_event):
    def _sniff():
        sniff(prn=processor.process_packet, store=False, stop_filter=lambda x: stop_event.is_set())
    t = threading.Thread(target=_sniff, daemon=True)
    t.start()
    return t

# ---- ENHANCED VISUALIZATIONS ---- #
def create_enhanced_visualizations(df, df_flows):
    if df.empty:
        st.warning("No packet data available. Start capture to see visualizations.")
        return

    # Create subplots for better layout
    fig = make_subplots(
        rows=2, cols=2,
        subplot_titles=('Protocol Distribution', 'Packets per Second', 'Top Source IPs', 'Packet Size Distribution'),
        specs=[[{"type": "pie"}, {"type": "scatter"}],
               [{"type": "bar"}, {"type": "histogram"}]]
    )

    # Protocol Distribution
    protocol_counts = df['protocol'].value_counts()
    fig.add_trace(
        go.Pie(labels=protocol_counts.index, values=protocol_counts.values, name="Protocols"),
        row=1, col=1
    )

    # Packets per Second Timeline
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df_grouped = df.groupby(df['timestamp'].dt.floor('s')).size()
    fig.add_trace(
        go.Scatter(x=df_grouped.index, y=df_grouped.values, mode='lines', name="Packets/sec"),
        row=1, col=2
    )

    # Top Source IPs
    top_sources = df['source'].value_counts().head(10)
    fig.add_trace(
        go.Bar(x=top_sources.index, y=top_sources.values, name="Source IPs"),
        row=2, col=1
    )

    # Packet Size Distribution
    fig.add_trace(
        go.Histogram(x=df['size'], nbinsx=50, name="Packet Sizes"),
        row=2, col=2
    )

    fig.update_layout(height=800, showlegend=False, title_text="Network Traffic Analysis Dashboard")
    st.plotly_chart(fig, use_container_width=True)

# ---- IDS PREDICTION ---- #
@st.cache_resource
def load_ids_model():
    model = load_model(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    encoder = joblib.load(ENCODER_PATH)
    return model, scaler, encoder

def run_detection_on_flows(df_flows):
    model, scaler, encoder = load_ids_model()
    
    # Check if model loading failed
    if model is None or scaler is None or encoder is None:
        return pd.DataFrame(), "Model loading failed. Please check the model files."
    
    if df_flows.empty:
        return pd.DataFrame(), "No flow features to analyze."
    
    # Check minimum flow requirement (30 flows)
    if len(df_flows) < 30:
        return pd.DataFrame(), f"Insufficient data for reliable detection. Need at least 30 flows, but only {len(df_flows)} flows available. Please capture more network traffic."
    
    missing = [col for col in IDS_FEATURES if col not in df_flows.columns]
    if missing:
        return pd.DataFrame(), f"Missing required features: {missing}"
    X_scaled = scaler.transform(df_flows[IDS_FEATURES])
    preds = model.predict(X_scaled)
    y_pred = np.argmax(preds, axis=1)
    labels = encoder.inverse_transform(y_pred)
    df_result = df_flows.copy()
    df_result['Prediction'] = labels
    return df_result, None

# ---- EXPORT FUNCTIONALITY ---- #
def get_download_link(df, filename, text, format_type="CSV"):
    try:
        if format_type == "CSV":
            data = df.to_csv(index=False)
            mime_type = "text/csv"
            file_extension = "csv"
        elif format_type == "JSON":
            data = df.to_json(orient='records', indent=2)
            mime_type = "application/json"
            file_extension = "json"
        elif format_type == "Excel":
            # For Excel, we need to use BytesIO
            import io
            buffer = io.BytesIO()
            with pd.ExcelWriter(buffer, engine='openpyxl') as writer:
                df.to_excel(writer, index=False, sheet_name='IDS_Report')
            buffer.seek(0)
            data = buffer.getvalue()
            mime_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            file_extension = "xlsx"
        else:
            # Default to CSV
            data = df.to_csv(index=False)
            mime_type = "text/csv"
            file_extension = "csv"
        
        # Update filename with correct extension
        if not filename.endswith(f".{file_extension}"):
            filename = filename.replace(".csv", f".{file_extension}")
        
        if format_type == "Excel":
            # For Excel, encode bytes directly
            b64 = base64.b64encode(data).decode()
        else:
            # For CSV and JSON, encode string
            b64 = base64.b64encode(data.encode()).decode()
        
        href = f'<a href="data:{mime_type};base64,{b64}" download="{filename}">{text}</a>'
        return href
    except Exception as e:
        st.error(f"Export error: {e}")
        return ""

# ---- SIDEBAR ---- #
def sidebar_controls():
    st.sidebar.title("🛡️ IDS Dashboard Controls")
    
    # Capture Controls
    st.sidebar.subheader("📡 Capture Settings")
    capture_duration = st.sidebar.slider("Capture Duration (minutes)", 1, 60, 10)
    
    # Detection Settings
    st.sidebar.subheader("🔍 Detection Settings")
    auto_detect = st.sidebar.checkbox("Auto-detect attacks", value=False)
    detection_interval = st.sidebar.slider("Detection interval (seconds)", 5, 60, 30)
    
    # Export Settings
    st.sidebar.subheader("📊 Export Options")
    export_format = st.sidebar.selectbox("Export format", ["CSV", "JSON", "Excel"])
    
    return {
        'capture_duration': capture_duration,
        'auto_detect': auto_detect,
        'detection_interval': detection_interval,
        'export_format': export_format
    }

# ---- MODEL FILE CHECK ---- #
def check_model_files():
    missing_files = []
    if not os.path.exists(MODEL_PATH):
        missing_files.append(MODEL_PATH)
    if not os.path.exists(SCALER_PATH):
        missing_files.append(SCALER_PATH)
    if not os.path.exists(ENCODER_PATH):
        missing_files.append(ENCODER_PATH)
    return missing_files

# ---- MAIN DASHBOARD ---- #
def main():
    # Check model files first
    missing_files = check_model_files()
    if missing_files:
        st.error("❌ Missing model files:")
        for file in missing_files:
            st.write(f"   - {file}")
        st.info("Please ensure all model files are in the current directory.")
        st.stop()
    
    # Header
    st.markdown("""
    <div class="main-header">
        <h1>🛡️ Advanced Network Intrusion Detection System</h1>
        <p>Real-time Network Traffic Analysis & Threat Detection Dashboard</p>
    </div>
    """, unsafe_allow_html=True)

    # Sidebar
    controls = sidebar_controls()

    # Session state initialization
    if 'capture_running' not in st.session_state:
        st.session_state.capture_running = False
    if 'stop_event' not in st.session_state:
        st.session_state.stop_event = threading.Event()
    if 'sniff_thread' not in st.session_state:
        st.session_state.sniff_thread = None
    if 'detection_results' not in st.session_state:
        st.session_state.detection_results = pd.DataFrame()

    processor = get_processor()

    # ---- CONTROL PANEL ---- #
    st.subheader("🎮 Control Panel")
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        if not st.session_state.capture_running:
            if st.button("▶️ Start Capture", use_container_width=True):
                st.session_state.stop_event.clear()
                st.session_state.sniff_thread = start_sniffing(processor, st.session_state.stop_event)
                st.session_state.capture_running = True
                st.success("Capture started successfully!")
                st.rerun()  # Force rerun to update the UI immediately
        else:
            if st.button("⏹️ Stop Capture", use_container_width=True):
                st.session_state.stop_event.set()
                st.session_state.capture_running = False
                st.info("Capture stopped.")
                st.rerun()  # Force rerun to update the UI immediately

    with col2:
        df_flows = processor.get_flow_feature_dataframe()
        flow_count = len(df_flows)
        
        # Show flow count and detection status
        if flow_count < 30:
            st.info(f"📊 Flows: {flow_count}/30 (Need {30-flow_count} more for detection)")
            if st.button("🔍 Run Detection", use_container_width=True, disabled=True):
                pass
        else:
            st.success(f"✅ Flows: {flow_count}/30 (Ready for detection)")
            if st.button("🔍 Run Detection", use_container_width=True):
                with st.spinner("Running intrusion detection..."):
                    df_result, err = run_detection_on_flows(df_flows)
                    if err:
                        st.error(err)
                    else:
                        st.session_state.detection_results = df_result
                        st.success("Detection completed!")

    with col3:
        if st.button("📊 Export Report", use_container_width=True):
            if not st.session_state.detection_results.empty:
                # Get the selected export format from sidebar
                export_format = controls['export_format']
                
                # Create filename with correct extension
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                if export_format == "CSV":
                    filename = f"ids_report_{timestamp}.csv"
                elif export_format == "JSON":
                    filename = f"ids_report_{timestamp}.json"
                elif export_format == "Excel":
                    filename = f"ids_report_{timestamp}.xlsx"
                else:
                    filename = f"ids_report_{timestamp}.csv"
                
                download_link = get_download_link(
                    st.session_state.detection_results, 
                    filename,
                    f"📥 Download {export_format} Report",
                    export_format
                )
                if download_link:
                    st.markdown(download_link, unsafe_allow_html=True)
                    st.success(f"✅ {export_format} report ready for download!")
            else:
                st.warning("No detection results to export. Run detection first.")

    with col4:
        if st.button("🔄 Refresh", use_container_width=True):
            st.rerun()

    # ---- REAL-TIME METRICS ---- #
    st.subheader("📈 Real-time Metrics")
    stats = processor.get_statistics()
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown(f"""
        <div class="metric-card">
            <h3>📦 Total Packets</h3>
            <h2>{stats['total_packets']:,}</h2>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown(f"""
        <div class="metric-card">
            <h3>🌊 Total Flows</h3>
            <h2>{stats['total_flows']:,}</h2>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown(f"""
        <div class="metric-card">
            <h3>📊 Avg Packet Size</h3>
            <h2>{stats['avg_packet_size']:.1f} bytes</h2>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        duration = (datetime.now() - processor.start_time).total_seconds()
        st.markdown(f"""
        <div class="metric-card">
            <h3>⏱️ Capture Duration</h3>
            <h2>{duration:.1f}s</h2>
        </div>
        """, unsafe_allow_html=True)

    # ---- INTELLIGENT THREAT ALERTS ---- #
    if not st.session_state.detection_results.empty:
        # Get attack distribution
        attack_summary = st.session_state.detection_results['Prediction'].value_counts()
        total_flows = len(st.session_state.detection_results)
        
        # Calculate percentages for debugging
        benign_count = attack_summary.get('Benign', 0)
        benign_percentage = (benign_count / total_flows) * 100 if total_flows > 0 else 0
        
        # # Enhanced debug info
        # st.sidebar.write(f"Debug: BENIGN = {benign_count}/{total_flows} ({benign_percentage:.1f}%)")
        # st.sidebar.write(f"Debug: All predictions: {dict(attack_summary)}")
        # st.sidebar.write(f"Debug: Is BENIGN > 50%? {benign_count > total_flows * 0.5}")
        
        # # Temporary test alert to see what's happening
        # if benign_count > 0:
        #     st.sidebar.success("✅ BENIGN detected - should show green alert!")
        # else:
        #     st.sidebar.error("❌ No BENIGN detected!")
        
        # Check if BENIGN is the majority (>50%)
        if benign_count > total_flows * 0.5:
            st.markdown("""
            <div class="success-box">
                <h3>✅ NETWORK SECURITY STATUS: NORMAL</h3>
                <p>Majority of network traffic appears to be legitimate and secure</p>
            </div>
            """, unsafe_allow_html=True)
        else:
            # Check for specific threats that are >50% of total flows (EXCLUDE BENIGN)
            threats_detected = []
            for attack_type, count in attack_summary.items():
                # Only consider non-BENIGN traffic as threats
                if attack_type != 'BENIGN' and count > total_flows * 0.5:
                    threats_detected.append(attack_type)
            
            if threats_detected:
                # Show red alert for dominant threats
                threat_text = ", ".join(threats_detected)
                st.markdown(f"""
                <div class="alert-box">
                    <h3>🚨 CRITICAL SECURITY ALERT!</h3>
                    <p><strong>{threat_text.upper()} ATTACKS DETECTED</strong></p>
                    <p>Dominant attack pattern identified in network traffic</p>
                </div>
                """, unsafe_allow_html=True)
            else:
                # Show amber warning for mixed traffic (when no single threat is dominant)
                non_benign_count = total_flows - benign_count
                if non_benign_count > 0:
                    st.markdown(f"""
                    <div style="background: linear-gradient(135deg, #f39c12 0%, #e67e22 100%); padding: 1rem; border-radius: 10px; color: white; text-align: center; margin: 1rem 0;">
                        <h3>⚠️ SECURITY WARNING</h3>
                        <p>Mixed traffic detected: {non_benign_count} suspicious flows among {total_flows} total flows</p>
                        <p>Monitor network activity closely</p>
                    </div>
                    """, unsafe_allow_html=True)
                else:
                    # All traffic is benign
                    st.markdown("""
                    <div class="success-box">
                        <h3>✅ NETWORK SECURITY STATUS: NORMAL</h3>
                        <p>All network traffic appears to be legitimate and secure</p>
                    </div>
                    """, unsafe_allow_html=True)

    # ---- ENHANCED VISUALIZATIONS ---- #
    st.subheader("📊 Network Traffic Analysis")
    df = processor.get_dataframe()
    df_flows = processor.get_flow_feature_dataframe()
    create_enhanced_visualizations(df, df_flows)

    # ---- DETECTION RESULTS ---- #
    if not st.session_state.detection_results.empty:
        st.subheader("🚨 Intrusion Detection Results")
        
        # Attack Summary
        attack_summary = st.session_state.detection_results['Prediction'].value_counts()
        col1, col2 = st.columns(2)
        
        with col1:
            fig_attacks = px.pie(
                values=attack_summary.values, 
                names=attack_summary.index, 
                title="Attack Type Distribution"
            )
            st.plotly_chart(fig_attacks, use_container_width=True)
        
        with col2:
            st.dataframe(
                st.session_state.detection_results[['Prediction']].tail(20), 
                use_container_width=True
            )

    # ---- FLOW FEATURES TABLE ---- #
    st.subheader("🔍 Recent Packet Flows")
    if not df_flows.empty:
        st.dataframe(df_flows.tail(15), use_container_width=True)
    else:
        st.info("Flow features are still being extracted. Try interacting with the network (ping, browse).")

    # ---- FOOTER ---- #
    st.markdown("---")
    st.caption(f"🛡️ Advanced IDS Dashboard | Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | APTYS Competition Ready")

if __name__ == "__main__":
    main()
