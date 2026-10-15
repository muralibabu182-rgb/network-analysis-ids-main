import streamlit as st
import pandas as pd
import threading
import time
from datetime import datetime

# Import our refactored modules
from packet_processor import EnhancedPacketProcessor
from config import IDS_FEATURES
from ids_model import check_model_files, run_detection_on_flows
from utils import get_download_link, start_sniffing
from visualizations import create_enhanced_visualizations, create_attack_distribution_chart
from ui_components import (
    sidebar_controls, create_metric_card, create_security_alert, 
    create_main_header, create_footer
)
from config import PAGE_CONFIG, DETECTION_SETTINGS
from styles import get_custom_css

# ---- PAGE CONFIGURATION ---- #
st.set_page_config(**PAGE_CONFIG)

# ---- CUSTOM CSS FOR PROFESSIONAL STYLING ---- #
st.markdown(get_custom_css(), unsafe_allow_html=True)

# ---- SHARED STATE ---- #
@st.cache_resource
def get_processor():
    processor = EnhancedPacketProcessor()
    return processor

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
    create_main_header()

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
                st.rerun()
        else:
            if st.button("⏹️ Stop Capture", use_container_width=True):
                st.session_state.stop_event.set()
                st.session_state.capture_running = False
                st.info("Capture stopped.")
                st.rerun()

    with col2:
        df_flows = processor.get_flow_feature_dataframe()
        flow_count = len(df_flows)
        
        # Show flow count and detection status
        if flow_count < DETECTION_SETTINGS['min_flows_required']:
            st.info(f"📊 Flows: {flow_count}/{DETECTION_SETTINGS['min_flows_required']} (Need {DETECTION_SETTINGS['min_flows_required']-flow_count} more for detection)")
            if st.button("🔍 Run Detection", use_container_width=True, disabled=True):
                pass
        else:
            st.success(f"✅ Flows: {flow_count}/{DETECTION_SETTINGS['min_flows_required']} (Ready for detection)")
            if st.button("🔍 Run Detection", use_container_width=True):
                with st.spinner("Running intrusion detection..."):
                    df_result, err = run_detection_on_flows(df_flows, IDS_FEATURES)
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
        create_metric_card("📦 Total Packets", f"{stats['total_packets']:,}")
    
    with col2:
        create_metric_card("🌊 Total Flows", f"{stats['total_flows']:,}")
    
    with col3:
        create_metric_card("📊 Avg Packet Size", f"{stats['avg_packet_size']:.1f} bytes")
    
    with col4:
        duration = (datetime.now() - processor.start_time).total_seconds()
        create_metric_card("⏱️ Capture Duration", f"{duration:.1f}s")

    # ---- INTELLIGENT THREAT ALERTS ---- #
    if not st.session_state.detection_results.empty:
        # Get attack distribution
        attack_summary = st.session_state.detection_results['Prediction'].value_counts()
        total_flows = len(st.session_state.detection_results)
        
        # Calculate percentages for debugging
        benign_count = attack_summary.get('Benign', 0)
        benign_percentage = (benign_count / total_flows) * 100 if total_flows > 0 else 0
        
        # Check if BENIGN is the majority (>50%)
        if benign_count > total_flows * 0.5:
            create_security_alert("success", "✅ NETWORK SECURITY STATUS: NORMAL", 
                                "Majority of network traffic appears to be legitimate and secure")
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
                create_security_alert("danger", "🚨 CRITICAL SECURITY ALERT!", 
                                    f"<strong>{threat_text.upper()} ATTACKS DETECTED</strong><br>Dominant attack pattern identified in network traffic")
            else:
                # Show amber warning for mixed traffic (when no single threat is dominant)
                non_benign_count = total_flows - benign_count
                if non_benign_count > 0:
                    create_security_alert("warning", "⚠️ SECURITY WARNING", 
                                        f"Mixed traffic detected: {non_benign_count} suspicious flows among {total_flows} total flows<br>Monitor network activity closely")
                else:
                    # All traffic is benign
                    create_security_alert("success", "✅ NETWORK SECURITY STATUS: NORMAL", 
                                        "All network traffic appears to be legitimate and secure")

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
            fig_attacks = create_attack_distribution_chart(attack_summary)
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
    create_footer()

if __name__ == "__main__":
    main()
