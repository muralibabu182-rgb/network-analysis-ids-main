import pandas as pd
import numpy as np
import threading
import logging
from datetime import datetime
from collections import defaultdict
from scapy.all import IP, TCP, UDP

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
            
            self.flow_features.append(features)
            del self.flow_cache[key]
        except Exception as e:
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
            print(f"Error creating flow features DataFrame: {e}")
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

# Import IDS features from config
from config import IDS_FEATURES
