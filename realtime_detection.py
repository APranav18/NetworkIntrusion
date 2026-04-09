"""
Real-Time Network Intrusion Detection Module
Uses Scapy for packet capture and ML model for attack classification.

Features:
- Live packet capture from network interface
- Feature extraction from network packets
- Real-time attack classification
- Integration with database logging
- Email alerts for detected attacks
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP
from scapy.layers.http import HTTPRequest
import numpy as np
import joblib
import os
import sys
import threading
import queue
from datetime import datetime
from collections import defaultdict
import time

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from database import log_attack
    from email_alert import send_alert_email
except ImportError:
    log_attack = None
    send_alert_email = None


class PacketFeatureExtractor:
    """
    Extracts machine learning features from network packets.
    Maintains flow state to calculate flow-based features.
    """
    
    def __init__(self):
        """Initialize the feature extractor with flow tracking."""
        # Flow tracking: key = (src_ip, dst_ip, src_port, dst_port, protocol)
        self.flows = defaultdict(lambda: {
            'packets': [],
            'fwd_packets': 0,
            'bwd_packets': 0,
            'fwd_bytes': 0,
            'bwd_bytes': 0,
            'start_time': None,
            'last_time': None,
            'packet_lengths': [],
            'fwd_iats': [],
            'bwd_iats': [],
            'last_fwd_time': None,
            'last_bwd_time': None
        })
        
        # Feature names matching the trained model
        self.feature_names = [
            'Flow Duration',
            'Total Fwd Packets',
            'Total Backward Packets',
            'Flow Bytes/s',
            'Flow Packets/s',
            'Packet Length Mean',
            'Packet Length Std',
            'Protocol',
            'Source Port',
            'Destination Port',
            'Fwd Packet Length Mean',
            'Bwd Packet Length Mean',
            'Flow IAT Mean',
            'Fwd IAT Mean',
            'Bwd IAT Mean',
            'Average Packet Size',
            'Avg Fwd Segment Size',
            'Avg Bwd Segment Size'
        ]
        
    def get_flow_key(self, packet):
        """
        Generate a unique key for a network flow.
        
        Args:
            packet: Scapy packet object
            
        Returns:
            tuple: Flow identifier
        """
        if IP not in packet:
            return None
            
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        
        src_port = 0
        dst_port = 0
        
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            
        # Normalize flow key (smaller IP first)
        if src_ip < dst_ip:
            return (src_ip, dst_ip, src_port, dst_port, protocol)
        else:
            return (dst_ip, src_ip, dst_port, src_port, protocol)
    
    def is_forward_packet(self, packet, flow_key):
        """
        Determine if packet is in forward or backward direction.
        
        Args:
            packet: Scapy packet object
            flow_key: Flow identifier tuple
            
        Returns:
            bool: True if forward direction
        """
        if IP not in packet:
            return True
        return packet[IP].src == flow_key[0]
    
    def update_flow(self, packet):
        """
        Update flow statistics with new packet.
        
        Args:
            packet: Scapy packet object
            
        Returns:
            tuple: (flow_key, flow_data, features) or None
        """
        flow_key = self.get_flow_key(packet)
        if flow_key is None:
            return None
            
        current_time = time.time()
        flow = self.flows[flow_key]
        packet_len = len(packet)
        
        # Initialize flow timing
        if flow['start_time'] is None:
            flow['start_time'] = current_time
        
        # Update packet counts and bytes
        is_fwd = self.is_forward_packet(packet, flow_key)
        
        if is_fwd:
            flow['fwd_packets'] += 1
            flow['fwd_bytes'] += packet_len
            if flow['last_fwd_time'] is not None:
                iat = (current_time - flow['last_fwd_time']) * 1000000  # microseconds
                flow['fwd_iats'].append(iat)
            flow['last_fwd_time'] = current_time
        else:
            flow['bwd_packets'] += 1
            flow['bwd_bytes'] += packet_len
            if flow['last_bwd_time'] is not None:
                iat = (current_time - flow['last_bwd_time']) * 1000000
                flow['bwd_iats'].append(iat)
            flow['last_bwd_time'] = current_time
        
        flow['packet_lengths'].append(packet_len)
        flow['packets'].append({
            'time': current_time,
            'length': packet_len,
            'is_forward': is_fwd
        })
        flow['last_time'] = current_time
        
        # Extract features
        features = self.extract_features(flow_key, packet)
        
        return flow_key, flow, features
    
    def extract_features(self, flow_key, packet):
        """
        Extract ML features from the current flow state.
        
        Args:
            flow_key: Flow identifier
            packet: Current packet
            
        Returns:
            numpy.ndarray: Feature vector
        """
        flow = self.flows[flow_key]
        
        # Calculate flow duration (microseconds)
        if flow['start_time'] and flow['last_time']:
            flow_duration = (flow['last_time'] - flow['start_time']) * 1000000
        else:
            flow_duration = 0
        
        # Packet counts
        total_fwd_packets = flow['fwd_packets']
        total_bwd_packets = flow['bwd_packets']
        total_packets = total_fwd_packets + total_bwd_packets
        
        # Bytes per second
        if flow_duration > 0:
            flow_bytes_per_sec = (flow['fwd_bytes'] + flow['bwd_bytes']) / (flow_duration / 1000000)
            flow_packets_per_sec = total_packets / (flow_duration / 1000000)
        else:
            flow_bytes_per_sec = 0
            flow_packets_per_sec = 0
        
        # Packet length statistics
        if flow['packet_lengths']:
            packet_len_mean = np.mean(flow['packet_lengths'])
            packet_len_std = np.std(flow['packet_lengths']) if len(flow['packet_lengths']) > 1 else 0
        else:
            packet_len_mean = 0
            packet_len_std = 0
        
        # Protocol (6=TCP, 17=UDP, 1=ICMP)
        protocol = flow_key[4]
        
        # Ports
        src_port = flow_key[2]
        dst_port = flow_key[3]
        
        # Forward/Backward packet length means
        fwd_pkt_lens = [p['length'] for p in flow['packets'] if p['is_forward']]
        bwd_pkt_lens = [p['length'] for p in flow['packets'] if not p['is_forward']]
        
        fwd_pkt_len_mean = np.mean(fwd_pkt_lens) if fwd_pkt_lens else 0
        bwd_pkt_len_mean = np.mean(bwd_pkt_lens) if bwd_pkt_lens else 0
        
        # Inter-arrival times
        if len(flow['packets']) > 1:
            times = [p['time'] for p in flow['packets']]
            iats = [(times[i] - times[i-1]) * 1000000 for i in range(1, len(times))]
            flow_iat_mean = np.mean(iats) if iats else 0
        else:
            flow_iat_mean = 0
        
        fwd_iat_mean = np.mean(flow['fwd_iats']) if flow['fwd_iats'] else 0
        bwd_iat_mean = np.mean(flow['bwd_iats']) if flow['bwd_iats'] else 0
        
        # Average packet/segment sizes
        avg_packet_size = packet_len_mean
        avg_fwd_segment_size = fwd_pkt_len_mean
        avg_bwd_segment_size = bwd_pkt_len_mean
        
        # Create feature vector
        features = np.array([
            flow_duration,
            total_fwd_packets,
            total_bwd_packets,
            flow_bytes_per_sec,
            flow_packets_per_sec,
            packet_len_mean,
            packet_len_std,
            protocol,
            src_port,
            dst_port,
            fwd_pkt_len_mean,
            bwd_pkt_len_mean,
            flow_iat_mean,
            fwd_iat_mean,
            bwd_iat_mean,
            avg_packet_size,
            avg_fwd_segment_size,
            avg_bwd_segment_size
        ])
        
        return features
    
    def cleanup_old_flows(self, max_age=60):
        """
        Remove flows older than max_age seconds.
        
        Args:
            max_age (int): Maximum flow age in seconds
        """
        current_time = time.time()
        expired_keys = []
        
        for key, flow in self.flows.items():
            if flow['last_time'] and (current_time - flow['last_time']) > max_age:
                expired_keys.append(key)
        
        for key in expired_keys:
            del self.flows[key]


class RealtimeDetector:
    """
    Real-time network intrusion detection system using ML.
    """
    
    def __init__(self, model_dir='model'):
        """
        Initialize the detector with trained model.
        
        Args:
            model_dir (str): Directory containing model files
        """
        self.model_dir = model_dir
        self.model = None
        self.scaler = None
        self.label_encoder = None
        self.anomaly_model = None
        self.feature_extractor = PacketFeatureExtractor()
        
        # Detection statistics
        self.stats = {
            'total_packets': 0,
            'attacks_detected': 0,
            'attack_types': defaultdict(int)
        }
        
        # Alert queue for GUI integration
        self.alert_queue = queue.Queue()
        
        # Running flag
        self.running = False
        
        # Load model
        self.load_model()
        self.load_anomaly_model()

    def load_anomaly_model(self):
        """Load the trained anomaly (IsolationForest) model if available."""
        try:
            anomaly_path = os.path.join(self.model_dir, 'anomaly_model.pkl')
            if os.path.exists(anomaly_path):
                self.anomaly_model = joblib.load(anomaly_path)
                print("✓ Anomaly (Zero-Day) model loaded successfully")
            else:
                print("⚠ Anomaly model not found. Zero-Day detection disabled.")
        except Exception as e:
            print(f"✗ Error loading anomaly model: {e}")
            self.anomaly_model = None
        
    def load_model(self):
        """Load the trained ML model and preprocessing artifacts."""
        try:
            model_path = os.path.join(self.model_dir, 'model.pkl')
            scaler_path = os.path.join(self.model_dir, 'scaler.pkl')
            encoder_path = os.path.join(self.model_dir, 'label_encoder.pkl')
            
            if os.path.exists(model_path):
                self.model = joblib.load(model_path)
                print("✓ ML Model loaded successfully")
            else:
                print("⚠ Model file not found. Please run train_model.py first.")
                return False
                
            if os.path.exists(scaler_path):
                self.scaler = joblib.load(scaler_path)
                print("✓ Scaler loaded successfully")
            else:
                print("⚠ Scaler file not found")
                return False
                
            if os.path.exists(encoder_path):
                self.label_encoder = joblib.load(encoder_path)
                print("✓ Label encoder loaded successfully")
            else:
                print("⚠ Label encoder not found")
                return False
                
            return True
            
        except Exception as e:
            print(f"✗ Error loading model: {e}")
            return False
    
    def predict(self, features):
        """
        Make prediction on extracted features.
        
        Args:
            features (numpy.ndarray): Feature vector
            
        Returns:
            tuple: (label, confidence)
        """
        if self.model is None or self.scaler is None:
            return None, 0
        
        try:
            # Scale features
            features_scaled = self.scaler.transform(features.reshape(1, -1))
            
            # Predict
            prediction = self.model.predict(features_scaled)[0]
            probabilities = self.model.predict_proba(features_scaled)[0]
            
            label = self.label_encoder.inverse_transform([prediction])[0]
            confidence = float(np.max(probabilities))
            
            return label, confidence
            
        except Exception as e:
            print(f"Prediction error: {e}")
            return None, 0
    
    def process_packet(self, packet):
        """
        Process a captured packet and detect attacks.
        
        Args:
            packet: Scapy packet object
        """
        if IP not in packet:
            return
        
        self.stats['total_packets'] += 1
        
        # Extract features
        result = self.feature_extractor.update_flow(packet)
        if result is None:
            return
        
        flow_key, flow_data, features = result
        
        # Make prediction
        label, confidence = self.predict(features)
        if label is None:
            return

        # Zero-Day/Anomaly detection if label is Normal
        is_zero_day = False
        anomaly_score = None
        if label == 'Normal' and self.anomaly_model is not None:
            try:
                features_scaled = self.scaler.transform(features.reshape(1, -1))
                anomaly_pred = self.anomaly_model.predict(features_scaled)[0]
                anomaly_score = self.anomaly_model.decision_function(features_scaled)[0]
                if anomaly_pred == -1:
                    is_zero_day = True
            except Exception as e:
                print(f"Anomaly detection error: {e}")

        # Extract packet info
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        src_port = 0
        dst_port = 0
        protocol = "IP"
        
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            protocol = "TCP"
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            protocol = "UDP"
        elif ICMP in packet:
            protocol = "ICMP"
        
        # Process detection result
        if label != 'Normal' or is_zero_day:
            self.stats['attacks_detected'] += 1
            attack_type = label if label != 'Normal' else 'Zero-Day'
            self.stats['attack_types'][attack_type] += 1

            # Create alert
            alert = {
                'timestamp': datetime.now().isoformat(),
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol': protocol,
                'attack_type': attack_type,
                'confidence': confidence if label != 'Normal' else None,
                'packet_size': len(packet),
                'anomaly_score': anomaly_score if is_zero_day else None
            }

            # Add to alert queue
            self.alert_queue.put(alert)

            # Print alert
            print(f"\n{'='*60}")
            if is_zero_day:
                print(f"⚠️  POSSIBLE ZERO-DAY ATTACK DETECTED!")
            else:
                print(f"⚠️  ATTACK DETECTED!")
            print(f"{'='*60}")
            print(f"  Type: {attack_type}")
            if is_zero_day:
                print(f"  Anomaly Score: {anomaly_score:.4f}")
            else:
                print(f"  Confidence: {confidence*100:.1f}%")
            print(f"  Source: {src_ip}:{src_port}")
            print(f"  Destination: {dst_ip}:{dst_port}")
            print(f"  Protocol: {protocol}")
            print(f"  Time: {alert['timestamp']}")
            print(f"{'='*60}\n")

            # Log to database
            if log_attack:
                try:
                    log_attack(
                        ip_address=src_ip,
                        attack_type=attack_type,
                        status='detected',
                        confidence=confidence if label != 'Normal' else None,
                        source_port=src_port,
                        dest_port=dst_port,
                        protocol=protocol,
                        packet_size=len(packet),
                        details=f"Destination: {dst_ip}" + (f", Anomaly Score: {anomaly_score:.4f}" if is_zero_day else "")
                    )
                except Exception as e:
                    print(f"Database logging error: {e}")

            # Send email alert for high-confidence attacks or Zero-Day
            if ((confidence and confidence > 0.85) or is_zero_day) and send_alert_email:
                try:
                    send_alert_email(
                        attack_type=attack_type,
                        source_ip=src_ip,
                        confidence=confidence if label != 'Normal' else None,
                        details=f"Port: {src_port} -> {dst_port}, Protocol: {protocol}" + (f", Anomaly Score: {anomaly_score:.4f}" if is_zero_day else "")
                    )
                except Exception as e:
                    print(f"Email alert error: {e}")
        
        # Periodic cleanup
        if self.stats['total_packets'] % 1000 == 0:
            self.feature_extractor.cleanup_old_flows()
    
    def start_capture(self, interface=None, filter_str="ip", count=0):
        """
        Start capturing packets from network interface.
        
        Args:
            interface (str): Network interface to capture from
            filter_str (str): BPF filter string
            count (int): Number of packets to capture (0 = infinite)
        """
        self.running = True
        
        print("\n" + "#"*60)
        print("#   REAL-TIME NETWORK INTRUSION DETECTION SYSTEM   #")
        print("#"*60)
        print(f"\n  Interface: {interface or 'default'}")
        print(f"  Filter: {filter_str}")
        print(f"  Press Ctrl+C to stop\n")
        print("="*60 + "\n")
        
        try:
            sniff(
                iface=interface,
                prn=self.process_packet,
                filter=filter_str,
                count=count if count > 0 else 0,
                store=False
            )
        except KeyboardInterrupt:
            print("\n\nStopping capture...")
        except Exception as e:
            print(f"Capture error: {e}")
        finally:
            self.running = False
            self.print_statistics()
    
    def print_statistics(self):
        """Print capture statistics."""
        print("\n" + "="*60)
        print("  CAPTURE STATISTICS")
        print("="*60)
        print(f"  Total packets processed: {self.stats['total_packets']:,}")
        print(f"  Attacks detected: {self.stats['attacks_detected']:,}")
        
        if self.stats['attack_types']:
            print("\n  Attack types breakdown:")
            for attack_type, count in sorted(self.stats['attack_types'].items(), 
                                            key=lambda x: x[1], reverse=True):
                print(f"    • {attack_type}: {count}")
        
        print("="*60 + "\n")
    
    def stop(self):
        """Stop the packet capture."""
        self.running = False


def simulate_detection():
    """
    Simulate detection with synthetic packets for testing.
    """
    print("\n" + "#"*60)
    print("#   SIMULATED INTRUSION DETECTION")
    print("#"*60)
    
    detector = RealtimeDetector()
    
    if detector.model is None:
        print("Model not loaded. Please run train_model.py first.")
        return
    
    # Simulate some detections
    test_samples = [
        # Normal traffic
        np.array([100000, 10, 8, 50000, 100, 500, 300, 6, 45892, 80, 
                 400, 600, 100000, 150000, 200000, 500, 400, 600]),
        # DoS-like pattern (high packet rate)
        np.array([1000, 1000, 5, 5000000, 10000, 100, 50, 6, 12345, 80,
                 100, 50, 1000, 500, 2000, 100, 100, 50]),
        # Port scan pattern (short flows, many ports)
        np.array([100, 1, 0, 1000, 10, 60, 0, 6, 54321, 22,
                 60, 0, 50000, 50000, 0, 60, 60, 0]),
        # Brute force pattern
        np.array([5000, 50, 50, 100000, 200, 100, 20, 6, 11111, 22,
                 100, 100, 50000, 50000, 50000, 100, 100, 100]),
    ]
    
    labels = ['Normal', 'DoS', 'PortScan', 'BruteForce']
    
    for i, (sample, expected) in enumerate(zip(test_samples, labels)):
        label, confidence = detector.predict(sample)
        status = "✓" if label == expected else "✗"
        print(f"\n  Sample {i+1}: Expected={expected}, Predicted={label}, "
              f"Confidence={confidence*100:.1f}% [{status}]")
    
    print("\n" + "="*60)


def main():
    """Main function to run the real-time detector."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Real-Time Network Intrusion Detection System'
    )
    parser.add_argument(
        '-i', '--interface',
        help='Network interface to capture from'
    )
    parser.add_argument(
        '-f', '--filter',
        default='ip',
        help='BPF filter string (default: ip)'
    )
    parser.add_argument(
        '-c', '--count',
        type=int,
        default=0,
        help='Number of packets to capture (0 = infinite)'
    )
    parser.add_argument(
        '--simulate',
        action='store_true',
        help='Run simulation instead of live capture'
    )
    
    args = parser.parse_args()
    
    if args.simulate:
        simulate_detection()
    else:
        detector = RealtimeDetector()
        detector.start_capture(
            interface=args.interface,
            filter_str=args.filter,
            count=args.count
        )


if __name__ == "__main__":
    main()
