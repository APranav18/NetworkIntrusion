"""
Real-Time Network Intrusion Detection Module
Captures live network traffic and detects attacks in real-time.
"""

import threading
import time
import socket
import struct
import json
import requests
from datetime import datetime, timedelta
from collections import defaultdict
import psutil

# Try to import scapy for packet capture
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, get_if_list, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: scapy not available. Using socket-based monitoring.")

# Import database functions
from database import (
    record_failed_login, add_security_notification, add_realtime_activity,
    get_monitored_websites, block_ip_address, is_ip_blocked, get_blocked_ips
)


class RealTimeMonitor:
    """Real-time network traffic monitor for intrusion detection."""
    
    def __init__(self, socketio=None):
        self.socketio = socketio
        self.running = False
        self.capture_thread = None
        self.analysis_thread = None
        
        # Traffic statistics
        self.stats = {
            'packets_captured': 0,
            'bytes_captured': 0,
            'attacks_detected': 0,
            'ips_blocked': 0,
            'start_time': None
        }
        
        # Connection tracking for detecting attacks
        self.connection_tracker = defaultdict(lambda: {
            'syn_count': 0,
            'failed_auth': 0,
            'port_scan_ports': set(),
            'last_seen': datetime.now(),
            'packets': 0,
            'bytes': 0
        })
        
        # Attack thresholds
        self.thresholds = {
            'syn_flood': 100,           # SYN packets per second
            'port_scan': 10,            # Different ports in 60 seconds
            'brute_force': 5,           # Failed auth attempts
            'dos_packets': 1000,        # Packets per second from single IP
            'dos_bytes': 10000000       # Bytes per second (10MB)
        }
        
        # Time windows for detection (seconds)
        self.time_windows = {
            'syn_flood': 1,
            'port_scan': 60,
            'brute_force': 300,
            'dos': 1
        }
        
        # Recent detections to avoid duplicates
        self.recent_detections = {}
        
        # Suspicious ports to monitor
        self.suspicious_ports = {
            22: 'SSH',
            23: 'Telnet',
            21: 'FTP',
            3389: 'RDP',
            5900: 'VNC',
            3306: 'MySQL',
            5432: 'PostgreSQL',
            1433: 'MSSQL',
            27017: 'MongoDB',
            6379: 'Redis'
        }
        
        # Common attack signatures
        self.attack_signatures = [
            b'cmd.exe',
            b'/etc/passwd',
            b'/etc/shadow',
            b'SELECT * FROM',
            b'UNION SELECT',
            b'<script>',
            b'../../../',
            b'admin\' OR \'1\'=\'1',
            b'root\' OR \'1\'=\'1'
        ]
        
    def start(self):
        """Start real-time monitoring."""
        if self.running:
            return False
            
        self.running = True
        self.stats['start_time'] = datetime.now()
        
        # Start packet capture thread
        self.capture_thread = threading.Thread(target=self._capture_packets, daemon=True)
        self.capture_thread.start()
        
        # Start analysis thread
        self.analysis_thread = threading.Thread(target=self._analyze_traffic, daemon=True)
        self.analysis_thread.start()
        
        # Start stats broadcast thread
        self.stats_thread = threading.Thread(target=self._broadcast_stats, daemon=True)
        self.stats_thread.start()
        
        self._emit_event('monitor_started', {
            'message': 'Real-time monitoring started',
            'timestamp': datetime.now().isoformat()
        })
        
        return True
        
    def stop(self):
        """Stop real-time monitoring."""
        self.running = False
        self._emit_event('monitor_stopped', {
            'message': 'Real-time monitoring stopped',
            'timestamp': datetime.now().isoformat()
        })
        return True
        
    def _capture_packets(self):
        """Capture network packets using scapy or socket."""
        if SCAPY_AVAILABLE:
            self._capture_with_scapy()
        else:
            self._capture_with_socket()
            
    def _capture_with_scapy(self):
        """Capture packets using scapy (more detailed)."""
        try:
            # Get available interfaces
            interfaces = get_if_list()
            print(f"[Monitor] Available interfaces: {interfaces}")
            
            # Start sniffing
            sniff(
                prn=self._process_packet,
                store=False,
                stop_filter=lambda _: not self.running
            )
        except Exception as e:
            print(f"[Monitor] Scapy capture error: {e}")
            # Fallback to socket
            self._capture_with_socket()
            
    def _capture_with_socket(self):
        """Capture packets using raw sockets (Windows compatible)."""
        try:
            # Create raw socket
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            
            # Get local IP
            hostname = socket.gethostname()
            host_ip = socket.gethostbyname(hostname)
            s.bind((host_ip, 0))
            
            # Include IP headers
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            
            # Enable promiscuous mode on Windows
            try:
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            except:
                pass
                
            print(f"[Monitor] Socket capture started on {host_ip}")
            
            while self.running:
                try:
                    packet, addr = s.recvfrom(65535)
                    self._process_raw_packet(packet, addr)
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        print(f"[Monitor] Packet recv error: {e}")
                        
            # Disable promiscuous mode
            try:
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except:
                pass
            s.close()
            
        except Exception as e:
            print(f"[Monitor] Socket capture error: {e}")
            # Use network stats monitoring as fallback
            self._monitor_network_stats()
            
    def _monitor_network_stats(self):
        """Monitor network statistics using psutil (fallback method)."""
        print("[Monitor] Using psutil network stats monitoring")
        
        prev_stats = psutil.net_io_counters()
        prev_connections = set()
        
        while self.running:
            try:
                time.sleep(1)
                
                # Get current stats
                curr_stats = psutil.net_io_counters()
                
                # Calculate rates
                bytes_recv = curr_stats.bytes_recv - prev_stats.bytes_recv
                bytes_sent = curr_stats.bytes_sent - prev_stats.bytes_sent
                packets_recv = curr_stats.packets_recv - prev_stats.packets_recv
                packets_sent = curr_stats.packets_sent - prev_stats.packets_sent
                
                self.stats['packets_captured'] += packets_recv + packets_sent
                self.stats['bytes_captured'] += bytes_recv + bytes_sent
                
                # Check for unusual traffic
                if bytes_recv > self.thresholds['dos_bytes']:
                    self._detect_attack('high_traffic', {
                        'type': 'High Traffic Alert',
                        'bytes_per_sec': bytes_recv,
                        'packets_per_sec': packets_recv
                    })
                    
                # Monitor connections
                connections = psutil.net_connections(kind='inet')
                curr_conn_set = set()
                
                for conn in connections:
                    if conn.raddr:
                        remote_ip = conn.raddr.ip
                        remote_port = conn.raddr.port
                        local_port = conn.laddr.port if conn.laddr else 0
                        
                        conn_key = f"{remote_ip}:{remote_port}"
                        curr_conn_set.add(conn_key)
                        
                        # Track connection
                        self.connection_tracker[remote_ip]['packets'] += 1
                        self.connection_tracker[remote_ip]['last_seen'] = datetime.now()
                        
                        # Check for port scanning
                        if remote_port not in self.connection_tracker[remote_ip]['port_scan_ports']:
                            self.connection_tracker[remote_ip]['port_scan_ports'].add(remote_port)
                            
                            if len(self.connection_tracker[remote_ip]['port_scan_ports']) > self.thresholds['port_scan']:
                                self._detect_attack('port_scan', {
                                    'ip': remote_ip,
                                    'ports_scanned': len(self.connection_tracker[remote_ip]['port_scan_ports'])
                                })
                                
                        # Check for suspicious port access
                        if local_port in self.suspicious_ports:
                            self._emit_event('suspicious_connection', {
                                'ip': remote_ip,
                                'port': local_port,
                                'service': self.suspicious_ports[local_port],
                                'timestamp': datetime.now().isoformat()
                            })
                            
                # Emit live stats
                self._emit_event('traffic_stats', {
                    'bytes_recv': bytes_recv,
                    'bytes_sent': bytes_sent,
                    'packets_recv': packets_recv,
                    'packets_sent': packets_sent,
                    'active_connections': len(connections),
                    'timestamp': datetime.now().isoformat()
                })
                
                prev_stats = curr_stats
                prev_connections = curr_conn_set
                
            except Exception as e:
                print(f"[Monitor] Stats monitoring error: {e}")
                
    def _process_packet(self, packet):
        """Process a captured packet (scapy)."""
        try:
            self.stats['packets_captured'] += 1
            
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                packet_len = len(packet)
                
                self.stats['bytes_captured'] += packet_len
                
                # Track connection
                tracker = self.connection_tracker[src_ip]
                tracker['packets'] += 1
                tracker['bytes'] += packet_len
                tracker['last_seen'] = datetime.now()
                
                # Check for SYN flood
                if TCP in packet:
                    flags = packet[TCP].flags
                    dst_port = packet[TCP].dport
                    src_port = packet[TCP].sport
                    
                    if flags == 'S':  # SYN flag
                        tracker['syn_count'] += 1
                        if tracker['syn_count'] > self.thresholds['syn_flood']:
                            self._detect_attack('syn_flood', {
                                'ip': src_ip,
                                'syn_count': tracker['syn_count']
                            })
                            
                    # Port scanning detection
                    tracker['port_scan_ports'].add(dst_port)
                    if len(tracker['port_scan_ports']) > self.thresholds['port_scan']:
                        self._detect_attack('port_scan', {
                            'ip': src_ip,
                            'ports_scanned': len(tracker['port_scan_ports'])
                        })
                        
                    # Check for suspicious port access
                    if dst_port in self.suspicious_ports:
                        self._emit_event('suspicious_connection', {
                            'ip': src_ip,
                            'port': dst_port,
                            'service': self.suspicious_ports[dst_port],
                            'timestamp': datetime.now().isoformat()
                        })
                        
                # Check packet payload for attack signatures
                if Raw in packet:
                    payload = bytes(packet[Raw].load)
                    self._check_payload_signatures(src_ip, payload)
                    
                # DoS detection
                if tracker['packets'] > self.thresholds['dos_packets']:
                    self._detect_attack('dos', {
                        'ip': src_ip,
                        'packets': tracker['packets'],
                        'bytes': tracker['bytes']
                    })
                    
                # Emit packet event (sampled)
                if self.stats['packets_captured'] % 100 == 0:
                    self._emit_event('packet_captured', {
                        'src': src_ip,
                        'dst': dst_ip,
                        'size': packet_len,
                        'protocol': self._get_protocol(packet),
                        'timestamp': datetime.now().isoformat()
                    })
                    
        except Exception as e:
            print(f"[Monitor] Packet processing error: {e}")
            
    def _process_raw_packet(self, packet, addr):
        """Process a raw packet (socket capture)."""
        try:
            self.stats['packets_captured'] += 1
            self.stats['bytes_captured'] += len(packet)
            
            # Parse IP header
            ip_header = packet[0:20]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
            
            version_ihl = iph[0]
            ihl = version_ihl & 0xF
            iph_length = ihl * 4
            
            protocol = iph[6]
            src_ip = socket.inet_ntoa(iph[8])
            dst_ip = socket.inet_ntoa(iph[9])
            
            # Track connection
            tracker = self.connection_tracker[src_ip]
            tracker['packets'] += 1
            tracker['bytes'] += len(packet)
            tracker['last_seen'] = datetime.now()
            
            # Parse TCP/UDP header
            if protocol == 6:  # TCP
                tcp_header = packet[iph_length:iph_length+20]
                tcph = struct.unpack('!HHLLBBHHH', tcp_header)
                dst_port = tcph[1]
                flags = tcph[5]
                
                # SYN flag detection
                if flags & 0x02 and not (flags & 0x10):  # SYN without ACK
                    tracker['syn_count'] += 1
                    if tracker['syn_count'] > self.thresholds['syn_flood']:
                        self._detect_attack('syn_flood', {
                            'ip': src_ip,
                            'syn_count': tracker['syn_count']
                        })
                        
                # Port scanning
                tracker['port_scan_ports'].add(dst_port)
                if len(tracker['port_scan_ports']) > self.thresholds['port_scan']:
                    self._detect_attack('port_scan', {
                        'ip': src_ip,
                        'ports_scanned': len(tracker['port_scan_ports'])
                    })
                    
            elif protocol == 17:  # UDP
                udp_header = packet[iph_length:iph_length+8]
                udph = struct.unpack('!HHHH', udp_header)
                dst_port = udph[1]
                tracker['port_scan_ports'].add(dst_port)
                
            # DoS detection
            if tracker['packets'] > self.thresholds['dos_packets']:
                self._detect_attack('dos', {
                    'ip': src_ip,
                    'packets': tracker['packets']
                })
                
        except Exception as e:
            pass  # Ignore malformed packets
            
    def _check_payload_signatures(self, src_ip, payload):
        """Check packet payload for known attack signatures."""
        for signature in self.attack_signatures:
            if signature in payload:
                self._detect_attack('malicious_payload', {
                    'ip': src_ip,
                    'signature': signature.decode('utf-8', errors='ignore'),
                    'payload_preview': payload[:100].decode('utf-8', errors='ignore')
                })
                break
                
    def _get_protocol(self, packet):
        """Get protocol name from packet."""
        if TCP in packet:
            return 'TCP'
        elif UDP in packet:
            return 'UDP'
        elif ICMP in packet:
            return 'ICMP'
        return 'OTHER'
        
    def _analyze_traffic(self):
        """Periodic traffic analysis and cleanup."""
        while self.running:
            try:
                time.sleep(10)  # Analyze every 10 seconds
                
                now = datetime.now()
                
                # Clean up old tracking data
                expired = []
                for ip, data in self.connection_tracker.items():
                    age = (now - data['last_seen']).total_seconds()
                    
                    # Reset counters for old connections
                    if age > 60:
                        data['syn_count'] = 0
                        data['port_scan_ports'].clear()
                        
                    if age > 300:  # 5 minutes
                        expired.append(ip)
                        
                for ip in expired:
                    del self.connection_tracker[ip]
                    
                # Clean up old detections
                expired_detections = []
                for key, timestamp in self.recent_detections.items():
                    if (now - timestamp).total_seconds() > 60:
                        expired_detections.append(key)
                        
                for key in expired_detections:
                    del self.recent_detections[key]
                    
            except Exception as e:
                print(f"[Monitor] Analysis error: {e}")
                
    def _detect_attack(self, attack_type, details):
        """Handle attack detection."""
        # Avoid duplicate detections
        detection_key = f"{attack_type}:{details.get('ip', 'unknown')}"
        now = datetime.now()
        
        if detection_key in self.recent_detections:
            last_detection = self.recent_detections[detection_key]
            if (now - last_detection).total_seconds() < 30:  # 30 second cooldown
                return
                
        self.recent_detections[detection_key] = now
        self.stats['attacks_detected'] += 1
        
        attack_ip = details.get('ip', 'unknown')
        
        # Get IP geolocation
        geo_data = self._get_ip_geolocation(attack_ip)
        
        # Create attack event
        attack_event = {
            'type': attack_type,
            'ip': attack_ip,
            'details': details,
            'geo': geo_data,
            'timestamp': now.isoformat(),
            'severity': self._get_severity(attack_type)
        }
        
        # Log to database
        try:
            # Add security notification
            add_security_notification(
                notification_type=attack_type,
                title=f"{attack_type.replace('_', ' ').title()} Detected",
                message=f"Attack from {attack_ip} ({geo_data.get('city', 'Unknown')}, {geo_data.get('country', 'Unknown')})",
                severity=attack_event['severity'],
                ip_address=attack_ip,
                website_id=None
            )
            
            # Add realtime activity
            add_realtime_activity(
                website_id=None,
                activity_type=attack_type,
                ip_address=attack_ip,
                details=json.dumps(details),
                severity=attack_event['severity']
            )
            
            # Auto-block if severe
            if attack_event['severity'] == 'critical' and attack_ip != 'unknown':
                if not is_ip_blocked(attack_ip):
                    block_ip_address(
                        ip_address=attack_ip,
                        reason=f"Auto-blocked: {attack_type}",
                        geo_data=geo_data
                    )
                    self.stats['ips_blocked'] += 1
                    attack_event['auto_blocked'] = True
                    
        except Exception as e:
            print(f"[Monitor] Database logging error: {e}")
            
        # Emit event to dashboard
        self._emit_event('attack_detected', attack_event)
        print(f"[Monitor] ⚠️ Attack detected: {attack_type} from {attack_ip}")
        
    def _get_severity(self, attack_type):
        """Determine attack severity."""
        severity_map = {
            'syn_flood': 'critical',
            'dos': 'critical',
            'ddos': 'critical',
            'port_scan': 'warning',
            'brute_force': 'danger',
            'malicious_payload': 'critical',
            'high_traffic': 'warning'
        }
        return severity_map.get(attack_type, 'info')
        
    def _get_ip_geolocation(self, ip):
        """Get geolocation data for an IP address."""
        try:
            # Skip private IPs
            if ip.startswith(('10.', '192.168.', '172.16.', '127.')):
                return {
                    'country': 'Local Network',
                    'city': 'Private',
                    'lat': 0,
                    'lon': 0
                }
                
            response = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return {
                        'country': data.get('country', 'Unknown'),
                        'city': data.get('city', 'Unknown'),
                        'region': data.get('regionName', 'Unknown'),
                        'isp': data.get('isp', 'Unknown'),
                        'lat': data.get('lat', 0),
                        'lon': data.get('lon', 0)
                    }
        except Exception as e:
            print(f"[Monitor] Geolocation error: {e}")
            
        return {'country': 'Unknown', 'city': 'Unknown', 'lat': 0, 'lon': 0}
        
    def _broadcast_stats(self):
        """Broadcast monitoring statistics periodically."""
        while self.running:
            try:
                time.sleep(2)  # Broadcast every 2 seconds
                
                uptime = 0
                if self.stats['start_time']:
                    uptime = (datetime.now() - self.stats['start_time']).total_seconds()
                    
                stats_event = {
                    'packets_captured': self.stats['packets_captured'],
                    'bytes_captured': self.stats['bytes_captured'],
                    'attacks_detected': self.stats['attacks_detected'],
                    'ips_blocked': self.stats['ips_blocked'],
                    'active_trackers': len(self.connection_tracker),
                    'uptime_seconds': int(uptime),
                    'timestamp': datetime.now().isoformat()
                }
                
                self._emit_event('monitor_stats', stats_event)
                
            except Exception as e:
                print(f"[Monitor] Stats broadcast error: {e}")
                
    def _emit_event(self, event_name, data):
        """Emit event to connected clients via WebSocket."""
        if self.socketio:
            try:
                self.socketio.emit(event_name, data, namespace='/monitor')
            except Exception as e:
                print(f"[Monitor] Socket emit error: {e}")
                
    def get_stats(self):
        """Get current monitoring statistics."""
        uptime = 0
        if self.stats['start_time']:
            uptime = (datetime.now() - self.stats['start_time']).total_seconds()
            
        return {
            **self.stats,
            'running': self.running,
            'uptime_seconds': int(uptime),
            'active_connections': len(self.connection_tracker),
            'blocked_ips': len(get_blocked_ips())
        }
        
    def get_active_connections(self):
        """Get list of active connections being tracked."""
        connections = []
        for ip, data in self.connection_tracker.items():
            connections.append({
                'ip': ip,
                'packets': data['packets'],
                'bytes': data['bytes'],
                'ports_accessed': len(data['port_scan_ports']),
                'last_seen': data['last_seen'].isoformat()
            })
        return sorted(connections, key=lambda x: x['packets'], reverse=True)[:50]


# Global monitor instance
monitor = None

def get_monitor(socketio=None):
    """Get or create the global monitor instance."""
    global monitor
    if monitor is None:
        monitor = RealTimeMonitor(socketio)
    elif socketio and monitor.socketio is None:
        monitor.socketio = socketio
    return monitor
