"""
WiFi/Hotspot Network Monitor Module
Monitors WiFi network and Mobile Hotspot for connected devices and unauthorized access attempts.
REAL-TIME monitoring - NO DEMO MODE - Everything is REAL
"""

import threading
import time
import socket
import subprocess
import re
import json
import os
from datetime import datetime, timedelta
from collections import defaultdict


# Log suspicious WiFi events to a file for external processing
SUSPICIOUS_LOG_PATH = os.path.join(os.path.dirname(__file__), 'wifi_suspicious.log')

def log_suspicious_event(message, level="medium", category="wifi_intrusion"):
    """Log suspicious WiFi events to a file for later Wazuh processing."""
    try:
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "level": level,
            "category": category,
            "message": message
        }
        with open(SUSPICIOUS_LOG_PATH, 'a', encoding='utf-8') as f:
            f.write(json.dumps(log_entry) + '\n')
    except Exception as e:
        print(f"[WiFi] Failed to log suspicious event: {e}")

# Try to import scapy for ARP scanning
try:
    from scapy.all import ARP, Ether, srp, sniff, get_if_list, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

import psutil

# MAC vendor lookup (common vendors for mobile devices)
MAC_VENDORS = {
    # Apple devices
    'AC:DE:48': 'Apple iPhone/iPad',
    '00:1F:F3': 'Apple',
    '3C:06:30': 'Apple',
    '28:CF:DA': 'Apple',
    'F0:18:98': 'Apple',
    '00:25:00': 'Apple',
    '00:1C:B3': 'Apple',
    '00:23:12': 'Apple',
    '00:26:08': 'Apple',
    '04:0C:CE': 'Apple',
    '10:40:F3': 'Apple',
    '14:10:9F': 'Apple',
    '18:AF:61': 'Apple',
    '1C:1A:C0': 'Apple',
    '20:C9:D0': 'Apple',
    '24:A0:74': 'Apple',
    '28:6A:BA': 'Apple',
    '2C:B4:3A': 'Apple',
    '34:08:BC': 'Apple',
    '38:C9:86': 'Apple',
    '3C:15:C2': 'Apple',
    '40:33:1A': 'Apple',
    '44:D8:84': 'Apple',
    '48:60:BC': 'Apple',
    '4C:57:CA': 'Apple',
    '50:EA:D6': 'Apple',
    '54:26:96': 'Apple',
    '58:55:CA': 'Apple',
    '5C:F9:DD': 'Apple',
    '60:F8:1D': 'Apple',
    '64:A5:C3': 'Apple',
    '68:DB:CA': 'Apple',
    '6C:40:08': 'Apple',
    '70:DE:E2': 'Apple',
    '74:E2:F5': 'Apple',
    '78:31:C1': 'Apple',
    '7C:6D:62': 'Apple',
    '80:E6:50': 'Apple',
    '84:38:35': 'Apple',
    '88:66:A5': 'Apple',
    '8C:85:90': 'Apple',
    '90:8D:6C': 'Apple',
    '94:94:26': 'Apple',
    '98:01:A7': 'Apple',
    '9C:20:7B': 'Apple',
    'A0:D7:95': 'Apple',
    'A4:5E:60': 'Apple',
    'A8:66:7F': 'Apple',
    'AC:BC:32': 'Apple',
    'B0:CA:68': 'Apple',
    'B4:F0:AB': 'Apple',
    'B8:C1:11': 'Apple',
    'BC:67:78': 'Apple',
    'C0:CE:CD': 'Apple',
    'C4:2C:03': 'Apple',
    'C8:33:4B': 'Apple',
    'CC:08:E0': 'Apple',
    'D0:25:98': 'Apple',
    'D4:61:9D': 'Apple',
    'D8:00:4D': 'Apple',
    'DC:2B:2A': 'Apple',
    'E0:B5:5F': 'Apple',
    'E4:25:E7': 'Apple',
    'E8:04:0B': 'Apple',
    'EC:35:86': 'Apple',
    'F0:D1:A9': 'Apple',
    'F4:5C:89': 'Apple',
    'F8:1E:DF': 'Apple',
    'FC:E9:98': 'Apple',
    
    # Samsung devices
    '00:16:6C': 'Samsung',
    '00:17:C9': 'Samsung',
    '00:18:AF': 'Samsung',
    '00:1D:25': 'Samsung',
    '00:1D:F6': 'Samsung',
    '00:21:19': 'Samsung',
    '00:21:D1': 'Samsung',
    '00:23:D6': 'Samsung',
    '00:24:54': 'Samsung',
    '00:24:90': 'Samsung',
    '00:25:66': 'Samsung',
    '00:26:37': 'Samsung',
    '10:D5:42': 'Samsung',
    '14:49:E0': 'Samsung',
    '18:22:7E': 'Samsung',
    '1C:62:B8': 'Samsung',
    '20:13:E0': 'Samsung',
    '24:4B:81': 'Samsung',
    '28:27:BF': 'Samsung',
    '2C:AE:2B': 'Samsung',
    '30:96:FB': 'Samsung',
    '34:23:BA': 'Samsung',
    '38:01:95': 'Samsung',
    '3C:5A:37': 'Samsung',
    '40:0E:85': 'Samsung',
    '44:4E:1A': 'Samsung',
    '48:44:F7': 'Samsung',
    '4C:3C:16': 'Samsung',
    '50:01:BB': 'Samsung',
    '54:40:AD': 'Samsung',
    '58:C3:8B': 'Samsung',
    '5C:0A:5B': 'Samsung',
    '60:6B:BD': 'Samsung',
    '64:77:91': 'Samsung',
    '68:48:98': 'Samsung',
    '6C:2F:2C': 'Samsung',
    '70:28:8B': 'Samsung',
    '74:45:8A': 'Samsung',
    '78:25:AD': 'Samsung',
    '7C:0B:C6': 'Samsung',
    '80:18:A7': 'Samsung',
    '84:11:9E': 'Samsung',
    '88:32:9B': 'Samsung',
    '8C:71:F8': 'Samsung',
    '90:00:DB': 'Samsung',
    '94:01:C2': 'Samsung',
    '98:0C:82': 'Samsung',
    '9C:02:98': 'Samsung',
    'A0:0B:BA': 'Samsung',
    'A4:07:B6': 'Samsung',
    'A8:06:00': 'Samsung',
    'AC:36:13': 'Samsung',
    'B0:47:BF': 'Samsung',
    'B4:07:F9': 'Samsung',
    'B8:5A:73': 'Samsung',
    'BC:14:EF': 'Samsung',
    'C0:19:F5': 'Samsung',
    'C4:42:02': 'Samsung',
    'C8:14:51': 'Samsung',
    'CC:05:1B': 'Samsung',
    'D0:22:BE': 'Samsung',
    'D4:87:D8': 'Samsung',
    'D8:57:EF': 'Samsung',
    'DC:66:72': 'Samsung',
    'E0:99:71': 'Samsung',
    'E4:12:1D': 'Samsung',
    'E8:03:9A': 'Samsung',
    'EC:1F:72': 'Samsung',
    'F0:08:F1': 'Samsung',
    'F4:09:D8': 'Samsung',
    'F8:04:2E': 'Samsung',
    'FC:19:10': 'Samsung',
    
    # Xiaomi/Redmi
    '00:9E:C8': 'Xiaomi',
    '0C:1D:AF': 'Xiaomi',
    '10:2A:B3': 'Xiaomi',
    '14:F6:5A': 'Xiaomi',
    '18:59:36': 'Xiaomi',
    '20:34:FB': 'Xiaomi',
    '28:6C:07': 'Xiaomi',
    '34:80:B3': 'Xiaomi',
    '3C:BD:3E': 'Xiaomi',
    '44:23:7C': 'Xiaomi',
    '50:64:2B': 'Xiaomi',
    '58:44:98': 'Xiaomi',
    '64:B4:73': 'Xiaomi',
    '68:DF:DD': 'Xiaomi',
    '74:23:44': 'Xiaomi',
    '78:02:F8': 'Xiaomi',
    '7C:1D:D9': 'Xiaomi',
    '84:F3:EB': 'Xiaomi',
    '8C:BE:BE': 'Xiaomi',
    '98:FA:E3': 'Xiaomi',
    'A4:50:46': 'Xiaomi',
    'AC:C1:EE': 'Xiaomi',
    'B0:E2:35': 'Xiaomi',
    'C4:6A:B7': 'Xiaomi',
    'D4:97:0B': 'Xiaomi',
    'E8:AB:F3': 'Xiaomi',
    'F0:B4:29': 'Xiaomi',
    'F4:F5:DB': 'Xiaomi',
    'FC:64:BA': 'Xiaomi',
    
    # OnePlus
    '94:65:2D': 'OnePlus',
    'C0:EE:FB': 'OnePlus',
    
    # OPPO
    '18:82:19': 'OPPO',
    '2C:5B:E1': 'OPPO',
    '3C:77:E6': 'OPPO',
    '48:AD:08': 'OPPO',
    '5C:B9:01': 'OPPO',
    '88:D5:0C': 'OPPO',
    'A4:3B:FA': 'OPPO',
    'C4:A5:DF': 'OPPO',
    'E0:19:1D': 'OPPO',
    
    # Vivo
    '20:5E:F7': 'Vivo',
    '40:14:33': 'Vivo',
    '74:D2:1D': 'Vivo',
    '98:6D:35': 'Vivo',
    'B4:A2:EB': 'Vivo',
    'C8:E7:D8': 'Vivo',
    'E4:46:DA': 'Vivo',
    
    # Google/Pixel
    '00:1A:11': 'Google',
    '14:5A:05': 'Google',
    '3C:5A:B4': 'Google',
    '54:60:09': 'Google',
    '94:EB:2C': 'Google',
    'A4:77:33': 'Google',
    'D8:6C:63': 'Google',
    'F4:F5:D8': 'Google',
    
    # Huawei
    '00:18:82': 'Huawei',
    '00:1E:10': 'Huawei',
    '00:22:A1': 'Huawei',
    '00:25:68': 'Huawei',
    '00:25:9E': 'Huawei',
    '04:02:1F': 'Huawei',
    '04:25:C5': 'Huawei',
    '08:19:A6': 'Huawei',
    '10:1B:54': 'Huawei',
    '14:30:04': 'Huawei',
    '18:C5:8A': 'Huawei',
    '1C:15:1F': 'Huawei',
    '20:0B:C7': 'Huawei',
    '24:09:95': 'Huawei',
    
    # Windows PC
    '00:15:5D': 'Windows PC (Hyper-V)',
    '00:03:FF': 'Windows PC',
    '00:0D:3A': 'Windows PC (Microsoft)',
    '28:18:78': 'Windows PC (Microsoft)',
    '3C:83:75': 'Windows PC (Microsoft)',
    '50:1A:C5': 'Windows PC (Microsoft)',
    
    # Intel (Laptop WiFi)
    '00:16:EA': 'Intel (Laptop)',
    '00:1B:21': 'Intel (Laptop)',
    '00:1C:BF': 'Intel (Laptop)',
    '3C:A9:F4': 'Intel (Laptop)',
    '48:51:B7': 'Intel (Laptop)',
    '68:05:CA': 'Intel (Laptop)',
    '84:3A:4B': 'Intel (Laptop)',
    
    # Dell
    '00:14:22': 'Dell',
    '00:21:9B': 'Dell',
    '18:03:73': 'Dell',
    'B0:83:FE': 'Dell',
    
    # HP
    '00:17:A4': 'HP',
    '00:1A:4B': 'HP',
    '2C:41:38': 'HP',
    '80:C1:6E': 'HP',
    
    # Lenovo
    '00:06:1B': 'Lenovo',
    '00:16:41': 'Lenovo',
    '00:1A:6B': 'Lenovo',
    '00:21:86': 'Lenovo',
    
    # Routers
    '00:14:BF': 'Linksys Router',
    '00:1A:70': 'Cisco Router',
    '00:23:68': 'TP-Link Router',
    '30:B5:C2': 'TP-Link',
    '00:24:B2': 'Netgear',
    
    # VM/Virtual
    '00:50:56': 'VMware VM',
    '00:0C:29': 'VMware VM',
    '08:00:27': 'VirtualBox VM',
    '52:54:00': 'QEMU VM',
}


class WiFiMonitor:
    """Monitor WiFi/Hotspot network for connected devices and intrusion attempts.
    REAL-TIME monitoring with aggressive scanning for hotspot mode.
    NO DEMO MODE - Everything is REAL network data.
    """
    
    def __init__(self, socketio=None):
        self.socketio = socketio
        self.running = False
        self.scan_thread = None
        self.monitor_thread = None
        self.auth_monitor_thread = None
        self.hotspot_mode = False
        
        # Known devices (trusted)
        self.known_devices = {}
        
        # Current connected devices
        self.connected_devices = {}
        
        # New/Unknown devices (potential intruders)
        self.unknown_devices = {}
        
        # Intruders - devices trying multiple access attempts
        self.intruders = defaultdict(lambda: {
            'ip': None,
            'mac': None,
            'hostname': None,
            'vendor': None,
            'attempt_count': 0,
            'failed_auth_count': 0,
            'first_seen': None,
            'last_attempt': None,
            'is_intruder': False,
            'blocked': False
        })
        
        # Connection attempts tracker
        self.connection_attempts = defaultdict(lambda: {
            'count': 0,
            'first_seen': None,
            'last_seen': None,
            'blocked': False,
            'ports': []
        })
        
        # Failed authentication attempts
        self.failed_auth_attempts = []
        
        # Network info
        self.network_info = {
            'interface': None,
            'gateway_ip': None,
            'local_ip': None,
            'subnet': None,
            'is_hotspot': False,
            'hotspot_name': None
        }
        
        self._detect_network()
        
    def _detect_network(self):
        """Detect local network configuration and check for hotspot."""
        try:
            # Find local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect(('8.8.8.8', 80))
                local_ip = s.getsockname()[0]
            except:
                local_ip = '127.0.0.1'
            finally:
                s.close()
                
            self.network_info['local_ip'] = local_ip
            
            # Calculate subnet
            ip_parts = local_ip.split('.')
            self.network_info['subnet'] = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
            self.network_info['gateway_ip'] = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.1"
            
            # Check if this is a hotspot (common hotspot IP ranges)
            if local_ip.startswith('192.168.43.') or local_ip.startswith('192.168.137.'):
                self.network_info['is_hotspot'] = True
                self.hotspot_mode = True
                print(f"[WiFi] HOTSPOT MODE DETECTED")
            
            # Try to get hotspot info
            self._detect_hotspot_info()
            
            print(f"[WiFi] Network detected: {self.network_info['subnet']}")
            print(f"[WiFi] Local IP: {local_ip}")
            print(f"[WiFi] Hotspot Mode: {self.hotspot_mode}")
            
        except Exception as e:
            print(f"[WiFi] Network detection error: {e}")
            
    def _detect_hotspot_info(self):
        """Detect if mobile hotspot is active and get info."""
        try:
            # Check for Mobile Hotspot service on Windows
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'hostednetwork'],
                capture_output=True, text=True, timeout=5
            )
            
            if 'Status' in result.stdout:
                if 'Started' in result.stdout or 'Running' in result.stdout:
                    self.hotspot_mode = True
                    self.network_info['is_hotspot'] = True
                    
                    # Extract SSID
                    ssid_match = re.search(r'SSID name\s*:\s*"?([^"\n]+)"?', result.stdout)
                    if ssid_match:
                        self.network_info['hotspot_name'] = ssid_match.group(1).strip()
                        
            # Check for Internet Connection Sharing adapters
            result2 = subprocess.run(
                ['netsh', 'interface', 'show', 'interface'],
                capture_output=True, text=True, timeout=5
            )
            
            if 'Local Area Connection*' in result2.stdout:
                for line in result2.stdout.split('\n'):
                    if 'Local Area Connection*' in line and 'Connected' in line:
                        self.hotspot_mode = True
                        self.network_info['is_hotspot'] = True
                            
        except Exception as e:
            print(f"[WiFi] Hotspot detection: {e}")
            
    def start(self):
        """Start WiFi/Hotspot monitoring - REAL TIME."""
        if self.running:
            return False
            
        self.running = True
        
        # Re-detect network (in case hotspot was just turned on)
        self._detect_network()
        
        # Start network scan thread (faster for hotspot mode)
        self.scan_thread = threading.Thread(target=self._scan_network, daemon=True)
        self.scan_thread.start()
        
        # Start connection monitor thread
        self.monitor_thread = threading.Thread(target=self._monitor_connections, daemon=True)
        self.monitor_thread.start()
        
        # Start authentication failure monitor
        self.auth_monitor_thread = threading.Thread(target=self._monitor_auth_failures, daemon=True)
        self.auth_monitor_thread.start()
        
        # Start packet sniffer for Npcap-based monitoring (if scapy available)
        if SCAPY_AVAILABLE:
            self.sniffer_thread = threading.Thread(target=self._packet_sniffer, daemon=True)
            self.sniffer_thread.start()
            print("[WiFi] Npcap packet sniffer started!")
        
        # Start hotspot client monitor thread
        self.hotspot_client_thread = threading.Thread(target=self._monitor_hotspot_clients, daemon=True)
        self.hotspot_client_thread.start()
        
        self._emit_event('wifi_monitor_started', {
            'message': f'{"HOTSPOT" if self.hotspot_mode else "WiFi"} REAL-TIME monitoring started',
            'network': self.network_info,
            'hotspot_mode': self.hotspot_mode,
            'npcap_enabled': SCAPY_AVAILABLE,
            'timestamp': datetime.now().isoformat()
        })
        
        # Emit separate hotspot_mode event for UI
        self._emit_event('hotspot_mode', {
            'enabled': self.hotspot_mode,
            'network': self.network_info
        })
        
        return True
        
    def stop(self):
        """Stop WiFi monitoring."""
        self.running = False
        self._emit_event('wifi_monitor_stopped', {
            'message': 'WiFi monitoring stopped',
            'timestamp': datetime.now().isoformat()
        })
        return True
        
    def _scan_network(self):
        """Periodically scan network for devices. REAL scanning - no demo mode."""
        scan_interval = 3 if self.hotspot_mode else 5  # Faster for hotspot
        
        while self.running:
            try:
                devices = self._arp_scan()
                
                # Update connected devices
                current_macs = set()
                for device in devices:
                    mac = device.get('mac', '').upper()
                    if not mac or mac == 'UNKNOWN':
                        continue
                        
                    current_macs.add(mac)
                    
                    if mac not in self.connected_devices:
                        # NEW DEVICE CONNECTED!
                        device['first_seen'] = datetime.now().isoformat()
                        device['status'] = 'new'
                        device['connection_count'] = 1
                        
                        if mac not in self.known_devices:
                            # Unknown device - potential intruder!
                            self.unknown_devices[mac] = device
                            
                            # Track as potential intruder
                            self.intruders[mac]['ip'] = device.get('ip')
                            self.intruders[mac]['mac'] = mac
                            self.intruders[mac]['hostname'] = device.get('hostname')
                            self.intruders[mac]['vendor'] = device.get('vendor')
                            self.intruders[mac]['first_seen'] = datetime.now().isoformat()
                            self.intruders[mac]['attempt_count'] = 1
                            
                            self._emit_event('new_device_detected', {
                                'device': device,
                                'alert': True,
                                'is_hotspot': self.hotspot_mode,
                                'message': f"⚠️ NEW DEVICE: {device.get('ip')} - {device.get('hostname', 'Unknown')} ({device.get('vendor', 'Unknown Device')})",
                                'timestamp': datetime.now().isoformat()
                            })
                        else:
                            device['status'] = 'trusted'
                    else:
                        # Update existing device
                        device['status'] = self.connected_devices[mac].get('status', 'unknown')
                        device['first_seen'] = self.connected_devices[mac].get('first_seen')
                        device['connection_count'] = self.connected_devices[mac].get('connection_count', 0) + 1
                            
                    self.connected_devices[mac] = device
                    device['last_seen'] = datetime.now().isoformat()
                    
                # Check for disconnected devices
                disconnected = set(self.connected_devices.keys()) - current_macs
                for mac in disconnected:
                    device = self.connected_devices.pop(mac, None)
                    if device:
                        self._emit_event('device_disconnected', {
                            'device': device,
                            'timestamp': datetime.now().isoformat()
                        })
                        
                # Count device types
                trusted_count = sum(1 for d in self.connected_devices.values() if d.get('status') == 'trusted')
                unknown_count = len(self.unknown_devices)
                blocked_count = sum(1 for d in self.connected_devices.values() if d.get('status') == 'blocked')
                        
                # Emit current device list
                self._emit_event('wifi_devices_update', {
                    'devices': list(self.connected_devices.values()),
                    'unknown_count': unknown_count,
                    'trusted_count': trusted_count,
                    'blocked_count': blocked_count,
                    'total_count': len(self.connected_devices),
                    'is_hotspot': self.hotspot_mode,
                    'timestamp': datetime.now().isoformat()
                })
                
                time.sleep(scan_interval)
                
            except Exception as e:
                print(f"[WiFi] Scan error: {e}")
                time.sleep(2)
                
    def _arp_scan(self):
        """Scan network using multiple REAL methods."""
        devices = []
        seen_macs = set()
        
        # Method 1: Windows ARP cache (always works)
        devices.extend(self._arp_scan_windows())
        
        # Method 2: Ping sweep for hotspot mode
        if self.hotspot_mode:
            self._ping_sweep_fast()
            devices.extend(self._arp_scan_windows())
            
        # Method 3: Scapy if available
        if SCAPY_AVAILABLE:
            devices.extend(self._arp_scan_scapy())
            
        # Method 4: Active connections
        devices.extend(self._scan_active_connections())
        
        # Deduplicate by MAC
        unique_devices = []
        for device in devices:
            mac = device.get('mac', '').upper()
            if mac and mac not in seen_macs and mac != 'FF:FF:FF:FF:FF:FF':
                seen_macs.add(mac)
                unique_devices.append(device)
                
        return unique_devices
        
    def _arp_scan_windows(self):
        """Scan using Windows arp command - REAL data."""
        devices = []
        
        try:
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=10)
            
            for line in result.stdout.split('\n'):
                match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})\s+(\w+)', line)
                if match:
                    ip = match.group(1)
                    mac = match.group(2).replace('-', ':').upper()
                    dtype = match.group(3)
                    
                    if mac == 'FF:FF:FF:FF:FF:FF' or dtype == 'invalid':
                        continue
                        
                    device = {
                        'ip': ip,
                        'mac': mac,
                        'vendor': self._get_vendor(mac),
                        'hostname': self._get_hostname(ip),
                        'type': 'connected'
                    }
                    devices.append(device)
                    
        except Exception as e:
            print(f"[WiFi] ARP scan error: {e}")
            
        return devices
        
    def _ping_sweep_fast(self):
        """Quick ping sweep to populate ARP cache."""
        try:
            subnet_base = self.network_info.get('subnet', '192.168.1.0/24').rsplit('.', 1)[0]
            
            # Ping common hotspot range (usually .1 to .10 for hotspots)
            for i in range(1, 15):
                ip = f"{subnet_base}.{i}"
                subprocess.Popen(
                    ['ping', '-n', '1', '-w', '100', ip],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
            time.sleep(0.5)
            
        except Exception as e:
            print(f"[WiFi] Ping sweep error: {e}")
            
    def _arp_scan_scapy(self):
        """Use scapy for ARP scanning if available - REAL packets."""
        devices = []
        
        if not SCAPY_AVAILABLE:
            return devices
            
        try:
            subnet = self.network_info.get('subnet', '192.168.1.0/24')
            arp = ARP(pdst=subnet)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            
            result = srp(packet, timeout=2, verbose=0)[0]
            
            for sent, received in result:
                mac = received.hwsrc.upper()
                ip = received.psrc
                
                device = {
                    'ip': ip,
                    'mac': mac,
                    'vendor': self._get_vendor(mac),
                    'hostname': self._get_hostname(ip),
                    'type': 'connected'
                }
                devices.append(device)
                
        except Exception as e:
            print(f"[WiFi] Scapy error: {e}")
            
        return devices
        
    def _scan_active_connections(self):
        """Get devices from active network connections - REAL connections."""
        devices = []
        
        try:
            connections = psutil.net_connections(kind='inet')
            
            seen_ips = set()
            local_subnet = self.network_info.get('subnet', '192.168.1.0/24').rsplit('.', 1)[0]
            
            for conn in connections:
                if conn.raddr:
                    remote_ip = conn.raddr.ip
                    
                    # Local network only
                    if remote_ip.startswith(local_subnet) and remote_ip not in seen_ips:
                        if conn.status in ['ESTABLISHED', 'TIME_WAIT']:
                            seen_ips.add(remote_ip)
                            device = {
                                'ip': remote_ip,
                                'mac': 'Resolving...',
                                'vendor': 'Active Connection',
                                'hostname': self._get_hostname(remote_ip),
                                'type': 'active'
                            }
                            devices.append(device)
                            
        except Exception as e:
            print(f"[WiFi] Connection scan error: {e}")
            
        return devices
        
    def _monitor_connections(self):
        """Monitor for connection attempts and suspicious activity - REAL TIME."""
        while self.running:
            try:
                connections = psutil.net_connections(kind='inet')
                
                for conn in connections:
                    if conn.raddr:
                        remote_ip = conn.raddr.ip
                        local_port = conn.laddr.port if conn.laddr else 0
                        status = conn.status
                        
                        # Track local network connections
                        local_subnet = self.network_info.get('subnet', '').rsplit('.', 1)[0]
                        if remote_ip.startswith(local_subnet) or remote_ip.startswith(('192.168.', '10.', '172.')):
                            tracker = self.connection_attempts[remote_ip]
                            tracker['count'] += 1
                            
                            if tracker['first_seen'] is None:
                                tracker['first_seen'] = datetime.now()
                            tracker['last_seen'] = datetime.now()
                            
                            if local_port not in tracker['ports']:
                                tracker['ports'].append(local_port)
                            
                            # Suspicious ports
                            suspicious_ports = [22, 23, 3389, 5900, 445, 139, 21, 25, 110, 143]
                            if local_port in suspicious_ports:
                                self._emit_event('suspicious_connection', {
                                    'ip': remote_ip,
                                    'port': local_port,
                                    'service': self._get_service_name(local_port),
                                    'status': status,
                                    'timestamp': datetime.now().isoformat()
                                })
                                
                            # Port scanning detection
                            if len(tracker['ports']) > 10:
                                self._emit_event('port_scan_detected', {
                                    'ip': remote_ip,
                                    'ports': tracker['ports'][-20:],
                                    'port_count': len(tracker['ports']),
                                    'timestamp': datetime.now().isoformat()
                                })
                                
                time.sleep(1)
                
            except Exception as e:
                print(f"[WiFi] Monitor error: {e}")
                time.sleep(2)
                
    def _monitor_auth_failures(self):
        """
        Monitor for failed authentication attempts to hotspot.
        Detects devices trying to connect with wrong passwords.
        After 5+ failed attempts, marks as INTRUDER.
        
        Monitors multiple event sources:
        - WiFi Direct Session Events (used by Mobile Hotspot)
        - SharedAccess NAT Events  
        - WLAN AutoConfig Events
        - Security Events
        """
        print("[WiFi] Starting hotspot auth failure monitoring...")
        print("[WiFi] Monitoring: WiFi Direct, SharedAccess, WLAN-AutoConfig, Security events")
        
        check_count = 0
        
        while self.running:
            try:
                check_count += 1
                
                # METHOD 1: WiFi Direct Session Events (Mobile Hotspot uses WiFi Direct)
                # These events capture connection attempts to the hotspot
                ps_wifidirect_command = '''
                try {
                    $events = @()
                    
                    # WiFi Direct Session Owner events
                    $wfdEvents = Get-WinEvent -FilterHashtable @{
                        LogName='Microsoft-Windows-WiFiDirect-Session-Owner/Operational'
                        StartTime=(Get-Date).AddMinutes(-3)
                    } -MaxEvents 30 -ErrorAction SilentlyContinue
                    
                    foreach ($e in $wfdEvents) {
                        $events += @{
                            Time = $e.TimeCreated.ToString('o')
                            Id = $e.Id
                            Source = 'WiFiDirect'
                            Message = $e.Message.Substring(0, [Math]::Min($e.Message.Length, 600))
                        }
                    }
                    
                    ConvertTo-Json $events -Compress
                } catch { '[]' }
                '''
                
                result_wfd = subprocess.run(
                    ['powershell', '-Command', ps_wifidirect_command],
                    capture_output=True, text=True, timeout=15
                )
                
                if result_wfd.stdout.strip() and result_wfd.stdout.strip() != '[]':
                    try:
                        events = json.loads(result_wfd.stdout)
                        if not isinstance(events, list):
                            events = [events]
                        
                        for event in events:
                            message = event.get('Message', '')
                            event_id = event.get('Id', 0)
                            
                            # Look for connection failures, disconnects, errors
                            if any(word in message.lower() for word in ['fail', 'error', 'disconnect', 'reject', 'denied', 'timeout']):
                                # Extract MAC address if present
                                mac_match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}', message)
                                
                                if mac_match:
                                    device_key = mac_match.group(0).upper().replace('-', ':')
                                else:
                                    device_key = f"HOTSPOT_{hash(message) % 10000:04d}"
                                
                                print(f"[WiFi] WiFi Direct event detected: {message[:100]}")
                                self._record_failed_attempt(device_key, f"WiFi Direct: {message}")
                                
                    except json.JSONDecodeError:
                        pass
                
                # METHOD 2: SharedAccess/NAT Events (ICS - Internet Connection Sharing)
                ps_nat_command = '''
                try {
                    $events = @()
                    
                    $natEvents = Get-WinEvent -FilterHashtable @{
                        LogName='Microsoft-Windows-SharedAccess_NAT/Operational'
                        StartTime=(Get-Date).AddMinutes(-3)
                    } -MaxEvents 20 -ErrorAction SilentlyContinue
                    
                    foreach ($e in $natEvents) {
                        $events += @{
                            Time = $e.TimeCreated.ToString('o')
                            Id = $e.Id
                            Source = 'NAT'
                            Message = if ($e.Message) { $e.Message.Substring(0, [Math]::Min($e.Message.Length, 400)) } else { 'NAT Event' }
                        }
                    }
                    
                    ConvertTo-Json $events -Compress
                } catch { '[]' }
                '''
                
                result_nat = subprocess.run(
                    ['powershell', '-Command', ps_nat_command],
                    capture_output=True, text=True, timeout=15
                )
                
                if result_nat.stdout.strip() and result_nat.stdout.strip() != '[]':
                    try:
                        events = json.loads(result_nat.stdout)
                        if not isinstance(events, list):
                            events = [events]
                        
                        for event in events:
                            message = event.get('Message', '')
                            # NAT events may indicate new connections
                            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', message)
                            if ip_match:
                                ip = ip_match.group(1)
                                if ip.startswith('192.168.137.') or ip.startswith('192.168.43.'):
                                    print(f"[WiFi] NAT activity for hotspot client: {ip}")
                                    
                    except json.JSONDecodeError:
                        pass
                
                # METHOD 3: HotspotAuth events - specifically for Mobile Hotspot authentication
                ps_hotspotauth_command = '''
                try {
                    $events = @()
                    
                    # HotspotAuth events - captures hotspot authentication attempts
                    $hotspotEvents = Get-WinEvent -FilterHashtable @{
                        LogName='Microsoft-Windows-HotspotAuth/Operational'
                        StartTime=(Get-Date).AddMinutes(-3)
                    } -MaxEvents 20 -ErrorAction SilentlyContinue
                    
                    foreach ($e in $hotspotEvents) {
                        $events += @{
                            Time = $e.TimeCreated.ToString('o')
                            Id = $e.Id
                            Source = 'HotspotAuth'
                            Message = if ($e.Message) { $e.Message.Substring(0, [Math]::Min($e.Message.Length, 500)) } else { 'Auth Event' }
                        }
                    }
                    
                    ConvertTo-Json $events -Compress
                } catch { '[]' }
                '''
                
                result_hotspot = subprocess.run(
                    ['powershell', '-Command', ps_hotspotauth_command],
                    capture_output=True, text=True, timeout=15
                )
                
                if result_hotspot.stdout.strip() and result_hotspot.stdout.strip() != '[]':
                    try:
                        events = json.loads(result_hotspot.stdout)
                        if not isinstance(events, list):
                            events = [events]
                        
                        for event in events:
                            message = event.get('Message', '')
                            
                            # Check for authentication failures
                            if any(word in message.lower() for word in ['fail', 'error', 'denied', 'reject', 'invalid']):
                                mac_match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}', message)
                                
                                if mac_match:
                                    device_key = mac_match.group(0).upper().replace('-', ':')
                                else:
                                    device_key = f"HOTSPOTAUTH_{hash(message) % 10000:04d}"
                                
                                print(f"[WiFi] HotspotAuth event: {message[:100]}")
                                self._record_failed_attempt(device_key, f"HotspotAuth: {message}")
                                
                    except json.JSONDecodeError:
                        pass
                
                # METHOD 4: WLAN-AutoConfig events
                ps_wlan_command = '''
                try {
                    Get-WinEvent -FilterHashtable @{
                        LogName='Microsoft-Windows-WLAN-AutoConfig/Operational'
                        ID=@(8003, 11006)
                        StartTime=(Get-Date).AddMinutes(-2)
                    } -MaxEvents 20 -ErrorAction SilentlyContinue | 
                    Select-Object TimeCreated, Id, @{N='Message';E={$_.Message.Substring(0, [Math]::Min($_.Message.Length, 500))}} |
                    ConvertTo-Json -Compress
                } catch { '[]' }
                '''
                
                result = subprocess.run(
                    ['powershell', '-Command', ps_wlan_command],
                    capture_output=True, text=True, timeout=15
                )
                
                if result.stdout.strip() and result.stdout.strip() != '[]':
                    try:
                        events = json.loads(result.stdout)
                        if not isinstance(events, list):
                            events = [events]
                        
                        for event in events:
                            message = event.get('Message', '')
                            event_id = event.get('Id', 0)
                            
                            # Event 8003 = Connection failed (wrong password, timeout, etc.)
                            if event_id == 8003 or 'fail' in message.lower():
                                # Try to extract MAC/device info from event
                                mac_match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}', message)
                                
                                # Use a unique key (MAC if found, otherwise generate from timestamp)
                                if mac_match:
                                    device_key = mac_match.group(0).upper().replace('-', ':')
                                else:
                                    # Use hash of message as fallback key
                                    device_key = f"UNKNOWN_{hash(message) % 10000:04d}"
                                
                                self._record_failed_attempt(device_key, message)
                                
                    except json.JSONDecodeError:
                        pass
                
                # Method 2: Check Windows Security events (logon failures)
                ps_security_command = '''
                try {
                    Get-WinEvent -FilterHashtable @{
                        LogName='Security'
                        ID=@(4625, 5152, 4776)
                        StartTime=(Get-Date).AddMinutes(-2)
                    } -MaxEvents 15 -ErrorAction SilentlyContinue | 
                    Select-Object TimeCreated, Id, @{N='Message';E={$_.Message.Substring(0, [Math]::Min($_.Message.Length, 800))}} |
                    ConvertTo-Json -Compress
                } catch { '[]' }
                '''
                
                result2 = subprocess.run(
                    ['powershell', '-Command', ps_security_command],
                    capture_output=True, text=True, timeout=15
                )
                
                if result2.stdout.strip() and result2.stdout.strip() != '[]':
                    try:
                        events = json.loads(result2.stdout)
                        if not isinstance(events, list):
                            events = [events]
                            
                        for event in events:
                            message = event.get('Message', '')
                            
                            # Extract IP address
                            ip_match = re.search(r'Source Network Address:\s*(\d+\.\d+\.\d+\.\d+)', message)
                            if not ip_match:
                                ip_match = re.search(r'Client Address:\s*(\d+\.\d+\.\d+\.\d+)', message)
                            
                            if ip_match:
                                ip = ip_match.group(1)
                                # Skip local/loopback addresses
                                if ip.startswith('127.') or ip == '-':
                                    continue
                                    
                                self._record_failed_attempt(ip, message)
                                
                    except json.JSONDecodeError:
                        pass
                
                # Method 3: Monitor hotspot client connection attempts via ARP
                # Devices trying to connect will appear briefly in ARP table
                self._check_hotspot_connection_attempts()
                
                time.sleep(3)  # Check every 3 seconds
                
            except Exception as e:
                print(f"[WiFi] Auth monitor error: {e}")
                time.sleep(5)
    
    def _packet_sniffer(self):
        """
        Sniff network packets using Npcap/scapy for connection detection.
        Monitors for ARP requests, connection attempts, and association frames.
        """
        if not SCAPY_AVAILABLE:
            print("[WiFi] Scapy not available, packet sniffing disabled")
            return
            
        print("[WiFi] Starting Npcap packet sniffer...")
        
        def process_packet(pkt):
            """Process each captured packet."""
            try:
                # Check for ARP requests (device trying to connect)
                if pkt.haslayer(ARP):
                    arp = pkt[ARP]
                    
                    # ARP request (op=1) - device asking "who has this IP?"
                    if arp.op == 1:  # ARP request
                        src_mac = arp.hwsrc.upper()
                        src_ip = arp.psrc
                        dst_ip = arp.pdst
                        
                        # Check if from hotspot subnet
                        if (dst_ip.startswith('192.168.137.') or dst_ip.startswith('192.168.43.') or
                            src_ip.startswith('192.168.137.') or src_ip.startswith('192.168.43.')):
                            
                            # New device attempting connection
                            if src_mac not in self.connected_devices and src_mac not in self.known_devices:
                                # Track this device
                                if src_mac not in self.intruders:
                                    self.intruders[src_mac] = {
                                        'ip': src_ip,
                                        'mac': src_mac,
                                        'hostname': self._get_hostname(src_ip) if src_ip != '0.0.0.0' else 'Unknown',
                                        'vendor': self._get_vendor(src_mac),
                                        'failed_auth_count': 1,
                                        'first_seen': datetime.now().isoformat(),
                                        'last_attempt': datetime.now().isoformat(),
                                        'is_intruder': False,
                                        'type': 'arp_detected'
                                    }
                                    print(f"[WiFi] ARP detected: {src_mac} ({src_ip}) -> {dst_ip}")
                                else:
                                    # Increment attempt count
                                    self.intruders[src_mac]['failed_auth_count'] += 1
                                    self.intruders[src_mac]['last_attempt'] = datetime.now().isoformat()
                                    
                                    # Check if should be marked as intruder (3+ attempts)
                                    if self.intruders[src_mac]['failed_auth_count'] >= 3:
                                        self.intruders[src_mac]['is_intruder'] = True
                                        print(f"[WiFi] 🚨 INTRUDER from ARP: {src_mac} - {self.intruders[src_mac]['failed_auth_count']} attempts!")
                                        
                                        self._emit_event('intruder_detected', {
                                            'ip': src_ip,
                                            'mac': src_mac,
                                            'hostname': self.intruders[src_mac].get('hostname', 'Unknown'),
                                            'vendor': self.intruders[src_mac].get('vendor', 'Unknown'),
                                            'failed_count': self.intruders[src_mac]['failed_auth_count'],
                                            'first_seen': self.intruders[src_mac]['first_seen'],
                                            'last_attempt': self.intruders[src_mac]['last_attempt'],
                                            'message': f"🚨 INTRUDER: {src_mac} - {self.intruders[src_mac]['failed_auth_count']} attempts detected via ARP!",
                                            'timestamp': datetime.now().isoformat()
                                        })
                                        
            except Exception as e:
                pass  # Silently ignore packet processing errors
        
        try:
            # Get the network interface to sniff on
            interfaces = get_if_list()
            print(f"[WiFi] Available interfaces: {interfaces}")
            
            # Sniff ARP packets
            while self.running:
                try:
                    # Sniff for 5 seconds at a time
                    sniff(
                        filter="arp",
                        prn=process_packet,
                        store=False,
                        timeout=5,
                        quiet=True
                    )
                except Exception as e:
                    print(f"[WiFi] Sniffer error: {e}")
                    time.sleep(2)
                    
        except Exception as e:
            print(f"[WiFi] Packet sniffer failed: {e}")
    
    def _monitor_hotspot_clients(self):
        """
        Continuously monitor and emit hotspot client updates.
        Tracks connection attempts to detect intruders.
        """
        print("[WiFi] Starting hotspot client monitor...")
        
        last_connected_macs = set()
        attempt_tracker = {}  # Track IPs that appear in ARP but never connect
        
        while self.running:
            try:
                # Check if hotspot is active
                if self.hotspot_mode or getattr(self, 'hotspot_active', False):
                    # Get ACTUALLY connected clients from Windows API
                    status = self.get_hotspot_status()
                    
                    current_connected_macs = set()
                    
                    if status.get('success') and status.get('clients'):
                        for client in status['clients']:
                            mac = client.get('MacAddress', '').upper().replace('-', ':')
                            if mac and mac != 'FF:FF:FF:FF:FF:FF':
                                current_connected_macs.add(mac)
                    
                    # Get full client list with IPs (only verified connected)
                    clients = self.get_hotspot_clients()
                    
                    # Track new connections
                    new_connections = current_connected_macs - last_connected_macs
                    for mac in new_connections:
                        client = next((c for c in clients if c.get('mac') == mac), None)
                        if client:
                            print(f"[WiFi] New client connected: {client.get('hostname', 'Unknown')} ({client.get('ip', 'N/A')}) - {mac}")
                            
                            self._emit_event('new_hotspot_client', {
                                'client': client,
                                'message': f"📱 Connected: {client.get('hostname', 'Unknown')} ({client.get('ip', 'Getting IP...')})",
                                'timestamp': datetime.now().isoformat()
                            })
                            
                            # Remove from intruders if was tracked there
                            if mac in self.intruders:
                                del self.intruders[mac]
                    
                    # Track disconnections
                    disconnections = last_connected_macs - current_connected_macs
                    for mac in disconnections:
                        print(f"[WiFi] Client disconnected: {mac}")
                        self._emit_event('hotspot_client_disconnected', {
                            'mac': mac,
                            'timestamp': datetime.now().isoformat()
                        })
                    
                    last_connected_macs = current_connected_macs
                    
                    # DETECT INTRUDERS: Check ARP for devices NOT in connected list
                    # Devices that appear in ARP but aren't connected = trying to connect (possibly with wrong password)
                    try:
                        arp_result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=5)
                        
                        for line in arp_result.stdout.split('\n'):
                            if '192.168.137.' in line or '192.168.43.' in line:
                                match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})', line)
                                if match:
                                    ip = match.group(1)
                                    mac = match.group(2).upper().replace('-', ':')
                                    
                                    # Skip gateway, broadcast, and known MACs
                                    if ip.endswith('.1') or ip.endswith('.255') or mac == 'FF:FF:FF:FF:FF:FF':
                                        continue
                                    
                                    # If device is in ARP but NOT connected = possible intruder
                                    if mac not in current_connected_macs and mac not in self.known_devices:
                                        # Track this attempt
                                        if mac not in attempt_tracker:
                                            attempt_tracker[mac] = {'count': 0, 'ip': ip, 'first_seen': datetime.now()}
                                        
                                        attempt_tracker[mac]['count'] += 1
                                        attempt_tracker[mac]['last_seen'] = datetime.now()
                                        
                                        # If 3+ attempts without connecting = INTRUDER
                                        if attempt_tracker[mac]['count'] >= 3:
                                            hostname = self._get_hostname(ip)
                                            vendor = self._get_vendor(mac)
                                            
                                            if mac not in self.intruders or not self.intruders[mac].get('is_intruder'):
                                                self.intruders[mac] = {
                                                    'ip': ip,
                                                    'mac': mac,
                                                    'hostname': hostname if hostname != ip else 'Unknown Device',
                                                    'vendor': vendor,
                                                    'failed_auth_count': attempt_tracker[mac]['count'],
                                                    'first_seen': attempt_tracker[mac]['first_seen'].isoformat(),
                                                    'last_attempt': datetime.now().isoformat(),
                                                    'is_intruder': True,
                                                    'type': 'failed_connection'
                                                }
                                                
                                                print(f"[WiFi] 🚨 INTRUDER DETECTED: {hostname} ({ip}) - MAC: {mac} - {attempt_tracker[mac]['count']} failed attempts!")
                                                
                                                self._emit_event('intruder_detected', {
                                                    'ip': ip,
                                                    'mac': mac,
                                                    'hostname': hostname if hostname != ip else 'Unknown Device',
                                                    'vendor': vendor,
                                                    'failed_count': attempt_tracker[mac]['count'],
                                                    'first_seen': self.intruders[mac]['first_seen'],
                                                    'last_attempt': self.intruders[mac]['last_attempt'],
                                                    'message': f"🚨 INTRUDER: {hostname} ({ip}) - {attempt_tracker[mac]['count']} failed connection attempts!",
                                                    'timestamp': datetime.now().isoformat()
                                                })
                                            else:
                                                # Update existing intruder
                                                self.intruders[mac]['failed_auth_count'] = attempt_tracker[mac]['count']
                                                self.intruders[mac]['last_attempt'] = datetime.now().isoformat()
                                        
                                        elif attempt_tracker[mac]['count'] == 2:
                                            print(f"[WiFi] ⚠️ Warning: {ip} ({mac}) - 2 failed attempts (1 more = intruder)")
                                            
                    except Exception as e:
                        pass
                    
                    # Clear old attempt records (older than 10 minutes)
                    now = datetime.now()
                    old_attempts = [mac for mac, data in attempt_tracker.items() 
                                   if (now - data['last_seen']).total_seconds() > 600]
                    for mac in old_attempts:
                        del attempt_tracker[mac]
                    
                    # Emit current clients list
                    if clients:
                        self._emit_event('hotspot_clients_update', {
                            'clients': clients,
                            'count': len(clients),
                            'timestamp': datetime.now().isoformat()
                        })
                
                time.sleep(3)  # Check every 3 seconds
                
            except Exception as e:
                print(f"[WiFi] Hotspot client monitor error: {e}")
                time.sleep(5)
    
    def _record_failed_attempt(self, device_key, message=''):
        """Record a failed authentication attempt for a device."""
        now = datetime.now()
        
        # Initialize or update intruder record
        if device_key not in self.intruders or not self.intruders[device_key].get('first_seen'):
            self.intruders[device_key] = {
                'ip': device_key if re.match(r'\d+\.\d+\.\d+\.\d+', device_key) else '',
                'mac': device_key if ':' in device_key else '',
                'hostname': '',
                'vendor': '',
                'failed_auth_count': 0,
                'first_seen': now.isoformat(),
                'last_attempt': now.isoformat(),
                'is_intruder': False,
                'attempts': []
            }
        
        intruder = self.intruders[device_key]
        intruder['failed_auth_count'] += 1
        intruder['last_attempt'] = now.isoformat()
        
        # Store attempt details (keep last 10)
        intruder.setdefault('attempts', []).append({
            'time': now.isoformat(),
            'message': message[:200] if message else 'Connection failed'
        })
        if len(intruder['attempts']) > 10:
            intruder['attempts'] = intruder['attempts'][-10:]
        
        # Try to get hostname
        if intruder['ip'] and not intruder['hostname']:
            try:
                intruder['hostname'] = self._get_hostname(intruder['ip'])
            except:
                pass
        
        # Try to get vendor from MAC
        if intruder['mac'] and not intruder['vendor']:
            intruder['vendor'] = self._get_vendor(intruder['mac'])
        
        # Mark as INTRUDER after 3+ failed attempts
        if intruder['failed_auth_count'] >= 3 and not intruder['is_intruder']:
            intruder['is_intruder'] = True
            
            print(f"[WiFi] 🚨 INTRUDER DETECTED: {device_key} - {intruder['failed_auth_count']} failed attempts!")
            
            self._emit_event('intruder_detected', {
                'ip': intruder['ip'] or device_key,
                'mac': intruder['mac'],
                'hostname': intruder['hostname'] or 'Unknown Device',
                'vendor': intruder['vendor'] or 'Unknown',
                'failed_count': intruder['failed_auth_count'],
                'first_seen': intruder['first_seen'],
                'last_attempt': intruder['last_attempt'],
                'message': f"🚨 INTRUDER: {intruder['hostname'] or device_key} - {intruder['failed_auth_count']} failed password attempts!",
                'timestamp': now.isoformat()
            })
        
        # Emit warning for 2 attempts (suspicious, one more = intruder)
        elif intruder['failed_auth_count'] == 2:
            self._emit_event('suspicious_connection', {
                'ip': intruder['ip'] or device_key,
                'service': 'Hotspot',
                'port': 'WiFi',
                'attempts': intruder['failed_auth_count'],
                'message': f"⚠️ Warning: {intruder['hostname'] or device_key} - {intruder['failed_auth_count']} failed attempts (1 more = INTRUDER)"
            })
    
    def _check_hotspot_connection_attempts(self):
        """
        Check for devices attempting to connect to hotspot.
        Uses netsh to get mobile hotspot client info.
        """
        if not self.hotspot_mode and not getattr(self, 'hotspot_active', False):
            return
            
        try:
            # Get currently connected clients
            current_clients = set()
            
            # Method: Use netsh to show hosted network connections
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'hostednetwork'],
                capture_output=True, text=True, timeout=5
            )
            
            # Parse for client information
            for line in result.stdout.split('\n'):
                if 'Number of clients' in line:
                    match = re.search(r':\s*(\d+)', line)
                    if match:
                        client_count = int(match.group(1))
                        
            # Also check ARP for recent entries in hotspot subnet
            arp_result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=5)
            
            for line in arp_result.stdout.split('\n'):
                # Look for hotspot subnet IPs (192.168.137.x)
                if '192.168.137.' in line or '192.168.43.' in line:
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})', line)
                    if match:
                        ip = match.group(1)
                        mac = match.group(2).upper().replace('-', ':')
                        
                        # Skip gateway
                        if ip.endswith('.1'):
                            continue
                            
                        # Check if this is a new device attempting connection
                        if mac not in self.connected_devices and mac not in self.known_devices:
                            # Potential new connection attempt
                            if mac not in self.intruders:
                                self.intruders[mac] = {
                                    'ip': ip,
                                    'mac': mac,
                                    'hostname': self._get_hostname(ip),
                                    'vendor': self._get_vendor(mac),
                                    'failed_auth_count': 1,
                                    'first_seen': datetime.now().isoformat(),
                                    'last_attempt': datetime.now().isoformat(),
                                    'is_intruder': False
                                }
                                
        except Exception as e:
            pass
                
    def _get_vendor(self, mac):
        """Get device vendor from MAC address."""
        if not mac or mac == 'Unknown':
            return 'Unknown Device'
            
        oui = mac[:8].upper()
        return MAC_VENDORS.get(oui, 'Unknown Device')
        
    def _get_hostname(self, ip):
        """Get hostname for IP address."""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            if hostname and hostname != ip:
                return hostname
        except:
            pass
            
        try:
            result = subprocess.run(
                ['nbtstat', '-A', ip],
                capture_output=True, text=True, timeout=3
            )
            
            for line in result.stdout.split('\n'):
                if '<00>' in line and 'UNIQUE' in line:
                    parts = line.split()
                    if parts:
                        return parts[0].strip()
        except:
            pass
            
        return ip
    
    def _ping_host(self, ip, timeout=1):
        """Check if a host is reachable by ping."""
        try:
            result = subprocess.run(
                ['ping', '-n', '1', '-w', str(timeout * 1000), ip],
                capture_output=True, text=True, timeout=timeout + 2
            )
            return result.returncode == 0
        except:
            return False
        
    def _get_service_name(self, port):
        """Get service name for port number."""
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 139: 'NetBIOS', 143: 'IMAP', 443: 'HTTPS',
            445: 'SMB', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC'
        }
        return services.get(port, f'Port-{port}')
        
    def _emit_event(self, event_name, data):
        """Emit event to connected clients."""
        if self.socketio:
            try:
                self.socketio.emit(event_name, data, namespace='/wifi')
            except Exception as e:
                print(f"[WiFi] Emit error: {e}")
                
    def get_devices(self):
        """Get list of connected devices."""
        return list(self.connected_devices.values())
        
    def get_unknown_devices(self):
        """Get list of unknown/new devices."""
        return list(self.unknown_devices.values())
        
    def get_intruders(self):
        """
        Get list of detected intruders (devices with 3+ failed password attempts).
        Returns devices that tried to connect to hotspot with wrong password.
        """
        intruders_list = []
        
        for key, intruder in self.intruders.items():
            failed_count = intruder.get('failed_auth_count', 0)
            
            # Include if marked as intruder OR has 3+ failed attempts
            if intruder.get('is_intruder') or failed_count >= 3:
                intruders_list.append({
                    'ip': intruder.get('ip') or key,
                    'mac': intruder.get('mac', 'Unknown'),
                    'hostname': intruder.get('hostname') or 'Unknown Device',
                    'vendor': intruder.get('vendor') or 'Unknown',
                    'failed_count': failed_count,
                    'first_seen': intruder.get('first_seen'),
                    'last_attempt': intruder.get('last_attempt'),
                    'is_intruder': True,
                    'attempts': intruder.get('attempts', [])[-5:]  # Last 5 attempts
                })
        
        # Sort by failed count (highest first)
        intruders_list.sort(key=lambda x: x.get('failed_count', 0), reverse=True)
        
        return intruders_list
    
    def clear_intruders(self):
        """
        Clear all detected intruders from the list.
        Resets the intruders dictionary.
        """
        cleared_count = len([i for i in self.intruders.values() if i.get('is_intruder') or i.get('failed_auth_count', 0) >= 3])
        self.intruders.clear()
        
        # Emit socket event to update UI
        if self.socketio:
            self.socketio.emit('intruders_cleared', {
                'cleared_count': cleared_count,
                'timestamp': datetime.now().isoformat()
            }, namespace='/wifi')
        
        logger.info(f"Cleared {cleared_count} intruders from the list")
        return cleared_count
    
    def get_suspicious_devices(self):
        """
        Get devices with 1-2 failed attempts (suspicious but not yet intruders).
        Intruders are devices with 3+ failed attempts.
        """
        suspicious_list = []
        
        for key, device in self.intruders.items():
            failed_count = device.get('failed_auth_count', 0)
            
            # Include if 1-2 failed attempts (suspicious but not intruder yet)
            if 1 <= failed_count < 3 and not device.get('is_intruder'):
                suspicious_list.append({
                    'ip': device.get('ip') or key,
                    'mac': device.get('mac', 'Unknown'),
                    'hostname': device.get('hostname') or 'Unknown Device',
                    'vendor': device.get('vendor') or 'Unknown',
                    'failed_count': failed_count,
                    'first_seen': device.get('first_seen'),
                    'last_attempt': device.get('last_attempt')
                })
        
        return suspicious_list
        
    def trust_device(self, mac):
        """Mark a device as trusted."""
        mac = mac.upper()
        if mac in self.connected_devices:
            self.known_devices[mac] = self.connected_devices[mac]
            self.connected_devices[mac]['status'] = 'trusted'
            if mac in self.unknown_devices:
                del self.unknown_devices[mac]
            return True
        return False
        
    def block_device(self, mac):
        """Mark a device as blocked."""
        mac = mac.upper()
        if mac in self.connected_devices:
            self.connected_devices[mac]['status'] = 'blocked'
            self.connected_devices[mac]['blocked_at'] = datetime.now().isoformat()
            return True
        return False
        
    def get_stats(self):
        """Get WiFi monitoring statistics."""
        return {
            'running': self.running,
            'hotspot_mode': self.hotspot_mode,
            'hotspot_active': self.hotspot_active if hasattr(self, 'hotspot_active') else False,
            'total_devices': len(self.connected_devices),
            'unknown_devices': len(self.unknown_devices),
            'known_devices': len(self.known_devices),
            'intruders': len([i for i in self.intruders.values() if i.get('is_intruder')]),
            'network': self.network_info
        }
    
    def start_hotspot(self):
        """
        Start Windows Mobile Hotspot - REAL HOTSPOT CONTROL.
        Uses PowerShell to enable Mobile Hotspot on Windows 10/11.
        """
        try:
            # Method 1: Use Windows Settings API via PowerShell
            ps_script = '''
            Add-Type -AssemblyName System.Runtime.WindowsRuntime
            
            $asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | ? { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]
            
            Function Await($WinRtTask, $ResultType) {
                $asTask = $asTaskGeneric.MakeGenericMethod($ResultType)
                $netTask = $asTask.Invoke($null, @($WinRtTask))
                $netTask.Wait(-1) | Out-Null
                $netTask.Result
            }
            
            $connectionProfile = [Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime]::GetInternetConnectionProfile()
            $tetheringManager = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime]::CreateFromConnectionProfile($connectionProfile)
            
            if ($tetheringManager.TetheringOperationalState -ne 'On') {
                $result = Await ($tetheringManager.StartTetheringAsync()) ([Windows.Networking.NetworkOperators.NetworkOperatorTetheringOperationResult])
                if ($result.Status -eq 'Success') {
                    Write-Output "HOTSPOT_STARTED"
                } else {
                    Write-Output "FAILED:$($result.Status)"
                }
            } else {
                Write-Output "HOTSPOT_ALREADY_ON"
            }
            '''
            
            result = subprocess.run(
                ['powershell', '-ExecutionPolicy', 'Bypass', '-Command', ps_script],
                capture_output=True, text=True, timeout=30
            )
            
            output = result.stdout.strip()
            
            if 'HOTSPOT_STARTED' in output or 'HOTSPOT_ALREADY_ON' in output:
                self.hotspot_active = True
                self.hotspot_mode = True
                
                # Wait a moment for hotspot to fully initialize
                time.sleep(2)
                
                # Re-detect network to get hotspot IP
                self._detect_network()
                
                self._emit_event('hotspot_enabled', {
                    'success': True,
                    'message': 'Mobile Hotspot enabled successfully',
                    'network': self.network_info,
                    'timestamp': datetime.now().isoformat()
                })
                
                print("[WiFi] Mobile Hotspot ENABLED successfully")
                return {'success': True, 'message': 'Hotspot enabled'}
            else:
                print(f"[WiFi] Hotspot start failed: {output}")
                # Try fallback method using netsh (for hosted network)
                return self._start_hotspot_netsh()
                
        except Exception as e:
            print(f"[WiFi] Hotspot start error: {e}")
            return self._start_hotspot_netsh()
    
    def _start_hotspot_netsh(self):
        """Fallback method using netsh hostednetwork (older Windows)."""
        try:
            # Check if hosted network is supported
            check_result = subprocess.run(
                ['netsh', 'wlan', 'show', 'drivers'],
                capture_output=True, text=True, timeout=10
            )
            
            if 'Hosted network supported' not in check_result.stdout and 'Yes' not in check_result.stdout:
                return {'success': False, 'message': 'Hosted network not supported. Please enable Mobile Hotspot from Windows Settings.'}
            
            # Start hosted network
            subprocess.run(
                ['netsh', 'wlan', 'start', 'hostednetwork'],
                capture_output=True, text=True, timeout=10
            )
            
            self.hotspot_active = True
            self.hotspot_mode = True
            time.sleep(2)
            self._detect_network()
            
            self._emit_event('hotspot_enabled', {
                'success': True,
                'message': 'Hosted Network enabled',
                'timestamp': datetime.now().isoformat()
            })
            
            return {'success': True, 'message': 'Hotspot enabled via hosted network'}
            
        except Exception as e:
            return {'success': False, 'message': f'Failed to start hotspot: {str(e)}. Please enable Mobile Hotspot manually from Windows Settings.'}
    
    def stop_hotspot(self):
        """
        Stop Windows Mobile Hotspot.
        """
        try:
            ps_script = '''
            Add-Type -AssemblyName System.Runtime.WindowsRuntime
            
            $asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | ? { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]
            
            Function Await($WinRtTask, $ResultType) {
                $asTask = $asTaskGeneric.MakeGenericMethod($ResultType)
                $netTask = $asTask.Invoke($null, @($WinRtTask))
                $netTask.Wait(-1) | Out-Null
                $netTask.Result
            }
            
            $connectionProfile = [Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime]::GetInternetConnectionProfile()
            $tetheringManager = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime]::CreateFromConnectionProfile($connectionProfile)
            
            if ($tetheringManager.TetheringOperationalState -eq 'On') {
                $result = Await ($tetheringManager.StopTetheringAsync()) ([Windows.Networking.NetworkOperators.NetworkOperatorTetheringOperationResult])
                Write-Output "HOTSPOT_STOPPED"
            } else {
                Write-Output "HOTSPOT_ALREADY_OFF"
            }
            '''
            
            result = subprocess.run(
                ['powershell', '-ExecutionPolicy', 'Bypass', '-Command', ps_script],
                capture_output=True, text=True, timeout=30
            )
            
            self.hotspot_active = False
            self.hotspot_mode = False
            
            self._emit_event('hotspot_disabled', {
                'success': True,
                'message': 'Mobile Hotspot disabled',
                'timestamp': datetime.now().isoformat()
            })
            
            print("[WiFi] Mobile Hotspot DISABLED")
            return {'success': True, 'message': 'Hotspot disabled'}
            
        except Exception as e:
            # Try netsh fallback
            try:
                subprocess.run(['netsh', 'wlan', 'stop', 'hostednetwork'], capture_output=True, timeout=10)
                self.hotspot_active = False
                return {'success': True, 'message': 'Hotspot stopped'}
            except:
                return {'success': False, 'message': str(e)}
    
    def get_hotspot_status(self):
        """Get current hotspot status and connected clients."""
        try:
            ps_script = '''
            Add-Type -AssemblyName System.Runtime.WindowsRuntime
            
            $asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | ? { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]
            
            Function Await($WinRtTask, $ResultType) {
                $asTask = $asTaskGeneric.MakeGenericMethod($ResultType)
                $netTask = $asTask.Invoke($null, @($WinRtTask))
                $netTask.Wait(-1) | Out-Null
                $netTask.Result
            }
            
            $connectionProfile = [Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime]::GetInternetConnectionProfile()
            
            if ($connectionProfile) {
                $tetheringManager = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime]::CreateFromConnectionProfile($connectionProfile)
                
                $status = @{
                    State = $tetheringManager.TetheringOperationalState.ToString()
                    MaxClients = $tetheringManager.MaxClientCount
                    ClientCount = $tetheringManager.ClientCount
                    SSID = ""
                    Clients = @()
                }
                
                # Get SSID
                $config = $tetheringManager.GetCurrentAccessPointConfiguration()
                if ($config) {
                    $status.SSID = $config.Ssid
                }
                
                # Get connected clients
                $clients = $tetheringManager.GetTetheringClients()
                foreach ($client in $clients) {
                    $status.Clients += @{
                        HostName = $client.HostNames[0].DisplayName
                        MacAddress = $client.MacAddress
                    }
                }
                
                ConvertTo-Json $status -Compress
            } else {
                Write-Output '{"State":"NoConnection","Error":"No internet connection"}'
            }
            '''
            
            result = subprocess.run(
                ['powershell', '-ExecutionPolicy', 'Bypass', '-Command', ps_script],
                capture_output=True, text=True, timeout=15
            )
            
            if result.stdout.strip():
                try:
                    status = json.loads(result.stdout.strip())
                    self.hotspot_active = status.get('State') == 'On'
                    return {
                        'success': True,
                        'active': self.hotspot_active,
                        'ssid': status.get('SSID', 'Unknown'),
                        'max_clients': status.get('MaxClients', 8),
                        'client_count': status.get('ClientCount', 0),
                        'clients': status.get('Clients', [])
                    }
                except json.JSONDecodeError:
                    pass
            
            return {'success': True, 'active': False, 'clients': []}
            
        except Exception as e:
            print(f"[WiFi] Hotspot status error: {e}")
            return {'success': False, 'active': False, 'error': str(e)}
    
    def get_hotspot_clients(self):
        """
        Get all devices ACTUALLY connected to the hotspot with IP addresses.
        Verifies connectivity by pinging devices.
        """
        clients = []
        seen_macs = set()
        
        try:
            # Method 1: Use Windows Tethering API to get connected clients (most accurate)
            status = self.get_hotspot_status()
            api_macs = set()
            
            if status.get('success') and status.get('clients'):
                for client in status['clients']:
                    mac = client.get('MacAddress', '').upper().replace('-', ':')
                    if mac and mac not in seen_macs and mac != 'FF:FF:FF:FF:FF:FF':
                        seen_macs.add(mac)
                        api_macs.add(mac)
                        clients.append({
                            'hostname': client.get('HostName', 'Unknown'),
                            'mac': mac,
                            'ip': '',  # Will be filled by ARP scan
                            'vendor': self._get_vendor(mac),
                            'source': 'tethering_api',
                            'verified': True  # API-verified as connected
                        })
            
            # Method 2: ARP scan for IP addresses - but VERIFY connectivity
            arp_result = subprocess.run(
                ['arp', '-a'],
                capture_output=True, text=True, timeout=10
            )
            
            # Parse ARP table and match with hotspot subnet (192.168.137.x)
            for line in arp_result.stdout.split('\n'):
                match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})', line)
                if match:
                    ip = match.group(1)
                    mac = match.group(2).upper().replace('-', ':')
                    
                    # Check if this is a hotspot client (192.168.137.x is Windows hotspot subnet)
                    if ip.startswith('192.168.137.') or ip.startswith('192.168.43.'):
                        # Skip gateway (.1) and broadcast (.255)
                        if ip.endswith('.1') or ip.endswith('.255'):
                            continue
                        
                        # Skip broadcast MAC
                        if mac == 'FF:FF:FF:FF:FF:FF':
                            continue
                        
                        # Update existing client with IP
                        found = False
                        for client in clients:
                            if client['mac'] == mac:
                                client['ip'] = ip
                                found = True
                                break
                        
                        # If not in API list, verify by ping before adding
                        if not found and mac not in seen_macs:
                            # Quick ping to verify device is actually connected
                            is_alive = self._ping_host(ip)
                            
                            if is_alive:
                                seen_macs.add(mac)
                                hostname = self._get_hostname(ip)
                                clients.append({
                                    'hostname': hostname if hostname != ip else 'Unknown',
                                    'mac': mac,
                                    'ip': ip,
                                    'vendor': self._get_vendor(mac),
                                    'source': 'arp_verified',
                                    'verified': True
                                })
            
            # Emit hotspot clients update
            if clients:
                self._emit_event('hotspot_clients_update', {
                    'clients': clients,
                    'count': len(clients),
                    'timestamp': datetime.now().isoformat()
                })
            
            return clients
            
        except Exception as e:
            print(f"[WiFi] Error getting hotspot clients: {e}")
            return clients
    
    def clear_intruders(self):
        """Clear all intruder records."""
        count = len([i for i in self.intruders.values() if i.get('is_intruder')])
        self.intruders.clear()
        
        self._emit_event('intruders_cleared', {
            'message': f'Cleared {count} intruder records',
            'timestamp': datetime.now().isoformat()
        })
        
        return {'success': True, 'cleared': count}


# Global WiFi monitor instance
wifi_monitor = None

def get_wifi_monitor(socketio=None):
    """Get or create WiFi monitor instance."""
    global wifi_monitor
    if wifi_monitor is None:
        wifi_monitor = WiFiMonitor(socketio)
    elif socketio and wifi_monitor.socketio is None:
        wifi_monitor.socketio = socketio
    return wifi_monitor
