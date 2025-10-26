from scapy.all import *
import yaml
import time
from collections import defaultdict, deque
import logging

class AdvancedSniffer:
    def __init__(self, db_manager, notification_manager, alert_system):
        self.db_manager = db_manager
        self.notification_manager = notification_manager
        self.alert_system = alert_system
        self.load_ids_rules()
        self.suspicious_ips = defaultdict(lambda: {'port_scan': deque(), 'icmp': deque()})
        self.packet_count = 0
        
    def load_ids_rules(self):
        try:
            with open('ids_rules.yaml', 'r') as file:
                self.ids_rules = yaml.safe_load(file)
            print("✅ IDS Rules loaded successfully")
        except Exception as e:
            print(f"❌ Error loading IDS rules: {e}")
            self.ids_rules = {'rules': {}}
    
    def packet_handler(self, packet):
        try:
            self.packet_count += 1
            self.db_manager.store_packet(packet)
            
            if packet.haslayer('IP'):
                self.detect_port_scan(packet)
                self.detect_dns_exfiltration(packet)
                self.detect_http_credentials(packet)
                self.detect_suspicious_ports(packet)
                self.detect_icmp_flood(packet)
                
            # Show progress every 100 packets
            if self.packet_count % 100 == 0:
                print(f"📦 Processed {self.packet_count} packets...")
                
        except Exception as e:
            pass
    
    def detect_port_scan(self, packet):
        if packet.haslayer('TCP') and packet['TCP'].flags == 'S':
            src_ip = packet['IP'].src
            dst_port = packet['TCP'].dport
            
            if dst_port in [80, 443, 22, 53]:
                return
                
            current_time = time.time()
            self.suspicious_ips[src_ip]['port_scan'].append(current_time)
            
            # Remove old entries
            while (self.suspicious_ips[src_ip]['port_scan'] and 
                   current_time - self.suspicious_ips[src_ip]['port_scan'][0] > 10):
                self.suspicious_ips[src_ip]['port_scan'].popleft()
            
            if len(self.suspicious_ips[src_ip]['port_scan']) >= 10:
                alert_msg = f"Multiple SYN packets detected - Potential port scanning activity"
                self.db_manager.store_alert("HIGH", "Port Scan", alert_msg, src_ip)
                self.alert_system.trigger_alert("Port Scan", "HIGH", src_ip, alert_msg)
                self.suspicious_ips[src_ip]['port_scan'].clear()
    
    def detect_dns_exfiltration(self, packet):
        if packet.haslayer('DNSQR'):
            query = packet['DNSQR'].qname.decode('utf-8', errors='ignore')
            if len(query) > 50:
                alert_msg = f"Unusually long DNS query detected - Possible data exfiltration"
                self.db_manager.store_alert("MEDIUM", "DNS Exfiltration", alert_msg, packet['IP'].src)
                self.alert_system.trigger_alert("DNS Exfiltration", "MEDIUM", packet['IP'].src, alert_msg)
    
    def detect_http_credentials(self, packet):
        if packet.haslayer('TCP') and (packet['TCP'].dport == 80 or packet['TCP'].sport == 80):
            if packet.haslayer('Raw'):
                try:
                    load = packet['Raw'].load.decode('utf-8', errors='ignore').lower()
                    if 'password' in load or 'login' in load:
                        alert_msg = f"Credentials detected in HTTP traffic"
                        self.db_manager.store_alert("HIGH", "HTTP Credentials", alert_msg, packet['IP'].src)
                        self.alert_system.trigger_alert("HTTP Credentials", "HIGH", packet['IP'].src, alert_msg)
                except:
                    pass
    
    def detect_suspicious_ports(self, packet):
        if packet.haslayer('TCP'):
            dst_port = packet['TCP'].dport
            suspicious_ports = [4444, 31337, 1337, 12345, 666, 9999]
            if dst_port in suspicious_ports:
                alert_msg = f"Traffic detected on known suspicious port {dst_port}"
                self.db_manager.store_alert("MEDIUM", "Suspicious Port", alert_msg, packet['IP'].src)
                self.alert_system.trigger_alert("Suspicious Port", "MEDIUM", packet['IP'].src, alert_msg)
    
    def detect_icmp_flood(self, packet):
        if packet.haslayer('ICMP'):
            src_ip = packet['IP'].src
            current_time = time.time()
            self.suspicious_ips[src_ip]['icmp'].append(current_time)
            
            while (self.suspicious_ips[src_ip]['icmp'] and 
                   current_time - self.suspicious_ips[src_ip]['icmp'][0] > 5):
                self.suspicious_ips[src_ip]['icmp'].popleft()
            
            if len(self.suspicious_ips[src_ip]['icmp']) >= 50:
                alert_msg = f"ICMP flood detected - Potential DoS attack"
                self.db_manager.store_alert("HIGH", "ICMP Flood", alert_msg, src_ip)
                self.alert_system.trigger_alert("ICMP Flood", "HIGH", src_ip, alert_msg)
                self.suspicious_ips[src_ip]['icmp'].clear()
    
    def start_sniffing(self):
        print("\n🎯 Starting network monitoring...")
        print("📡 Listening for network traffic...")
        print("🚨 Security alerts will appear below:")
        print("-" * 50)
        
        try:
            sniff(prn=self.packet_handler, store=0)
        except KeyboardInterrupt:
            print("\n⏹️ Monitoring stopped by user")
            print(f"📊 Summary: Processed {self.packet_count} packets")