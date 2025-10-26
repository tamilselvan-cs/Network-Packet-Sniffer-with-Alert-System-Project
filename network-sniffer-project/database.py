import sqlite3
import json
import logging

class DatabaseManager:
    def __init__(self, db_name="network_sniffer.db"):
        self.db_name = db_name
        self.init_database()
    
    def init_database(self):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                source_ip TEXT,
                destination_ip TEXT,
                protocol TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                packet_size INTEGER
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                severity TEXT,
                alert_type TEXT,
                message TEXT,
                source_ip TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def store_packet(self, packet):
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            
            source_ip = destination_ip = protocol = "Unknown"
            src_port = dst_port = 0
            
            if packet.haslayer('IP'):
                source_ip = packet['IP'].src
                destination_ip = packet['IP'].dst
            
            if packet.haslayer('TCP'):
                protocol = "TCP"
                src_port = packet['TCP'].sport
                dst_port = packet['TCP'].dport
            elif packet.haslayer('UDP'):
                protocol = "UDP"
                src_port = packet['UDP'].sport
                dst_port = packet['UDP'].dport
            elif packet.haslayer('ICMP'):
                protocol = "ICMP"
            
            cursor.execute('''
                INSERT INTO packets (source_ip, destination_ip, protocol, src_port, dst_port, packet_size)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (source_ip, destination_ip, protocol, src_port, dst_port, len(packet)))
            
            conn.commit()
            conn.close()
        except Exception as e:
            pass
    
    def store_alert(self, severity, alert_type, message, source_ip):
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO alerts (severity, alert_type, message, source_ip)
                VALUES (?, ?, ?, ?)
            ''', (severity, alert_type, message, source_ip))
            
            conn.commit()
            conn.close()
        except Exception as e:
            pass
    
    def get_recent_alerts(self, limit=10):
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?', (limit,))
            alerts = cursor.fetchall()
            conn.close()
            return alerts
        except:
            return []
    
    def get_packet_stats(self):
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            cursor.execute('SELECT protocol, COUNT(*) FROM packets GROUP BY protocol')
            stats = cursor.fetchall()
            conn.close()
            return stats
        except:
            return []