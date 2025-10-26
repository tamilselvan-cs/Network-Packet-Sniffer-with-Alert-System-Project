import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import time
from database import DatabaseManager

class ModernSnifferDashboard:
    def __init__(self, root, sniffer):
        self.root = root
        self.sniffer = sniffer
        self.db_manager = DatabaseManager()
        self.setup_gui()
        self.running = False
        self.alert_count = 0
        
    def setup_gui(self):
        # Configure main window
        self.root.title("🔍 CyberGuard - Network Security Monitor")
        self.root.geometry("1000x700")
        self.root.configure(bg='#2c3e50')
        
        # Style configuration
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure colors
        style.configure('Title.TLabel', background='#2c3e50', foreground='white', font=('Arial', 16, 'bold'))
        style.configure('Card.TFrame', background='#34495e')
        style.configure('Card.TLabel', background='#34495e', foreground='white')
        style.configure('Start.TButton', background='#27ae60', foreground='white')
        style.configure('Stop.TButton', background='#e74c3c', foreground='white')
        
        # Header
        header_frame = ttk.Frame(self.root, style='Card.TFrame')
        header_frame.pack(fill=tk.X, padx=10, pady=10)
        
        title_label = ttk.Label(header_frame, text="🔍 CyberGuard - Network Security Monitor", style='Title.TLabel')
        title_label.pack(pady=10)
        
        # Stats Cards Row
        stats_frame = ttk.Frame(self.root, style='Card.TFrame')
        stats_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Stats cards
        self.packets_card = self.create_stat_card(stats_frame, "📦 Total Packets", "0", 0)
        self.alerts_card = self.create_stat_card(stats_frame, "🚨 Security Alerts", "0", 1)
        self.ports_card = self.create_stat_card(stats_frame, "🔒 Monitored Ports", "0", 2)
        self.threats_card = self.create_stat_card(stats_frame, "⚡ Active Threats", "0", 3)
        
        # Control Panel
        control_frame = ttk.LabelFrame(self.root, text="🎛️ Control Panel", padding=10)
        control_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Control buttons
        btn_frame = ttk.Frame(control_frame)
        btn_frame.pack(fill=tk.X)
        
        self.start_btn = ttk.Button(btn_frame, text="▶️ START MONITORING", command=self.start_sniffer, style='Start.TButton')
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(btn_frame, text="⏹️ STOP MONITORING", command=self.stop_sniffer, state=tk.DISABLED, style='Stop.TButton')
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        # Status indicator
        self.status_var = tk.StringVar(value="🔴 READY")
        status_label = ttk.Label(btn_frame, textvariable=self.status_var, foreground='red')
        status_label.pack(side=tk.RIGHT, padx=10)
        
        # Main Content Area
        content_frame = ttk.Frame(self.root)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Left side - Alerts
        alerts_frame = ttk.LabelFrame(content_frame, text="🚨 SECURITY ALERTS", padding=10)
        alerts_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        self.alerts_text = scrolledtext.ScrolledText(alerts_frame, height=20, width=60, bg='#1a1a1a', fg='white', 
                                                   font=('Consolas', 10))
        self.alerts_text.pack(fill=tk.BOTH, expand=True)
        
        # Right side - Statistics
        stats_right_frame = ttk.LabelFrame(content_frame, text="📊 NETWORK STATISTICS", padding=10)
        stats_right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))
        
        self.stats_text = scrolledtext.ScrolledText(stats_right_frame, height=20, width=40, bg='#1a1a1a', fg='white',
                                                  font=('Consolas', 10))
        self.stats_text.pack(fill=tk.BOTH, expand=True)
        
        # Footer
        footer_frame = ttk.Frame(self.root, style='Card.TFrame')
        footer_frame.pack(fill=tk.X, padx=10, pady=5)
        
        footer_label = ttk.Label(footer_frame, text="🛡️ Developed by TamilselvanC for Cyber Security Internship | Real-time Network Protection", 
                               style='Card.TLabel')
        footer_label.pack(pady=5)
        
    def create_stat_card(self, parent, title, value, column):
        card = ttk.Frame(parent, style='Card.TFrame', relief='raised', borderwidth=2)
        card.grid(row=0, column=column, padx=5, pady=5, sticky='ew')
        
        title_label = ttk.Label(card, text=title, style='Card.TLabel', font=('Arial', 10))
        title_label.pack(pady=(5, 0))
        
        value_var = tk.StringVar(value=value)
        value_label = ttk.Label(card, textvariable=value_var, style='Card.TLabel', 
                              font=('Arial', 16, 'bold'), foreground='#3498db')
        value_label.pack(pady=(0, 5))
        
        # Store reference to update later
        if title == "📦 Total Packets":
            self.packets_var = value_var
        elif title == "🚨 Security Alerts":
            self.alerts_var = value_var
        elif title == "🔒 Monitored Ports":
            self.ports_var = value_var
        elif title == "⚡ Active Threats":
            self.threats_var = value_var
            
        return card
    
    def start_sniffer(self):
        self.running = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status_var.set("🟢 MONITORING...")
        
        # Start sniffer in thread
        sniffer_thread = threading.Thread(target=self.sniffer.start_sniffing)
        sniffer_thread.daemon = True
        sniffer_thread.start()
        
        # Start GUI updates
        self.update_gui()
        
    def stop_sniffer(self):
        self.running = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_var.set("🔴 STOPPED")
        
    def update_gui(self):
        if self.running:
            try:
                # Update statistics
                stats = self.db_manager.get_packet_stats()
                total_packets = sum(count for _, count in stats)
                self.packets_var.set(str(total_packets))
                
                # Update protocol stats
                stats_text = "🌐 NETWORK TRAFFIC ANALYSIS\n\n"
                stats_text += "Protocol Distribution:\n"
                stats_text += "─" * 30 + "\n"
                
                for protocol, count in stats:
                    percentage = (count / total_packets * 100) if total_packets > 0 else 0
                    bar = "█" * int(percentage / 5)  # Simple bar chart
                    stats_text += f"{protocol:6} {bar:20} {count:6} ({percentage:.1f}%)\n"
                
                stats_text += "\n📈 TRAFFIC SUMMARY:\n"
                stats_text += "─" * 30 + "\n"
                stats_text += f"Total Packets: {total_packets}\n"
                stats_text += f"Active Alerts: {self.alert_count}\n"
                stats_text += f"Start Time: {time.strftime('%H:%M:%S')}\n"
                
                self.stats_text.delete(1.0, tk.END)
                self.stats_text.insert(1.0, stats_text)
                
                # Update alerts
                alerts = self.db_manager.get_recent_alerts(15)
                self.alert_count = len(alerts)
                self.alerts_var.set(str(self.alert_count))
                
                alerts_text = "🔴 LIVE SECURITY ALERTS\n\n"
                
                if alerts:
                    high_alerts = sum(1 for alert in alerts if alert[2] == "HIGH")
                    medium_alerts = sum(1 for alert in alerts if alert[2] == "MEDIUM")
                    
                    self.threats_var.set(str(high_alerts))
                    
                    alerts_text += f"🚨 HIGH: {high_alerts} | ⚠️ MEDIUM: {medium_alerts}\n"
                    alerts_text += "─" * 50 + "\n\n"
                    
                    for alert in alerts:
                        alert_id, timestamp, severity, alert_type, message, source_ip = alert
                        
                        # Color coding for severity
                        if severity == "HIGH":
                            severity_icon = "🔴"
                            color = "#ff4444"
                        else:
                            severity_icon = "🟡" 
                            color = "#ffaa00"
                        
                        time_str = timestamp.split()[1] if ' ' in timestamp else timestamp
                        alerts_text += f"{severity_icon} [{time_str}] {severity}\n"
                        alerts_text += f"   Type: {alert_type}\n"
                        alerts_text += f"   Source: {source_ip}\n"
                        alerts_text += f"   Message: {message}\n"
                        alerts_text += "   " + "─" * 40 + "\n"
                else:
                    alerts_text += "✅ No security alerts detected\n"
                    alerts_text += "Network is currently secure\n\n"
                    alerts_text += "🎯 Monitoring for:\n"
                    alerts_text += "   • Port Scans\n"
                    alerts_text += "   • Suspicious Ports\n" 
                    alerts_text += "   • DNS Exfiltration\n"
                    alerts_text += "   • HTTP Credentials\n"
                    alerts_text += "   • ICMP Floods\n"
                
                self.alerts_text.delete(1.0, tk.END)
                self.alerts_text.insert(1.0, alerts_text)
                
            except Exception as e:
                print(f"GUI update error: {e}")
            
            # Schedule next update
            self.root.after(3000, self.update_gui)
