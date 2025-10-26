# Network-Packet-Sniffer-with-Alert-System-Project
"Python-based network packet sniffer with real-time anomalyalerts using scapy,SQLite, and Matplotlib".

🔍 CyberGuard - Network Security Monitor
https://img.shields.io/badge/Python-3.8%252B-blue
https://img.shields.io/badge/License-MIT-green
https://img.shields.io/badge/Platform-Linux-lightgrey

A powerful, real-time network packet sniffer with Intrusion Detection System (IDS) capabilities, built for cybersecurity professionals and enthusiasts.

🚀 Features
🛡️ Security Monitoring
Real-time Packet Analysis - Live network traffic capture and inspection

Advanced IDS Engine - YAML-based rule system for threat detection

Multi-Vector Detection - Port scans, DNS exfiltration, credential leaks, and more

Threat Intelligence - Behavioral analysis and pattern recognition

🎨 User Experience
Modern GUI Dashboard - Dark-themed, intuitive interface

Live Statistics - Real-time traffic visualization and metrics

Smart Alerts - Color-coded notifications with sound alerts

Beginner-Friendly - Easy-to-use controls and clear visualizations

💾 Data Management
SQLite Database - Comprehensive packet and alert storage

Historical Analysis - Trend tracking and reporting

Export Capabilities - Data export for further analysis

Configurable Rules - Customizable detection thresholds

📋 Detection Capabilities
Threat Type	Detection Method	Severity
🔍 Port Scanning	SYN packet frequency analysis	🚨 HIGH
🌐 DNS Exfiltration	Long query length detection	⚠️ MEDIUM
🔑 HTTP Credentials	Cleartext password detection	🚨 HIGH
🚪 Suspicious Ports	Known malicious port monitoring	⚠️ MEDIUM
🌊 ICMP Flood	Packet rate threshold detection	🚨 HIGH
🛠️ Installation
Prerequisites
Kali Linux or any Linux distribution

Python 3.8 or higher

Root privileges for packet capture

Quick Setup
Clone the Repository

bash
git clone https://github.com/yourusername/cyberguard.git
cd cyberguard
Install Dependencies

bash
pip3 install -r requirements.txt
Run CyberGuard

bash
sudo python3 main.py
Manual Installation
Install Python Dependencies

bash
pip3 install scapy==2.5.0 PyYAML==6.0.1 pygame
Verify Installation

bash
python3 -c "import scapy; print('Scapy installed successfully')"
🎯 Usage
Starting the Application
bash
# Navigate to project directory
cd cyberguard

# Run with root privileges (required for packet capture)
sudo python3 main.py
Using the GUI
Launch the Dashboard

The modern GUI will open automatically

You'll see the welcome screen with system status

Start Monitoring

Click "▶️ START MONITORING" to begin packet capture

View real-time statistics in the dashboard

Monitor security alerts in the alerts panel

Stop Monitoring

Click "⏹️ STOP MONITORING" to halt packet capture

Review collected data and alerts

Command Line Interface
For advanced users, you can also use the command-line interface:

bash
# Run in command-line mode
sudo python3 sniffer_core.py
📁 Project Structure
text
Network-Packet-sniffer/
├── main.py                 # Main application entry point
├── sniffer_core.py         # Core packet capture and analysis engine
├── gui_dashboard.py        # Modern GUI interface
├── database.py            # SQLite database management
├── alert_system.py        # Advanced alert handling system
├── notification_manager.py # Email and notification system
├── ids_rules.yaml         # IDS rules configuration
├── requirements.txt       # Python dependencies
├── README.md             # This file
├── network_sniffer.db    # Database file (auto-generated)
├── cyberguard.log        # Log file (auto-generated)
└── Screenshots            #Screenshot of User interface
⚙️ Configuration
IDS Rules Configuration
Edit ids_rules.yaml to customize detection behavior:

yaml
rules:
  port_scan:
    name: "Port Scan Detection"
    threshold: 10        # SYN packets in time window
    time_window: 10      # seconds
    
  dns_exfiltration:
    name: "DNS Exfiltration"
    query_length_threshold: 50  # characters
    
  http_credentials:
    name: "HTTP Credentials"
    keywords: ["password", "login", "username", "credential"]
    
  suspicious_ports:
    name: "Suspicious Port Activity"
    ports: [4444, 31337, 1337, 12345, 54321]
    
  icmp_flood:
    name: "ICMP Flood"
    threshold: 100       # ICMP packets
    time_window: 5       # seconds
Email Notifications
Configure email alerts in notification_manager.py:

python
email_config = {
    'enabled': True,
    'smtp_server': 'smtp.gmail.com',
    'smtp_port': 587,
    'sender_email': 'your_email@gmail.com',
    'sender_password': 'your_app_password',
    'receiver_email': 'alerts@yourcompany.com'
}
🔧 Testing
Generate Test Traffic
Open a new terminal and run these commands to test detection capabilities:

bash
# Test port scan detection
nmap -sS 127.0.0.1

# Test ICMP flood detection
ping -f localhost

# Test DNS queries (in Python)
python3 -c "import socket; socket.gethostbyname('example.com')"

# Generate HTTP traffic
curl http://example.com
Expected Alerts
Port Scan: When multiple SYN packets detected

ICMP Flood: When ICMP packet rate exceeds threshold

DNS Exfiltration: When long DNS queries detected

HTTP Credentials: When passwords detected in HTTP traffic

📊 Features Overview
Dashboard Features
📈 Real-time Traffic Graphs - Live packet count visualization

🎯 Threat Level Indicators - Color-coded security status

📋 Protocol Distribution - Breakdown of network protocols

🔔 Alert History - Chronological alert tracking

Security Features
🛡️ Multi-layer Detection - Multiple detection algorithms

⚡ Real-time Processing - Immediate threat identification

📝 Comprehensive Logging - Detailed event recording

🎨 Visual Alerting - Color-coded severity indicators

Data Management
💾 Efficient Storage - Optimized database operations

🔍 Quick Search - Fast alert and packet lookup

📤 Export Options - Data export capabilities

🗂️ Organized Storage - Structured data organization

🐛 Troubleshooting
Common Issues
Permission Denied Error

bash
# Solution: Run with sudo
sudo python3 main.py
Module Not Found

bash
# Solution: Install dependencies
pip3 install -r requirements.txt
GUI Not Opening

bash
# Solution: Install tkinter
sudo apt install python3-tk
No Packets Captured

bash
# Solution: Check interface and permissions
ip link show
sudo python3 main.py
Debug Mode
Enable verbose logging for troubleshooting:

bash
sudo python3 main.py --debug
🤝 Contributing
We welcome contributions! Please feel free to submit pull requests, report bugs, or suggest new features.

Contribution Guidelines
Fork the repository

Create a feature branch (git checkout -b feature/AmazingFeature)

Commit your changes (git commit -m 'Add some AmazingFeature')

Push to the branch (git push origin feature/AmazingFeature)

Open a Pull Request

Development Setup
bash
# Set up development environment
git clone https://github.com/yourusername/cyberguard.git
cd cyberguard
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
📄 License
This project is licensed under the MIT License - see the LICENSE file for details.

⚠️ Legal Disclaimer
This tool is designed for:

✅ Educational purposes

✅ Authorized security testing

✅ Network monitoring with proper consent

✅ Cybersecurity research

Important: Always ensure you have explicit permission to monitor network traffic. Unauthorized use may violate laws and regulations.


📞 Contact
Developer: Tamilselvan C
Email: tamilselvanc.cs@gmail.com
LinkedIn: Your Profile

🙏 Acknowledgments
Elevate Labs - For the internship opportunity

Scapy Community - For the excellent packet manipulation library

Python Community - For comprehensive documentation and support

Kali Linux Team - For the robust security testing platform

<div align="center">
⭐ If you find this project useful, please give it a star on GitHub!

Built with ❤️ for the cybersecurity community

</div>
