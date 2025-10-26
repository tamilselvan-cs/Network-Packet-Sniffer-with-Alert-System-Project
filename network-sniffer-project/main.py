import tkinter as tk
import logging
from sniffer_core import AdvancedSniffer
from database import DatabaseManager
from notification_manager import NotificationManager
from gui_dashboard import ModernSnifferDashboard
from alert_system import AdvancedAlertSystem

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('cyberguard.log'),
        logging.StreamHandler()
    ]
)

def show_welcome_message():
    print("\n" + "="*60)
    print("🛡️  WELCOME TO CYBERGUARD NETWORK MONITOR")
    print("="*60)
    print("🔍 Real-time Network Security Monitoring")
    print("🚨 Advanced Threat Detection System")
    print("📊 Live Traffic Analysis Dashboard")
    print("="*60)
    print("Starting CyberGuard services...")
    print("GUI will open shortly...")
    print("="*60 + "\n")

def main():
    show_welcome_message()
    
    try:
        # Initialize all components
        print("[1/4] Initializing Database...")
        db_manager = DatabaseManager()
        
        print("[2/4] Starting Alert System...")
        alert_system = AdvancedAlertSystem()
        
        print("[3/4] Loading Notification Manager...")
        notification_manager = NotificationManager()
        
        print("[4/4] Starting Security Engine...")
        sniffer = AdvancedSniffer(db_manager, notification_manager, alert_system)
        
        print("✅ All systems ready!")
        print("\n🎯 Starting CyberGuard Dashboard...")
        
        # Start GUI
        root = tk.Tk()
        app = ModernSnifferDashboard(root, sniffer)
        root.mainloop()
        
    except Exception as e:
        logging.error(f"Application error: {e}")
        print(f"❌ Error: {e}")
        print("🔧 Falling back to command line mode...")
        
        # Fallback to command line
        db_manager = DatabaseManager()
        alert_system = AdvancedAlertSystem()
        notification_manager = NotificationManager()
        sniffer = AdvancedSniffer(db_manager, notification_manager, alert_system)
        sniffer.start_sniffing()

if __name__ == "__main__":
    main()