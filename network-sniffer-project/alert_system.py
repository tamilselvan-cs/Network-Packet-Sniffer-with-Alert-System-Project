import pygame
import logging
import time
from datetime import datetime

class AdvancedAlertSystem:
    def __init__(self):
        self.alert_history = []
        self.sound_enabled = True
        self.popup_enabled = True
        self.setup_sound()
    
    def setup_sound(self):
        try:
            pygame.mixer.init()
            # We'll use system beep for now since we don't have sound files
            self.sound_available = True
        except:
            self.sound_available = False
            print("Sound system not available - alerts will be visual only")
    
    def trigger_alert(self, alert_type, severity, source_ip, message):
        """Trigger a comprehensive alert with sound and visual notification"""
        
        alert_data = {
            'timestamp': datetime.now().strftime("%H:%M:%S"),
            'type': alert_type,
            'severity': severity,
            'source': source_ip,
            'message': message
        }
        
        self.alert_history.append(alert_data)
        
        # Print alert to console
        self.print_alert(alert_data)
        
        # Play alert sound for high severity
        if severity == "HIGH" and self.sound_enabled and self.sound_available:
            self.play_alert_sound()
        
        return alert_data
    
    def print_alert(self, alert):
        """Print formatted alert to console"""
        
        if alert['severity'] == "HIGH":
            color_code = "\033[91m"  # Red
            icon = "🔴"
        else:
            color_code = "\033[93m"  # Yellow
            icon = "🟡"
        
        reset_code = "\033[0m"
        
        print(f"\n{color_code}{'!' * 60}{reset_code}")
        print(f"{color_code}{icon} SECURITY ALERT TRIGGERED {icon}{reset_code}")
        print(f"{color_code}Time: {alert['timestamp']}{reset_code}")
        print(f"{color_code}Type: {alert['type']}{reset_code}")
        print(f"{color_code}Severity: {alert['severity']}{reset_code}")
        print(f"{color_code}Source: {alert['source']}{reset_code}")
        print(f"{color_code}Message: {alert['message']}{reset_code}")
        print(f"{color_code}{'!' * 60}{reset_code}\n")
    
    def play_alert_sound(self):
        """Play alert sound (system beep as fallback)"""
        try:
            # System beep
            print("\a")  # This should produce a beep sound
        except:
            pass
    
    def get_alert_summary(self):
        """Get summary of recent alerts"""
        high_alerts = sum(1 for alert in self.alert_history if alert['severity'] == "HIGH")
        medium_alerts = sum(1 for alert in self.alert_history if alert['severity'] == "MEDIUM")
        
        return {
            'total_alerts': len(self.alert_history),
            'high_alerts': high_alerts,
            'medium_alerts': medium_alerts,
            'recent_alerts': self.alert_history[-10:] if self.alert_history else []
        }