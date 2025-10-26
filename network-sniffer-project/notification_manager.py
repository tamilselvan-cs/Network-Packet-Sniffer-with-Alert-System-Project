import logging

class NotificationManager:
    def __init__(self):
        pass
    
    def send_alert(self, subject, message):
        # Just print to console for now
        print(f"🚨 ALERT: {subject} - {message}")
        logging.info(f"ALERT: {subject} - {message}")