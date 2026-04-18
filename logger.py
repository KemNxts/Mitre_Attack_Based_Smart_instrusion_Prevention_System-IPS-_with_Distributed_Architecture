import logging
import os
from datetime import datetime

class IPSLogger:
    def __init__(self):
        self.log_dir = 'logs'
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
            
        # System Log
        self.system_logger = logging.getLogger('system')
        self.system_logger.setLevel(logging.INFO)
        sys_handler = logging.FileHandler(os.path.join(self.log_dir, 'system.log'))
        sys_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        sys_handler.setFormatter(sys_formatter)
        self.system_logger.addHandler(sys_handler)
        
        # Alerts Log
        self.alerts_logger = logging.getLogger('alerts')
        self.alerts_logger.setLevel(logging.WARNING)
        alert_handler = logging.FileHandler(os.path.join(self.log_dir, 'alerts.log'))
        alert_formatter = logging.Formatter('%(asctime)s - ALERT - %(message)s')
        alert_handler.setFormatter(alert_formatter)
        self.alerts_logger.addHandler(alert_handler)

    def log_system(self, message, level="INFO"):
        if level == "WARNING":
            self.system_logger.warning(message)
        elif level == "ERROR":
            self.system_logger.error(message)
        else:
            self.system_logger.info(message)

    def log_alert(self, ip, attack, mitre, action, severity="Medium", confidence=1.0):
        message = (
            f"[{severity}] [Conf: {confidence:.2f}] "
            f"IP: {ip} | Attack: {attack} | MITRE: {mitre['technique']} | Action: {action}"
        )
        self.alerts_logger.warning(message)
        print(f"ALERT: {message}")
        return message
