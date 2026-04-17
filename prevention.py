class IPSPrevention:
    def __init__(self):
        self.blocked_ips = set()
        self.closed_ports = set()
        
    def get_action(self, attack_type, ip, confidence=1.0):
        if confidence < 0.6:
            return "Monitor Context"
            
        if attack_type == 'Brute Force':
            self.blocked_ips.add(ip)
            return "Block IP & Lock Account"
        elif attack_type == 'DoS':
            return "Rate Limit & Drop traffic"
        elif attack_type == 'Port Scan':
            self.closed_ports.add(ip)
            return "Close source ports"
        elif attack_type == 'Bot':
            self.blocked_ips.add(ip)
            return "Challenge & Quarantine"
        elif attack_type == 'Web Attack':
            return "WAF Filter & Block request"
        else:
            return "Allow"

    def get_severity(self, attack_type, confidence=1.0):
        severity_map = {
            'DoS': 'High',
            'Web Attack': 'High',
            'Brute Force': 'Medium',
            'Bot': 'Medium',
            'Port Scan': 'Low',
            'Normal': 'Low'
        }
        base_severity = severity_map.get(attack_type, 'Low')
        
        if confidence > 0.9 and base_severity != 'Low':
            return "CRITICAL"
        return base_severity
