class IPSPrevention:
    def __init__(self):
        self.blocked_ips = set()
        self.closed_ports = set()
        
    def get_action(self, attack_type, ip):
        if attack_type == 'Brute Force':
            self.blocked_ips.add(ip)
            return "Block IP"
        elif attack_type == 'DoS':
            return "Drop traffic"
        elif attack_type == 'Port Scan':
            self.closed_ports.add(80) # Simulated port
            return "Close port"
        elif attack_type == 'Bot':
            self.blocked_ips.add(ip)
            return "Quarantine source"
        elif attack_type == 'Web Attack':
            return "Block request"
        else:
            return "Allow"

    def get_severity(self, attack_type):
        severity_map = {
            'DoS': 'High',
            'Web Attack': 'High',
            'Brute Force': 'Medium',
            'Bot': 'Medium',
            'Port Scan': 'Low',
            'Normal': 'Low'
        }
        return severity_map.get(attack_type, 'Low')
