class IPSPrevention:
    def __init__(self):
        self.blocked_ips = set()
        self.closed_ports = set()
        
    def get_action(self, attack_type, ip, confidence=1.0, status="allowed"):
        # 🚫 DO NOT block here — server.py controls blocking
        if status == "blocked":
            return "Block IP (Enforced by IPS)"

        if confidence < 0.6:
            return "Monitor Context"
            
        if attack_type == 'Brute Force':
            return "Monitor Login Attempts"
        elif attack_type == 'DoS':
            return "Rate Limit Traffic"
        elif attack_type == 'Port Scan':
            return "Monitor Ports"
        elif attack_type == 'Bot':
            return "Challenge Traffic"
        elif attack_type == 'Web Attack':
            return "Apply WAF Filter"
        else:
            return "Allow"

    def enforce_block(self, ip):
        # ✅ Only called when server.py decides to block
        self.blocked_ips.add(ip)

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