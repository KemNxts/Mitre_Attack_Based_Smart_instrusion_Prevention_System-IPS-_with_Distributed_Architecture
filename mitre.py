def get_mitre(attack_type):
    mapping = {
        'Brute Force': {
            'tactic': 'Credential Access',
            'technique': 'T1110'
        },
        'DoS': {
            'tactic': 'Impact',
            'technique': 'T1499'
        },
        'Port Scan': {
            'tactic': 'Reconnaissance',
            'technique': 'T1046'
        },
        'Bot': {
            'tactic': 'Execution',
            'technique': 'T1059'
        },
        'Web Attack': {
            'tactic': 'Initial Access',
            'technique': 'T1190'
        },
        'Normal': {
            'tactic': 'None',
            'technique': 'None'
        }
    }
    return mapping.get(attack_type, {'tactic': 'Unknown', 'technique': 'Unknown'})
