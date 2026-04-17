def get_mitre(attack_type):
    mapping = {
        'Brute Force': {
            'tactic': 'Credential Access',
            'technique': 'T1110',
            'description': 'Adversaries may use brute force techniques to gain access to accounts when passwords are unknown.'
        },
        'DoS': {
            'tactic': 'Impact',
            'technique': 'T1499',
            'description': 'Adversaries may perform Denial of Service (DoS) attacks to degrade or block the availability of services.'
        },
        'Port Scan': {
            'tactic': 'Reconnaissance',
            'technique': 'T1046',
            'description': 'Adversaries may attempt to get a listing of services running on remote hosts to identify potential targets.'
        },
        'Bot': {
            'tactic': 'Execution',
            'technique': 'T1059',
            'description': 'Adversaries may use software bots to execute automated commands or repeated requests across multiple systems.'
        },
        'Web Attack': {
            'tactic': 'Initial Access',
            'technique': 'T1190',
            'description': 'Adversaries may exploit software vulnerabilities in internet-facing applications to gain access.'
        },
        'Normal': {
            'tactic': 'None',
            'technique': 'None',
            'description': 'Regular legitimate network traffic.'
        }
    }
    return mapping.get(attack_type, {'tactic': 'Unknown', 'technique': 'Unknown', 'description': 'No description available.'})
