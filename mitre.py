def get_mitre(attack_type):
    """
    Returns the MITRE ATT&CK Tactic and Technique mapping for the 7 canonical host-based attacks.
    """
    mapping = {
        'Parent-Child Memory Eater': {
            'tactic': 'Impact',
            'technique': 'T1496',
            'description': 'Adversaries may exhaust system resources (like RAM or CPU) to deny availability.'
        },
        'Cron Persistence': {
            'tactic': 'Persistence',
            'technique': 'T1053.003',
            'description': 'Adversaries may abuse the cron utility to perform task scheduling for initial or recurring execution of malicious code.'
        },
        'Systemd User Service Persistence': {
            'tactic': 'Persistence',
            'technique': 'T1543.002',
            'description': 'Adversaries may create or modify systemd services to establish persistence.'
        },
        'Discovery Burst': {
            'tactic': 'Discovery',
            'technique': 'T1082 / T1057',
            'description': 'Adversaries may rapidly execute system and process discovery commands to gather information.'
        },
        'Staging / Collection': {
            'tactic': 'Collection',
            'technique': 'T1074.001',
            'description': 'Adversaries may compress and stage collected data in a central location before exfiltration.'
        },
        'Process Masquerading': {
            'tactic': 'Defense Evasion',
            'technique': 'T1036.005',
            'description': 'Adversaries may match or approximate the name or location of legitimate or trusted files.'
        },
        'Shell RC Persistence': {
            'tactic': 'Persistence',
            'technique': 'T1546.004',
            'description': 'Adversaries may establish persistence by modifying Unix shell configuration profiles (e.g., .bashrc).'
        }
    }
    return mapping.get(attack_type, {'tactic': 'Unknown', 'technique': 'Unknown', 'description': 'No description available.'})
