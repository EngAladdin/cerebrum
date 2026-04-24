"""
cerebrum/rules_engine.py — Deterministic rules evaluator with aggregation windows.
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

log = logging.getLogger("cerebrum.rules")

# ── 15 sample rules covering SSH, HTTP, and generic honeypot patterns ─────────
SAMPLE_RULES = [
    {
        "id": "ssh_brute_force",
        "description": "SSH brute-force: ≥5 auth failures in 5 min",
        "protocol": "ssh",
        "event_types": ["authentication_failed"],
        "indicators": [],
        "window_seconds": 300,
        "count_threshold": 5,
        "skill_delta": 2,
        "level_threshold": 3,
        "action": "escalate_to_level_2",
    },
    {
        "id": "ssh_root_attempt",
        "description": "SSH login attempt using root account",
        "protocol": "ssh",
        "event_types": ["authentication_failed", "authentication_success"],
        "indicators": ["root"],
        "window_seconds": 60,
        "count_threshold": 1,
        "skill_delta": 1,
        "level_threshold": 2,
        "action": "flag",
    },
    {
        "id": "ssh_rapid_reconnect",
        "description": "≥10 new SSH connections in 60 s (scanner behaviour)",
        "protocol": "ssh",
        "event_types": ["connection_new", "authentication_failed"],
        "indicators": [],
        "window_seconds": 60,
        "count_threshold": 10,
        "skill_delta": 2,
        "level_threshold": 3,
        "action": "escalate_to_level_2",
    },
    {
        "id": "ssh_successful_login",
        "description": "SSH authentication success on honeypot",
        "protocol": "ssh",
        "event_types": ["authentication_success"],
        "indicators": [],
        "window_seconds": 3600,
        "count_threshold": 1,
        "skill_delta": 3,
        "level_threshold": 5,
        "action": "escalate_to_level_3",
    },
    {
        "id": "ssh_command_execution",
        "description": "Commands executed inside SSH honeypot session",
        "protocol": "ssh",
        "event_types": ["command_input"],
        "indicators": [],
        "window_seconds": 600,
        "count_threshold": 3,
        "skill_delta": 2,
        "level_threshold": 4,
        "action": "escalate_to_level_2",
    },
    {
        "id": "ssh_known_malware_indicator",
        "description": "Known malware keyword in credentials or commands",
        "protocol": "ssh",
        "event_types": ["authentication_failed", "command_input"],
        "indicators": ["wget", "curl", "chmod", "base64", "/tmp/", "xmrig"],
        "window_seconds": 600,
        "count_threshold": 1,
        "skill_delta": 3,
        "level_threshold": 5,
        "action": "escalate_to_level_3",
    },
    {
        "id": "http_path_traversal",
        "description": "HTTP path-traversal or LFI attempt",
        "protocol": "http",
        "event_types": ["request"],
        "indicators": ["../", "..%2F", "/etc/passwd", "/etc/shadow", "\\..\\"],
        "window_seconds": 120,
        "count_threshold": 1,
        "skill_delta": 2,
        "level_threshold": 3,
        "action": "escalate_to_level_2",
    },
    {
        "id": "http_sqli_attempt",
        "description": "SQL-injection pattern in HTTP request",
        "protocol": "http",
        "event_types": ["request"],
        "indicators": ["' OR ", "UNION SELECT", "1=1", "--", "DROP TABLE", "xp_cmdshell"],
        "window_seconds": 120,
        "count_threshold": 1,
        "skill_delta": 2,
        "level_threshold": 3,
        "action": "escalate_to_level_2",
    },
    {
        "id": "http_scanner_ua",
        "description": "Known scanner User-Agent detected",
        "protocol": "http",
        "event_types": ["request"],
        "indicators": ["sqlmap", "nikto", "masscan", "zgrab", "nmap", "dirbuster"],
        "window_seconds": 300,
        "count_threshold": 1,
        "skill_delta": 1,
        "level_threshold": 2,
        "action": "flag",
    },
    {
        "id": "http_brute_force",
        "description": "≥20 HTTP 401/403 responses in 5 min (credential stuffing)",
        "protocol": "http",
        "event_types": ["authentication_failed", "request_failed"],
        "indicators": [],
        "window_seconds": 300,
        "count_threshold": 20,
        "skill_delta": 2,
        "level_threshold": 4,
        "action": "escalate_to_level_2",
    },
    {
        "id": "http_shell_upload",
        "description": "Possible webshell upload attempt",
        "protocol": "http",
        "event_types": ["request"],
        "indicators": [".php", ".jsp", ".aspx", "cmd=", "exec=", "system(", "passthru("],
        "window_seconds": 300,
        "count_threshold": 1,
        "skill_delta": 3,
        "level_threshold": 5,
        "action": "escalate_to_level_3",
    },
    {
        "id": "generic_port_scan",
        "description": "Rapid connection attempts across ports (port scan)",
        "protocol": None,
        "event_types": ["connection_new", "connection_failed"],
        "indicators": [],
        "window_seconds": 30,
        "count_threshold": 15,
        "skill_delta": 1,
        "level_threshold": 2,
        "action": "flag",
    },
    {
        "id": "repeated_unknown_protocol",
        "description": "Repeated connection with unrecognised protocol",
        "protocol": None,
        "event_types": ["unknown_protocol"],
        "indicators": [],
        "window_seconds": 300,
        "count_threshold": 3,
        "skill_delta": 1,
        "level_threshold": 2,
        "action": "flag",
    },
    {
        "id": "high_skill_persistent_attacker",
        "description": "Session skill score crosses high-risk threshold → level 3",
        "protocol": None,
        "event_types": [],       # triggers on score check, not event type
        "indicators": [],
        "window_seconds": 3600,
        "count_threshold": 1,
        "skill_delta": 0,        # no additional delta; score already high
        "level_threshold": 7,
        "action": "escalate_to_level_3",
    },
    {
        "id": "credential_spray",
        "description": "≥10 different usernames tried in 10 min (credential spray)",
        "protocol": "ssh",
        "event_types": ["authentication_failed"],
        "indicators": [],
        "window_seconds": 600,
        "count_threshold": 10,
        "skill_delta": 2,
        "level_threshold": 4,
        "action": "escalate_to_level_2",
    },
]


def load_rules(rules: list[dict]) -> list[dict]:
    """Validate and return rules list."""
    required = {"id", "description", "event_types", "window_seconds",
                "count_threshold", "skill_delta", "action"}
    for r in rules:
        missing = required - r.keys()
        if missing:
            raise ValueError(f"Rule '{r.get('id','?')}' missing fields: {missing}")
    log.info(f"Loaded {len(rules)} rules")
    return rules


def _indicator_match(event_indicators: list[str], rule_indicators: list[str]) -> bool:
    """Case-insensitive substring match of any rule indicator in event indicators."""
    if not rule_indicators:
        return True
    ev_blob = " ".join(event_indicators).lower()
    return any(ind.lower() in ev_blob for ind in rule_indicators)


class RulesEngine:
    def __init__(self, rules: list[dict], db):
        self.rules = rules
        self.db    = db

    def evaluate(self, event, session: dict) -> list[tuple[dict, int, str]]:
        """
        Evaluate all rules against the incoming event + session.
        Returns list of (rule, new_skill_score, action) for each match.
        """
        matched = []
        for rule in self.rules:
            if not self._event_matches_rule(event, rule, session):
                continue

            # Check aggregation window
            count = self.db.count_events_in_window(
                session_id   = event.session_id,
                event_types  = rule["event_types"],
                window_seconds = rule["window_seconds"],
            )
            if count < rule["count_threshold"]:
                continue

            # Update skill score
            new_score = self.db.update_skill_score(
                session_id  = event.session_id,
                delta       = rule["skill_delta"],
            )

            # Determine action (may escalate to level 3 if score crosses threshold)
            action = rule["action"]
            if new_score >= rule["level_threshold"] and action != "escalate_to_level_3":
                # Bump to level 3 if score is high enough
                if rule.get("action") == "escalate_to_level_2" and new_score >= 7:
                    action = "escalate_to_level_3"

            log.info(
                f"Rule '{rule['id']}' matched session={event.session_id} "
                f"count={count} score={new_score} action={action}"
            )
            matched.append((rule, new_score, action))

        return matched

    def _event_matches_rule(self, event, rule: dict, session: dict) -> bool:
        # Protocol filter (None = any)
        if rule.get("protocol") and event.protocol != rule["protocol"]:
            return False

        # Event type filter (empty list = score-based rule, always consider)
        if rule["event_types"] and event.type not in rule["event_types"]:
            return False

        # Indicator match
        ev_indicators = event.indicators + (
            [event.username] if event.username else []
        )
        if not _indicator_match(ev_indicators, rule.get("indicators", [])):
            return False

        return True