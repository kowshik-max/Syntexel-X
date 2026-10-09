"""Map observed behaviour to MITRE ATT&CK techniques.

Mappings are *possible matches* based on the log evidence, not confirmed attacks.
"""

TECHNIQUES = {
    "T1110": ("Brute Force", "Credential Access"),
    "T1110.003": ("Password Spraying", "Credential Access"),
    "T1078": ("Valid Accounts", "Initial Access / Persistence / Privilege Escalation / Defense Evasion"),
}


def _tech(technique_id):
    name, tactic = TECHNIQUES[technique_id]
    return {"id": technique_id, "name": name, "tactic": tactic}


def map_repeated_failures(distinct_users):
    """Many different usernames from one IP suggests spraying; otherwise brute force."""
    return [_tech("T1110.003" if distinct_users >= 3 else "T1110")]


def map_success_after_failures():
    return [_tech("T1110"), _tech("T1078")]


def map_combination():
    return [_tech("T1110"), _tech("T1078")]


def map_none():
    return []


def summarize(techniques):
    """Return (ids_string, names_string) for storage/display."""
    if not techniques:
        return "", ""
    return (
        " / ".join(t["id"] for t in techniques),
        " / ".join(f"{t['name']} ({t['tactic']})" for t in techniques),
    )
