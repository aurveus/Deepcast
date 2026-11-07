"""Incident severity, shared by the incident report and the dashboard so both show the same level.

Critical = proof of movement: the source used a planted honeytoken, or reached a decoy that was only reachable through a lure.
No legitimate user can do either, so it outranks the stage and confidence rules (which stay as they were).
"""


def severity(stage, confidence, token_used=False, decoy_reached=False):
    if token_used or decoy_reached:
        return "Critical"
    if confidence >= 0.7 and stage != "reconnaissance":
        return "High"
    if confidence >= 0.5 and stage == "reconnaissance":
        return "Medium"
    return "Low"
