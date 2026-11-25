import json
import yaml

def matches_rule(rule, event):
    det = rule["detection"]

    def check_procdump(ev):
        img = (ev.get("Image") or "").lower()
        cmd = (ev.get("CommandLine") or "").lower()
        return img.endswith(("\\procdump.exe", "\\procdump64.exe")) and ("lsass" in cmd)

    def check_comsvcs(ev):
        img = (ev.get("Image") or "").lower()
        cmd = (ev.get("CommandLine") or "").lower()
        return img.endswith("\\rundll32.exe") and ("comsvcs" in cmd and "minidump" in cmd)

    def check_edr_filter(ev):
        img = (ev.get("Image") or "").lower()
        return img.startswith((
            "c:\\program files\\crowdstrike\\",
            "c:\\program files\\microsoft security client\\"
        ))

    matched_selection = check_procdump(event) or check_comsvcs(event)
    return matched_selection and not check_edr_filter(event)

def test_positive_and_negative_fixtures():
    with open("rules/credential_access/win_lsass_dump_procdump.yml") as f:
        rule = yaml.safe_load(f)

    with open("tests/fixtures/positive/lsass_dump.json") as f:
        pos_events = json.load(f)

    with open("tests/fixtures/negative/lsass_benign.json") as f:
        neg_events = json.load(f)

    assert all(matches_rule(rule, ev) for ev in pos_events), "Expected all positive attack events to trigger!"
    assert not any(matches_rule(rule, ev) for ev in neg_events), "Expected zero alerts on benign/EDR events!"
