"""
Tests for strikehound.py CLI helpers.
"""
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from argparse import Namespace
import pytest

from strikehound import (
    worst_finding_severity, clean_target_for_nmap, FAIL_SEVERITY_WEIGHTS,
    load_targets, zap_scan_config, parallel_map, zap_plan_enabled, write_zap_plan,
    load_policy, policy_threshold_for, merge_automation_results,
    _marker_path, _write_marker, target_is_complete,
)


def test_clean_target_for_nmap_strips_scheme():
    assert clean_target_for_nmap("http://example.com") == "example.com"
    assert clean_target_for_nmap("https://example.com:8080/path") == "example.com:8080"


def test_clean_target_for_nmap_keeps_bare_host():
    assert clean_target_for_nmap("192.168.1.1") == "192.168.1.1"


def test_worst_finding_severity_empty():
    assert worst_finding_severity([]) == "info"


def test_worst_finding_severity_returns_worst():
    findings = [
        {"severity": "Low"},
        {"severity": "critical"},
        {"severity": "MediUm"},
    ]
    assert worst_finding_severity(findings) == "critical"


def test_worst_finding_severity_ignores_unknown():
    findings = [{"severity": "apocalyptic"}, {"severity": "high"}]
    assert worst_finding_severity(findings) == "high"


def test_fail_severity_thresholds_ordered():
    assert FAIL_SEVERITY_WEIGHTS["critical"] > FAIL_SEVERITY_WEIGHTS["high"]
    assert FAIL_SEVERITY_WEIGHTS["high"] > FAIL_SEVERITY_WEIGHTS["medium"]
    assert FAIL_SEVERITY_WEIGHTS["medium"] > FAIL_SEVERITY_WEIGHTS["low"]
    assert FAIL_SEVERITY_WEIGHTS["low"] > FAIL_SEVERITY_WEIGHTS["info"]


def _args(target=None, targets_file=None):
    return Namespace(target=target, targets_file=targets_file)


# --- load_targets ---------------------------------------------------------


def test_load_targets_from_single_target():
    assert load_targets(_args(target="http://example.com")) == ["http://example.com"]


def test_load_targets_from_file_skips_comments_and_dedupes(tmp_path):
    f = tmp_path / "targets.txt"
    f.write_text("# comment line\n\nexample.com\n192.168.1.1\nexample.com\n")
    assert load_targets(_args(targets_file=str(f))) == ["example.com", "192.168.1.1"]


def test_load_targets_merges_target_and_file(tmp_path):
    f = tmp_path / "targets.txt"
    f.write_text("example.org\n")
    assert load_targets(_args(target="example.com", targets_file=str(f))) == ["example.com", "example.org"]


def test_load_targets_missing_file_exits(tmp_path):
    with pytest.raises(SystemExit):
        load_targets(_args(targets_file=str(tmp_path / "nope.txt")))


def test_load_targets_requires_at_least_one_target():
    with pytest.raises(SystemExit):
        load_targets(_args())


# --- zap_scan_config ------------------------------------------------------


def test_zap_scan_config_defaults_to_no_auth():
    assert zap_scan_config({"zap": {}}) == (None, False)
    assert zap_scan_config({}) == (None, False)


def test_zap_scan_config_form_auth():
    cfg = {
        "zap": {
            "ajax_spider": True,
            "auth": {
                "method": "form",
                "login_url": "http://x/login",
                "username_field": "user",
                "password_field": "pass",
                "username": "bob",
                "password": "pw",
            },
        }
    }
    auth, ajax = zap_scan_config(cfg)
    assert ajax is True
    assert auth["method"] == "form"
    assert auth["login_url"] == "http://x/login"
    assert auth["username"] == "bob"
    assert auth["password"] == "pw"


def test_zap_scan_config_header_auth():
    cfg = {"zap": {"auth": {"method": "header", "header_name": "X-Api-Key", "header_value": "abc"}}}
    auth, ajax = zap_scan_config(cfg)
    assert auth["method"] == "header"
    assert auth["header_name"] == "X-Api-Key"
    assert auth["header_value"] == "abc"
    assert ajax is False


def test_zap_scan_config_env_vars_override_config(monkeypatch):
    cfg = {"zap": {"auth": {"method": "form", "username": "configuser", "password": "configpw"}}}
    monkeypatch.setenv("STRIKEHOUND_ZAP_USERNAME", "envuser")
    monkeypatch.setenv("STRIKEHOUND_ZAP_PASSWORD", "envpw")
    auth, _ = zap_scan_config(cfg)
    assert auth["username"] == "envuser"
    assert auth["password"] == "envpw"


# --- parallel_map ---------------------------------------------------------


def fanout(x):
    return x * 2


def test_parallel_map_single_job_preserves_order():
    assert parallel_map(fanout, [1, 2, 3], jobs=1) == [2, 4, 6]


def test_parallel_map_multi_job_preserves_order():
    assert parallel_map(fanout, list(range(20)), jobs=5) == [x * 2 for x in range(20)]


def test_parallel_map_empty():
    assert parallel_map(fanout, [], jobs=4) == []


# --- ZAP automation plans -------------------------------------------------


def test_zap_plan_enabled_defaults_false():
    assert zap_plan_enabled({}) is False
    assert zap_plan_enabled({"zap": {"automation": False}}) is False


def test_zap_plan_enabled_true():
    assert zap_plan_enabled({"zap": {"automation": True}}) is True


def test_write_zap_plan_writes_valid_yaml(tmp_path):
    import yaml
    cfg = {
        "tools": {"zap_path": "/opt/zap/zap.sh"},
        "zap": {"automation": True, "auth": {"method": "none"}},
    }
    out_dir = tmp_path / "out"
    plan_path = write_zap_plan("http://example.com", cfg, str(out_dir))
    assert os.path.exists(plan_path)
    assert "zap-plans" in plan_path
    with open(plan_path, "r", encoding="utf-8") as f:
        plan = yaml.safe_load(f)
    assert plan["env"]["contexts"][0]["urls"] == ["http://example.com"]


def test_write_zap_plan_uses_absolute_report_dir(tmp_path):
    import yaml
    cfg = {"tools": {"zap_path": "zap.sh"}, "zap": {"automation": True}}
    out_dir = tmp_path / "out"
    plan_path = write_zap_plan("http://example.com", cfg, str(out_dir))
    with open(plan_path, "r", encoding="utf-8") as f:
        plan = yaml.safe_load(f)
    report_params = [j for j in plan["jobs"] if j["type"] == "report"][0]["parameters"]
    assert os.path.isabs(report_params["reportDir"])
    assert report_params["reportDir"].endswith(os.path.join("out", "zap-reports"))


# --- automation report merging --------------------------------------------


def test_merge_automation_results_returns_empty_without_report(tmp_path, capsys):
    cfg = {"zap": {"automation": True}}
    assert merge_automation_results("http://example.com", cfg, str(tmp_path)) == []


def test_merge_automation_results_filters_to_target(tmp_path):
    import json
    from modules.zap_report_parser import DEFAULT_REPORT_FILE
    report_dir = tmp_path / "zap-reports"
    report_dir.mkdir(parents=True)
    payload = {
        "site": [{
            "@name": "https://example.com", "@host": "example.com", "@port": "443", "@ssl": "true",
            "alerts": [{"alert": "Issue", "riskcode": "2"}],
        }, {
            "@name": "https://other.org", "@host": "other.org", "@port": "443", "@ssl": "true",
            "alerts": [{"alert": "Other", "riskcode": "1"}],
        }]
    }
    with open(report_dir / DEFAULT_REPORT_FILE, "w", encoding="utf-8") as f:
        json.dump(payload, f)

    # Only example.com findings come back for the example.com target.
    findings = merge_automation_results("http://example.com", {"zap": {}}, str(tmp_path))
    assert len(findings) == 1
    assert findings[0]["title"] == "Issue"


# --- resume markers -------------------------------------------------------


def test_marker_round_trip(tmp_path):
    target = "http://example.com"
    assert target_is_complete(str(tmp_path), target) is False
    path = _write_marker(str(tmp_path), target, 42)
    assert os.path.exists(path)
    assert target_is_complete(str(tmp_path), target) is True
    with open(path, "r", encoding="utf-8") as f:
        import yaml
        data = yaml.safe_load(f)
    assert data["findings"] == 42
    assert data["target"] == target


def test_marker_path_is_target_specific(tmp_path):
    assert _marker_path(str(tmp_path), "http://a.example.com") != _marker_path(str(tmp_path), "http://b.example.com")


# --- per-target policies ---------------------------------------------------


def test_policy_threshold_for_exact_and_suffix():
    policy = {"default": "info", "example.com": "high", "prod.example.net": "critical"}
    assert policy_threshold_for("http://example.com", policy) == "high"
    assert policy_threshold_for("https://app.example.com", policy) == "high"  # suffix match
    assert policy_threshold_for("prod.example.net", policy) == "critical"
    assert policy_threshold_for("unknown.org", policy) == "info"  # default


def test_policy_threshold_for_no_default_returns_info():
    assert policy_threshold_for("whatever.com", {"other.com": "low"}) == "info"


def test_load_policy_validates_shape(tmp_path):
    f = tmp_path / "p.yaml"
    f.write_text("example.com: high\ndefault: medium\n")
    assert load_policy(str(f)) == {"example.com": "high", "default": "medium"}


def test_load_policy_missing_file_exits(tmp_path):
    with pytest.raises(SystemExit):
        load_policy(str(tmp_path / "nope.yaml"))