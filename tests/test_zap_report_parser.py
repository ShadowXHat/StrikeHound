"""
Tests for modules/zap_report_parser.py - merging ZAP automation reports.
"""
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import json

from modules.zap_report_parser import parse_zap_json_report, latest_report


def _write_report(tmp_path, payload, name="zap-report.json"):
    path = tmp_path / name
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f)
    return str(path)


def _sample_payload():
    return {
        "@generated": "now",
        "site": [{
            "@name": "https://example.com",
            "@host": "example.com",
            "@port": "443",
            "@ssl": "true",
            "alerts": [
                {"alert": "Missing Header", "riskcode": "1", "desc": "d1",
                 "solution": "s1", "cweid": "16", "wascid": "15"},
                {"alert": "SQL Injection", "riskcode": "3", "desc": "d2",
                 "solution": "s2", "evidence": "ev", "confidence": "2"},
            ],
        }]
    }


def test_parse_zap_json_report(tmp_path):
    findings = parse_zap_json_report(_write_report(tmp_path, _sample_payload()))
    assert len(findings) == 2

    f0, f1 = findings
    assert f0["tool"] == "zap"
    assert f0["title"] == "Missing Header"
    assert f0["severity"] == 1            # riskcode parsed as int
    assert f0["target"] == "https://example.com"
    assert f0["port"] == 443              # from @ssl/@port
    assert f0["remediation"] == "s1"
    assert f0["cwe_id"] == "16"
    assert f0["wasc_id"] == "15"

    assert f1["severity"] == 3
    assert f1["evidence"] == "ev"
    assert f1["confidence"] == 2


def test_parse_handles_http_port_and_missing_ssl(tmp_path):
    payload = {
        "site": [{
            "@name": "http://example.com",
            "@host": "example.com",
            "@port": "80",
            "@ssl": "false",
            "alerts": [{"alert": "X", "riskcode": "0", "desc": "", "solution": ""}],
        }]
    }
    findings = parse_zap_json_report(_write_report(tmp_path, payload))
    assert findings[0]["port"] == 80


def test_parse_ignores_bad_riskcode(tmp_path):
    payload = {
        "site": [{
            "@name": "http://example.com",
            "@host": "example.com",
            "@port": "80",
            "alerts": [{"alert": "X", "riskcode": "not-a-number"}],
        }]
    }
    findings = parse_zap_json_report(_write_report(tmp_path, payload))
    assert findings[0]["severity"] == 0


def test_parse_empty_alerts(tmp_path):
    payload = {"site": [{"@name": "http://example.com", "@port": "80", "alerts": []}]}
    assert parse_zap_json_report(_write_report(tmp_path, payload)) == []


def test_parse_empty_report(tmp_path):
    assert parse_zap_json_report(_write_report(tmp_path, {})) == []


def test_latest_report_found(tmp_path):
    path = _write_report(tmp_path, {})
    assert latest_report(str(tmp_path)) == path


def test_latest_report_missing(tmp_path):
    assert latest_report(str(tmp_path)) is None
    assert latest_report(str(tmp_path / "nope")) is None