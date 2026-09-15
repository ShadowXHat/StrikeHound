"""
Tests for modules/zap_plan.py - ZAP Automation Framework plan generation.
"""
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import yaml

from modules.zap_plan import build_plan, AUTH_CONTEXT, AUTH_USER


def _load_plan(tmp_path, **kwargs):
    out = tmp_path / "plan.yaml"
    build_plan("http://example.com", str(out), **kwargs)
    with open(out, "r", encoding="utf-8") as f:
        return yaml.safe_load(f), str(out)


def test_build_plan_no_auth(tmp_path):
    plan, out = _load_plan(tmp_path)
    context = plan["env"]["contexts"][0]
    assert context["urls"] == ["http://example.com"]
    assert context["name"] == AUTH_CONTEXT
    assert "authentication" not in context
    assert "users" not in context
    job_types = [j["type"] for j in plan["jobs"]]
    assert job_types == ["spider", "passiveScan-wait", "activeScan", "report"]


def test_build_plan_form_auth(tmp_path):
    auth = {
        "method": "form",
        "login_url": "http://example.com/login",
        "username_field": "user",
        "password_field": "pass",
        "username": "alice",
        "password": "s3cret",
    }
    plan, _ = _load_plan(tmp_path, auth=auth)
    context = plan["env"]["contexts"][0]
    assert context["authentication"]["method"] == "form"
    assert context["authentication"]["parameters"]["loginUrl"] == "http://example.com/login"
    assert "user={%username%}" in context["authentication"]["parameters"]["loginRequestData"]
    assert "pass={%password%}" in context["authentication"]["parameters"]["loginRequestData"]
    assert context["users"][0]["name"] == AUTH_USER
    assert context["users"][0]["credentials"] == {"username": "alice", "password": "s3cret"}

    active = [j for j in plan["jobs"] if j["type"] == "activeScan"][0]
    assert active["parameters"]["user"] == AUTH_USER
    spider = [j for j in plan["jobs"] if j["type"] == "spider"][0]
    assert spider["parameters"]["user"] == AUTH_USER


def test_build_plan_header_auth(tmp_path):
    auth = {"method": "header", "header_name": "X-Api-Key", "header_value": "abc123"}
    plan, _ = _load_plan(tmp_path, auth=auth)
    context = plan["env"]["contexts"][0]
    assert context["authentication"]["method"] == "httpHeader"
    assert context["authentication"]["parameters"]["headerName"] == "X-Api-Key"
    assert context["authentication"]["parameters"]["headerValue"] == "abc123"
    assert "users" not in context
    # Header auth needs no per-user job config.
    active = [j for j in plan["jobs"] if j["type"] == "activeScan"][0]
    assert "user" not in active["parameters"]


def test_build_plan_ajax_spider_job(tmp_path):
    plan, _ = _load_plan(tmp_path, ajax_spider=True)
    assert any(j["type"] == "spiderAjax" for j in plan["jobs"])
    order = [j["type"] for j in plan["jobs"]]
    assert order.index("spider") < order.index("spiderAjax") < order.index("passiveScan-wait")


def test_plan_file_is_valid_yaml_and_nonempty(tmp_path):
    _, out = _load_plan(tmp_path)
    with open(out, "r", encoding="utf-8") as f:
        content = f.read()
    assert content.strip()
    assert "activeScan" in content
    assert "failOnError" in content