"""
Tests for modules/severity_mapper.py
"""
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from modules.severity_mapper import normalize

SAMPLE_MAP = {
    "nuclei": {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
    },
    "zap": {
        3: "Critical",
        2: "High",
        1: "Medium",
        0: "Low",
    },
}


def test_normalize_string_severity():
    assert normalize("nuclei", "critical", SAMPLE_MAP) == "Critical"
    assert normalize("nuclei", "HIGH", SAMPLE_MAP) == "High"  # case-insensitive


def test_normalize_integer_severity():
    assert normalize("zap", 3, SAMPLE_MAP) == "Critical"
    assert normalize("zap", 0, SAMPLE_MAP) == "Low"


def test_normalize_unknown_tool_defaults_to_info():
    assert normalize("some_new_tool", "critical", SAMPLE_MAP) == "Info"


def test_normalize_unknown_severity_value_defaults_to_info():
    assert normalize("nuclei", "apocalyptic", SAMPLE_MAP) == "Info"


def test_normalize_empty_severity_map():
    assert normalize("nuclei", "critical", {}) == "Info"
