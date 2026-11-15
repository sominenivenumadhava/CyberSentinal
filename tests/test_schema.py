"""
Unit tests for CyberSentinel schema normalization and categorization rules.
"""
from src.data.schema import (
    clean_column_name,
    normalize_label,
    get_attack_category,
    IDENTIFIER_COLUMNS,
    CANONICAL_FLOW_FEATURES,
)


def test_clean_column_name():
    assert clean_column_name(" Destination Port") == "destination_port"
    assert clean_column_name("Flow Bytes/s") == "flow_bytes_s"
    assert clean_column_name(" Total Fwd Packets ") == "total_fwd_packets"
    assert clean_column_name("Fwd Header Length.1") == "fwd_header_length_1"


def test_normalize_label():
    assert normalize_label("BENIGN") == "BENIGN"
    assert normalize_label("  DDoS  ") == "DDOS"
    assert normalize_label("Web Attack \x96 Brute Force") == "WEB ATTACK - BRUTE FORCE"


def test_get_attack_category():
    assert get_attack_category("BENIGN") == "BENIGN"
    assert get_attack_category("DDoS") == "DDoS"
    assert get_attack_category("PortScan") == "PortScan"
    assert get_attack_category("FTP-Patator") == "BruteForce"
    assert get_attack_category("DoS Hulk") == "DoS"
    assert get_attack_category("Web Attack – XSS") == "WebAttack"
    assert get_attack_category("Bot") == "Bot"
    assert get_attack_category("Infiltration") == "Infiltration"


def test_identifier_disjointness():
    """Ensure no identifier column accidentally overlaps with canonical flow features."""
    for col in IDENTIFIER_COLUMNS:
        assert col not in CANONICAL_FLOW_FEATURES

