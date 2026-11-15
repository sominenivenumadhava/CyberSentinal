"""
Data Schemas, Feature Definitions, and Identifier Exclusion Rules for CICIDS2017.
Enforces strict separation of identifiers, timestamps, and network telemetry features
to prevent shortcut learning and ensure model generalization across network topologies.
"""
from typing import List, Dict, Set

# Non-feature columns: Identifiers, IP addresses, ports, and timestamps.
# MUST BE PRESERVED FOR TRIAGE AND AUDIT, BUT STRICTLY EXCLUDED FROM MODEL INPUTS.
IDENTIFIER_COLUMNS: Set[str] = {
    "flow_id",
    "source_ip",
    "src_ip",
    "destination_ip",
    "dst_ip",
    "source_port",
    "src_port",
    "destination_port",
    "dst_port",
    "timestamp",
    "flow_bytes/s_raw",
}

# Duplicate or malformed columns frequently appearing in CICIDS2017 CSV exports
DUPLICATE_COLUMNS_TO_DROP: List[str] = [
    "fwd_header_length.1",
    "fwd_header_length_1",
]

# High-level attack categorization for multi-class classification and threat intelligence
ATTACK_CATEGORY_MAPPING: Dict[str, str] = {
    "BENIGN": "BENIGN",
    "FTP-PATATOR": "BruteForce",
    "SSH-PATATOR": "BruteForce",
    "DOS SLOWLORIS": "DoS",
    "DOS SLOWHTTPTEST": "DoS",
    "DOS HULK": "DoS",
    "DOS GOLDENEYE": "DoS",
    "HEARTBLEED": "DoS",
    "WEB ATTACK \x96 BRUTE FORCE": "WebAttack",
    "WEB ATTACK - BRUTE FORCE": "WebAttack",
    "WEB ATTACK \x96 XSS": "WebAttack",
    "WEB ATTACK - XSS": "WebAttack",
    "WEB ATTACK \x96 SQL INJECTION": "WebAttack",
    "WEB ATTACK - SQL INJECTION": "WebAttack",
    "INFILTRATION": "Infiltration",
    "BOT": "Bot",
    "PORTSCAN": "PortScan",
    "DDOS": "DDoS",
}

# Canonical list of 68 network flow features extracted by CICFlowMeter
CANONICAL_FLOW_FEATURES: List[str] = [
    "flow_duration",
    "total_fwd_packets",
    "total_backward_packets",
    "total_length_of_fwd_packets",
    "total_length_of_bwd_packets",
    "fwd_packet_length_max",
    "fwd_packet_length_min",
    "fwd_packet_length_mean",
    "fwd_packet_length_std",
    "bwd_packet_length_max",
    "bwd_packet_length_min",
    "bwd_packet_length_mean",
    "bwd_packet_length_std",
    "flow_bytes_s",
    "flow_packets_s",
    "flow_iat_mean",
    "flow_iat_std",
    "flow_iat_max",
    "flow_iat_min",
    "fwd_iat_total",
    "fwd_iat_mean",
    "fwd_iat_std",
    "fwd_iat_max",
    "fwd_iat_min",
    "bwd_iat_total",
    "bwd_iat_mean",
    "bwd_iat_std",
    "bwd_iat_max",
    "bwd_iat_min",
    "fwd_psh_flags",
    "bwd_psh_flags",
    "fwd_urg_flags",
    "bwd_urg_flags",
    "fwd_header_length",
    "bwd_header_length",
    "fwd_packets_s",
    "bwd_packets_s",
    "min_packet_length",
    "max_packet_length",
    "packet_length_mean",
    "packet_length_std",
    "packet_length_variance",
    "fin_flag_count",
    "syn_flag_count",
    "rst_flag_count",
    "psh_flag_count",
    "ack_flag_count",
    "urg_flag_count",
    "cwe_flag_count",
    "ece_flag_count",
    "down_up_ratio",
    "average_packet_size",
    "avg_fwd_segment_size",
    "avg_bwd_segment_size",
    "fwd_avg_bytes_bulk",
    "fwd_avg_packets_bulk",
    "fwd_avg_bulk_rate",
    "bwd_avg_bytes_bulk",
    "bwd_avg_packets_bulk",
    "bwd_avg_bulk_rate",
    "subflow_fwd_packets",
    "subflow_fwd_bytes",
    "subflow_bwd_packets",
    "subflow_bwd_bytes",
    "init_win_bytes_forward",
    "init_win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
    "active_mean",
    "active_std",
    "active_max",
    "active_min",
    "idle_mean",
    "idle_std",
    "idle_max",
    "idle_min",
]


def clean_column_name(col: str) -> str:
    """
    Standardize raw column name by stripping whitespace, converting to lowercase,
    and replacing special characters with underscores.
    """
    cleaned = col.strip().lower()
    cleaned = cleaned.replace(" / ", "_").replace("/", "_").replace(" ", "_")
    cleaned = cleaned.replace("-", "_").replace(".", "_")
    # Clean up double underscores
    while "__" in cleaned:
        cleaned = cleaned.replace("__", "_")
    return cleaned


def normalize_label(label: str) -> str:
    """Normalize attack label string."""
    if not isinstance(label, str):
        return "UNKNOWN"
    norm = label.strip().upper()
    # Normalize common encoding artifacts (e.g. Windows-1252 non-ascii hyphens)
    norm = norm.replace("\x96", "-").replace("–", "-").replace("—", "-")
    return norm


def get_attack_category(label: str) -> str:
    """Map raw label to standardized attack category."""
    norm = normalize_label(label)
    for key, cat in ATTACK_CATEGORY_MAPPING.items():
        if key in norm or norm in key:
            return cat
    if "BENIGN" in norm:
        return "BENIGN"
    return "OtherAttack"
