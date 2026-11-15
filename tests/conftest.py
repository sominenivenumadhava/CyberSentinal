"""
Pytest configuration and shared test fixtures for CyberSentinel.
"""
import pytest
import numpy as np
import pandas as pd
from typing import Dict, Any


@pytest.fixture
def sample_raw_flow_data() -> pd.DataFrame:
    """
    Generate synthetic raw CICIDS2017 network flow records with edge cases:
    - Leading/trailing whitespace in column names
    - IP addresses and timestamps (identifiers)
    - Infinite values (inf, -inf) in Flow Bytes/s
    - NaN missing values
    - Duplicate rows
    - Zero-variance (constant) features
    - Diverse attack labels and benign labels
    """
    n_rows = 100
    data = {
        # Identifiers (MUST BE SEPARATED)
        " Flow ID": [f"192.168.10.{i}-10.0.0.1-80-TCP" for i in range(n_rows)],
        " Source IP": [f"192.168.10.{i % 10}" for i in range(n_rows)],
        " Source Port": [1024 + i for i in range(n_rows)],
        " Destination IP": ["10.0.0.1" for _ in range(n_rows)],
        " Destination Port": [80 if i % 2 == 0 else 443 for i in range(n_rows)],
        " Timestamp": ["07/07/2017 8:30" for _ in range(n_rows)],
        
        # Invariant Network Flow Behavioral Features
        " Flow Duration": np.random.randint(100, 100000, size=n_rows),
        " Total Fwd Packets": np.random.randint(1, 50, size=n_rows),
        " Total Backward Packets": np.random.randint(0, 50, size=n_rows),
        "Total Length of Fwd Packets": np.random.randint(40, 5000, size=n_rows),
        " Total Length of Bwd Packets": np.random.randint(0, 5000, size=n_rows),
        "Fwd Packet Length Max": np.random.randint(40, 1500, size=n_rows),
        " Fwd Packet Length Min": np.random.randint(0, 40, size=n_rows),
        " Fwd Packet Length Mean": np.random.uniform(40.0, 500.0, size=n_rows),
        " Fwd Packet Length Std": np.random.uniform(0.0, 100.0, size=n_rows),
        "Bwd Packet Length Max": np.random.randint(0, 1500, size=n_rows),
        " Bwd Packet Length Min": np.random.randint(0, 40, size=n_rows),
        " Bwd Packet Length Mean": np.random.uniform(0.0, 500.0, size=n_rows),
        " Bwd Packet Length Std": np.random.uniform(0.0, 100.0, size=n_rows),
        
        # Edge cases: Inf and -Inf in Flow Bytes/s
        "Flow Bytes/s": np.random.uniform(10.0, 10000.0, size=n_rows),
        " Flow Packets/s": np.random.uniform(1.0, 500.0, size=n_rows),
        
        # Inter-arrival times
        " Flow IAT Mean": np.random.uniform(10.0, 1000.0, size=n_rows),
        " Flow IAT Std": np.random.uniform(0.0, 500.0, size=n_rows),
        " Flow IAT Max": np.random.uniform(100.0, 5000.0, size=n_rows),
        " Flow IAT Min": np.random.uniform(0.0, 10.0, size=n_rows),
        
        # TCP Flags
        "Fwd PSH Flags": np.random.choice([0, 1], size=n_rows),
        " Bwd PSH Flags": [0 for _ in range(n_rows)],  # Constant / zero-variance
        " Fwd URG Flags": [0 for _ in range(n_rows)],  # Constant / zero-variance
        " Bwd URG Flags": [0 for _ in range(n_rows)],  # Constant / zero-variance
        "FIN Flag Count": np.random.choice([0, 1], size=n_rows),
        " SYN Flag Count": np.random.choice([0, 1], size=n_rows),
        " RST Flag Count": np.random.choice([0, 1], size=n_rows),
        " PSH Flag Count": np.random.choice([0, 1], size=n_rows),
        " ACK Flag Count": np.random.choice([0, 1], size=n_rows),
        
        # Duplicate column test
        "Fwd Header Length.1": np.random.randint(20, 100, size=n_rows),
        
        # Ground Truth Label
        " Label": ["BENIGN" if i < 60 else ("DDoS" if i < 80 else ("PortScan" if i < 95 else "Infiltration")) for i in range(n_rows)]
    }

    df = pd.DataFrame(data)

    # Inject edge case: Infinite values
    df.loc[5, "Flow Bytes/s"] = np.inf
    df.loc[6, "Flow Bytes/s"] = -np.inf
    df.loc[7, " Flow Packets/s"] = np.inf

    # Inject edge case: Missing values (NaN)
    df.loc[10, " Fwd Packet Length Mean"] = np.nan
    df.loc[12, " Flow IAT Mean"] = np.nan

    # Inject edge case: Duplicate row
    df.loc[15] = df.loc[14]

    return df
