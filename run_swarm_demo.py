"""
CyberSentinel Multi-Agent Swarm Demonstration Script.
Executes an end-to-end investigation run on real network flow telemetry,
demonstrating concurrent model execution, threat correlation, and risk synthesis.
"""
import os
import json
from pathlib import Path
import pandas as pd

# Configure cache
mpl_cache = Path("./.cache/matplotlib").resolve()
mpl_cache.mkdir(parents=True, exist_ok=True)
os.environ["MPLCONFIGDIR"] = str(mpl_cache)

from config.settings import settings
from config.logging_config import logger
from src.agents.coordinator import CentralCoordinator


def run_demo():
    print("=" * 75)
    print("      CYBERSENTINEL: AUTONOMOUS MULTI-AGENT SWARM DEMONSTRATION")
    print("=" * 75)

    # 1. Load sample network flow batch
    dev_sample_path = settings.DATA_SAMPLES_DIR / "dev_sample.csv"
    meta_path = settings.DATA_SAMPLES_DIR / "dev_sample_meta.csv"

    if not dev_sample_path.exists() or not meta_path.exists():
        logger.error("Development sample files not found. Run src.data.run_pipeline first.")
        return

    features_df = pd.read_csv(dev_sample_path)
    meta_df = pd.read_csv(meta_path)

    # Take a diverse slice of 50 flows (both benign and attacks)
    slice_df = features_df.head(50).copy()
    slice_meta = meta_df.head(50).copy()

    # Recombine identifiers and flow features for raw agent ingestion
    combined_raw = pd.concat([slice_meta, slice_df], axis=1)
    raw_records = combined_raw.to_dict(orient="records")

    print(f"\n[*] Loaded telemetry batch: {len(raw_records)} flows for autonomous investigation.")

    # 2. Instantiate Central Coordinator
    coordinator = CentralCoordinator()

    # 3. Execute Multi-Agent Investigation
    task_id = "DEMO-SWARM-2026"
    result = coordinator.run_investigation(
        telemetry_data=raw_records,
        task_id=task_id,
        save_to_db=True,
    )

    # 4. Print Executive Results
    risk_rep = result["risk_report"]
    trace = result["execution_trace"]

    print("\n" + "=" * 75)
    print(f"             INVESTIGATION RESULTS: {task_id}")
    print("=" * 75)
    print(f"Overall Risk Score:      {risk_rep['overall_risk_score']}/100")
    print(f"Threat Severity Level:   {risk_rep['severity']}")
    print(f"Total Flows Evaluated:   {risk_rep['total_flows_evaluated']}")
    print(f"Classified Attacks:      {risk_rep['malicious_flows_count']}")
    print(f"Reconstruction Anomalies:{risk_rep['anomalous_flows_count']}")
    print(f"Correlated Incidents:    {len(risk_rep['correlated_incidents'])}")
    print(f"\nConsensus Resolution:\n  {risk_rep['conflict_resolution']}")

    print("\n--- AGENT EXECUTION TRACE ---")
    for agent_role, tr in trace.items():
        print(f"  - {agent_role:<30}: Status={tr['status']:<18} Latency={tr['latency_ms']:.2f} ms")

    print("\n--- CORRELATED INCIDENTS ---")
    for idx, inc in enumerate(risk_rep["correlated_incidents"][:3], 1):
        print(f"  Incident #{idx}: [{inc['pattern_type']}]")
        print(f"    Source IP:    {inc['source_ip']}")
        print(f"    Target Assets:{inc['target_ips']}")
        print(f"    Target Ports: {inc['target_ports']}")
        print(f"    Evidence:     {inc['evidence_summary']}")

    print("\n--- RECOMMENDED RESPONSE PLAYBOOKS (NON-DISRUPTIVE) ---")
    for idx, act in enumerate(risk_rep["recommended_actions"][:4], 1):
        print(f"  Playbook #{idx} [{act['priority']}]: {act['action_type']}")
        print(f"    Target:      {act['target']}")
        print(f"    Action:      {act['description']}")
        print(f"    Human Gate:  Requires Approval = {act['requires_approval']}")

    print("\n" + "=" * 75)
    print("Executive Summary:")
    print(risk_rep["executive_summary"])
    print("=" * 75)


if __name__ == "__main__":
    run_demo()
