import pandas as pd
from pathlib import Path

# ---------------------------------------------------------
# AI-Powered SOC Analytics
# Incident Triage & MITRE ATT&CK Enrichment
# ---------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent
INPUT_FILE = BASE_DIR / "data" / "processed" / "incidents.csv"
OUTPUT_FILE = BASE_DIR / "data" / "processed" / "triaged_incidents.csv"


def classify_incident(row):
    """
    Apply deterministic SOC triage logic.
    GenAI should be used later for investigation assistance,
    not for changing deterministic severity/risk calculations.
    """

    title = str(row["title"]).lower()
    severity = str(row["severity"]).lower()

    # Defaults
    techniques = []
    rationale = []
    risk_score = 50
    confidence = "Medium"
    priority = "P2"

    # -----------------------------------------------------
    # INC-00421 / Brute Force + PowerShell + Exfiltration
    # -----------------------------------------------------
    if "brute force" in title and "powershell" in title:
        techniques = [
            "T1110 - Brute Force",
            "T1059.001 - PowerShell",
            "Potential exfiltration behavior"
        ]
        risk_score = 95
        confidence = "High"
        priority = "P1"
        rationale = (
            "Multiple authentication failures were followed by successful "
            "authentication, suspicious PowerShell execution and abnormal "
            "outbound transfer activity."
        )

    # -----------------------------------------------------
    # Impossible Travel
    # -----------------------------------------------------
    elif "impossible travel" in title:
        techniques = [
            "T1078 - Valid Accounts"
        ]
        risk_score = 72
        confidence = "Medium"
        priority = "P2"
        rationale = (
            "Successful authentication events associated with geographically "
            "inconsistent locations within a short time window require "
            "validation of account legitimacy."
        )

    # -----------------------------------------------------
    # Lateral Movement
    # -----------------------------------------------------
    elif "lateral movement" in title:
        techniques = [
            "T1021.002 - SMB/Windows Admin Shares",
            "Potential lateral movement"
        ]
        risk_score = 82
        confidence = "Medium"
        priority = "P1"
        rationale = (
            "A single internal source communicated with multiple internal "
            "systems over SMB, which can indicate lateral movement."
        )

    # -----------------------------------------------------
    # Abnormal outbound transfer
    # -----------------------------------------------------
    elif "outbound data transfer" in title:
        techniques = [
            "Potential T1041 - Exfiltration Over C2 Channel"
        ]
        risk_score = 80
        confidence = "Medium"
        priority = "P1"
        rationale = (
            "Outbound data volume materially exceeds the normal profile "
            "assumed for the simulated environment and requires destination "
            "and file-level investigation."
        )

    # -----------------------------------------------------
    # Office -> CMD -> PowerShell
    # -----------------------------------------------------
    elif "office-topowershell" in title or "office-to-powershell" in title:
        techniques = [
            "T1059.001 - PowerShell",
            "T1204.002 - Malicious File"
        ]
        risk_score = 92
        confidence = "High"
        priority = "P1"
        rationale = (
            "A document application spawned command execution followed by "
            "PowerShell with an encoded command, representing a high-risk "
            "endpoint execution chain."
        )

    # -----------------------------------------------------
    # Generic critical/high fallback
    # -----------------------------------------------------
    elif severity == "critical":
        risk_score = 85
        confidence = "Medium"
        priority = "P1"
        rationale = "Critical severity requires immediate analyst investigation."

    elif severity == "high":
        risk_score = 70
        confidence = "Medium"
        priority = "P2"
        rationale = "High-severity activity requires analyst investigation."

    return pd.Series({
        "mitre_techniques": "; ".join(techniques),
        "risk_score": risk_score,
        "confidence": confidence,
        "priority": priority,
        "analyst_rationale": rationale
    })


def main():
    # Validate input
    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            f"Input file not found: {INPUT_FILE}"
        )

    incidents = pd.read_csv(INPUT_FILE)

    required_columns = [
        "incident_id",
        "title",
        "severity",
        "user",
        "host",
        "source_ip",
        "first_seen",
        "status"
    ]

    missing = [c for c in required_columns if c not in incidents.columns]

    if missing:
        raise ValueError(
            f"Missing required columns: {missing}"
        )

    # Apply deterministic triage
    enrichment = incidents.apply(classify_incident, axis=1)

    triaged = pd.concat(
        [incidents, enrichment],
        axis=1
    )

    # Recommended investigation steps
    triaged["recommended_investigation"] = triaged.apply(
        lambda row: (
            "Validate authentication; investigate source IP; review "
            "PowerShell command line; investigate outbound destination; "
            "search for related events across the environment."
            if row["incident_id"] == "INC-00421"
            else
            "Validate account activity, authentication location and device."
            if row["incident_id"] == "INC-00422"
            else
            "Review SMB connections, source host activity and contacted "
            "systems for lateral movement indicators."
            if row["incident_id"] == "INC-00423"
            else
            "Investigate destination, transferred data and user/device "
            "baseline before determining whether exfiltration occurred."
            if row["incident_id"] == "INC-00424"
            else
            "Review document origin, child-process chain, PowerShell command "
            "line and endpoint activity."
            if row["incident_id"] == "INC-00425"
            else
            "Perform standard SOC investigation and evidence validation."
        ),
        axis=1
    )

    # Save output
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    triaged.to_csv(OUTPUT_FILE, index=False)

    print("=" * 60)
    print("SOC INCIDENT TRIAGE COMPLETE")
    print("=" * 60)
    print(f"Input incidents : {len(incidents)}")
    print(f"Output file     : {OUTPUT_FILE}")
    print()

    print("Priority distribution:")
    print(triaged["priority"].value_counts())

    print()
    print("Risk scores:")
    for _, row in triaged.iterrows():
        print(
            f"{row['incident_id']} | "
            f"{row['severity'].upper()} | "
            f"Risk {row['risk_score']}/100 | "
            f"{row['priority']}"
        )


if __name__ == "__main__":
    main()