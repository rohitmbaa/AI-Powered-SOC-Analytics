# Architecture

Synthetic Security Logs
        |
        v
Python Data Generation / Cleaning
        |
        +------> SQL Analysis
        |
        v
Detection Rules
        |
        v
Alert Correlation / Incident Dataset
        |
        +------> Power BI SOC Dashboard
        |
        v
AI Investigation Layer
        |
        +------> Incident Summary
        +------> Potential MITRE ATT&CK Mapping
        +------> Investigation Recommendations
        |
        v
Human Analyst Decision

Design principle:
Deterministic code performs calculations and detection. GenAI assists with interpretation,
summarization and structured recommendations. The human analyst retains final decision authority.
