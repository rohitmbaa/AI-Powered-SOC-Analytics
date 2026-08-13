# AI-Powered SOC Analytics & Incident Investigation Platform

A synthetic, defensive cybersecurity analytics project demonstrating:
- Python security-log processing
- SQL-based investigation
- Rule-based detection
- Alert/incident correlation
- Power BI SOC-style reporting
- GenAI-assisted incident investigation
- MITRE ATT&CK mapping
- AI-assisted detection-rule test generation

## Important
All data is synthetic. No production credentials, real customer data, or real security telemetry are used.

## Architecture
See `docs/architecture.md`.

## Seeded scenarios
1. Brute force + successful authentication + suspicious PowerShell
2. Impossible travel
3. Potential lateral movement
4. Abnormal outbound data transfer
5. Office-to-PowerShell process chain

## Tech stack
Python, pandas, SQL, Power BI, GenAI, MITRE ATT&CK.

## Defensive design
Detection and calculations are deterministic. GenAI is used for summarization,
hypothesis generation, structured recommendations and test-case generation.
