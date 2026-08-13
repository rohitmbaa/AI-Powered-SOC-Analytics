# Power BI SOC Dashboard Plan

## Page 1 — SOC Overview
Cards:
- Total Events
- Total Alerts
- Critical Alerts
- High Alerts
- Open Incidents
- Investigating Incidents

Visuals:
- Alerts by day
- Alerts by severity
- Alerts by detection rule
- Alerts by source
- Open incidents by severity

## Page 2 — Threat Detection
- Detection rule ranking
- Severity distribution
- Source IP table
- User/host table
- Alert timeline

## Page 3 — Incident Investigation
Use incident_id as the drill-through/filter key.
Display:
- Incident title
- Severity
- User
- Host
- Source IP
- First seen
- Status
- Event timeline
- AI summary
- Potential ATT&CK techniques
- Recommended investigation

## Page 4 — Detection QA
- Test ID
- Scenario
- Expected result
- Actual result
- PASS/FAIL
- Detection rule
