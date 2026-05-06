# Colonial Pipeline Incident Simulation

A high-fidelity incident simulation and response package based on the Colonial Pipeline ransomware attack. This simulation has been **fully operationalized** and integrated into the Central Governance Platform.

## Features & Current State
- **Synthetic Log Generation**: PowerShell script (`generate-ransomware-logs.ps1`) successfully simulates T1490 and T1486 behaviors, writing Splunk CIM telemetry directly to the Governance Platform's `live-siem-feed`.
- **Detection Engineering**: YARA (`yara-darkside-payload.yar`) and Sigma (`sigma-darkside-ransomware.yml`) rules have been synthesized and actively ingested into the central `wiki/automation/rules/` registry.
- **Incident Response & GRC Mapping**: The `ot-ransomware-response.md` playbook strictly maps containment activities to **DORA Article 19** and **NIST 800-53 IR-4**, ensuring rigorous regulatory compliance during active incidents.

## Execution
To generate a new simulation run:
1. Ensure the Governance Platform React Server is active.
2. Execute `Synthetic-Logs/generate-ransomware-logs.ps1`.
3. Monitor the `LIVE SIEM FEED` on the Governance Dashboard for DORA Critical Alerts and Containment Resolutions.
