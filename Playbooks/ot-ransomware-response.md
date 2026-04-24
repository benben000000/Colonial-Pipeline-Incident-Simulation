---
category: Playbook
severity: Critical
tlp: RED
mitre_id: T1486
actor: DarkSide
compliance_refs: CIS v8: 17.1 | NIST 800-53: CP-2 | DORA: Article 19
last_updated: 2026-04-24
---

# OT/ICS Ransomware Response Playbook (Colonial Pipeline Scenario)

## Overview
This playbook governs the response to a ransomware infection that threatens or has crossed into the Operational Technology (OT) environment.

## 1. Immediate Containment (T3 Emergency)
- **Sever IT/OT Bridge**: If the infection originates in IT (as with Colonial Pipeline), immediately sever the network bridge connecting the corporate LAN to the SCADA/ICS network.
- **Preserve Evidence**: Do not reboot infected machines. Memory forensics (volatility) is required to extract decryption keys if the payload is poorly constructed.

## 2. Regulatory Collision Check (DORA 4-Hour Rule)
> [!WARNING]
> If you fall under DORA, a major ICT-related incident affecting critical functions MUST be reported to the competent authority within 4 hours of classification.
> *Are our critical energy delivery systems impaired?* Yes. Trigger legal notification workflows immediately.

## 3. The Inquisitor's Veto
> [!IMPORTANT]
> *Is paying the ransom the BEST outcome, or merely the most obvious one?*
> Colonial Pipeline paid $4.4M. The decryption tool provided by DarkSide was so slow that they still had to rely on their own backups to restore operations. 
> **Refined Action**: Prioritize localized backup restoration over waiting for threat actor tooling. Isolate the restored subnet before bringing it online to prevent re-infection via persistent access (e.g., compromised VPN credentials).

## 4. Remediation & Hardening
- Mandate MFA on all external entry points (VPNs).
- Implement strict network segmentation between IT and OT (Purdue Model Level 3.5 DMZ).
