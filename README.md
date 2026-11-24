# Blue Team Lab Writeups & SOC Case Reports

Repository documenting hands-on Tier 1 SOC alert triage, SIEM log correlation, threat intelligence analysis, and structured incident reporting from Blue Team labs (TryHackMe SOC Simulator).

## Tools & Methodology
* **SIEM & Log Analysis:** Event correlation, 5-Tuple network inspection, email header/body review, internal directory verification.
* **Threat Intelligence:** IOC reputation checks (domains, URLs, IPs).
* **Reporting Framework:** Structured T-E-C-V (Trigger, Evidence, Context/Impact, Verdict) and playbook-driven escalation.

## Case Index

| Case | Scenario | Severity | Verdict | Key Artifacts / Tools |
| :--- | :--- | :---: | :---: | :--- |
| [Case 01](./cases/case-01-false-positive-onboarding-email.md) | HR Partner Onboarding Email | Low | False Positive | Splunk, Email Header & Domain Verification |
| [Case 02](./cases/case-02-amazon-phishing-contained.md) | Amazon Brand Impersonation Phishing | Medium / High | True Positive (Contained) | Splunk, TryDetectThis, Firewall Logs, MITRE ATT&CK |
| [Case 03](./cases/case-03-phishing-and-compromised-mailbox-outbound-spam.md) | Inheritance Phishing & Compromised Mailbox Outbound Spam | Low $\rightarrow$ High | True Positive (Escalated) | Splunk Inbound/Outbound Pivot, MITRE ATT&CK |
| [Case 04](./cases/case-04-dns-tunneling-data-exfiltration.md) | PowerShell Data Exfiltration via DNS Tunneling | High | True Positive (Escalated) | Sysmon (Event ID 1), PowerShell Logs, DNS Tunneling, MITRE ATT&CK |
