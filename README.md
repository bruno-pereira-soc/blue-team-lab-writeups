# Blue Team Lab Writeups & SOC Case Reports

Repository documenting hands-on Tier 1 SOC alert triage, SIEM log correlation, threat intelligence analysis, and structured incident reporting from Blue Team labs (TryHackMe SOC Simulator).

## Tools & Methodology
* **SIEM & Log Analysis:** Event correlation, 5-Tuple network inspection, email header/body review, internal directory verification.
* **Threat Intelligence:** IOC reputation checks (domains, URLs, IPs).
* **Reporting Framework:** Structured T-E-C-V (Trigger, Evidence, Context/Impact, Verdict) and playbook-driven escalation.

## Case Index

| Case ID | Alert Rule(s) | Classification | Summary |
| :--- | :--- | :--- | :--- |
| [Case 01](cases/case-01-hrconnex-false-positive.md) | Inbound Email Containing Suspicious External Link (`8814`) | **False Positive** | Legitimate third-party HR onboarding email verified via internal HR-to-IT correspondence. |
| [Case 02](cases/case-02-amazon-phishing-contained.md) | Inbound Phishing Email (`8815`) & Blacklisted URL Blocked (`8816`) | **True Positive (Contained)** | Brand impersonation (`amazon[.]biz`) with malicious shortened link; user clicked, outbound connection blocked by firewall. |
