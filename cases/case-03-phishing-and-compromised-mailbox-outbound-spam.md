# Case 03 — Inheritance Phishing & Compromised Mailbox Outbound Spam (Alert 1000)

- **Environment:** TryHackMe SOC Simulator
- **Alert Rule:** `Suspicious email from external domain.` (1000)
- **Severity:** Low (Escalated to High based on SIEM correlation)
- **Classification:** True Positive (Suspected Account Compromise)

---

## Executive Summary
An initial Low-severity phishing alert targeting `support@tryhatme.com` was escalated to a High-severity incident after SIEM correlation revealed unauthorized outbound spam campaigns originating from the internal mailbox minutes later. The account was isolated for credential reset, session revocation, and persistence auditing (inbox rules and OAuth grants).

## Time of Activity
November 24, 2026, between `00:48:39` and `01:14:16` (initial inbound phishing email received at `00:48:39`, followed by four unauthorized outbound scam emails sent between `00:52:58` and `01:14:16`).

## Affected Entities
- **Compromised Internal Account:** `support@tryhatme.com`
- **SIEM Collector Host:** `10.67.181.77`

## Investigation & Analysis
Alert 1000 was triggered by an inbound email from `eileen@trendymillineryco[.]me` to `support@tryhatme.com` at `00:48:39` (`Subject: "Inheritance Alert: Unknown Billionaire Relative Left You Their Hat Fortunes"`), requesting banking details.

- **Threat Intelligence:** Lookup via TryDetectThis returned no prior malicious flags for `trendymillineryco[.]me`, indicating a newly registered or unindexed domain requiring behavioral log analysis rather than passive reputation reliance.
- **SIEM Pivot & Correlation:** Pivoting on `support@tryhatme.com` in Splunk uncovered four subsequent **outbound** scam emails originating from the internal mailbox:
  - `00:52:58` — To `lucie@trendymillineryco[.]me` (`Subject: "Get Your Degree Online in Hat Design Not Accredited"`)
  - `01:08:00` — To `josephine@yahoo[.]com` (`Subject: "Scam Alert Fake Hat Hotel Vouchers Up for Grabs"`)
  - `01:13:30` — To `burns@hatindustryinsights[.]xyz` (`Subject: "Time Traveling Hat Adventure Explore Ancient Lands for Cheap"`)
  - `01:14:16` — To `tobias@fashionforwardhats[.]me` (`Subject: "Scam Alert Fake Hat Hotel Vouchers Up for Grabs"`)

### Splunk Queries (SPL) Used for Triage
```spl
# 1. Pivot on internal mailbox across both inbound and outbound traffic
datasource="email" (sender="support@tryhatme.com" OR recipient="support@tryhatme.com")
| table timestamp, direction, sender, recipient, subject

# 2. Quantify outbound email volume to detect anomalous sending bursts
datasource="email" sender="support@tryhatme.com" direction="outbound"
| stats count by recipient, subject
