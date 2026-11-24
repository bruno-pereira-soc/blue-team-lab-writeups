# Case 03 — Inheritance Phishing & Compromised Mailbox Outbound Spam (Alert 1000)

- **Environment:** TryHackMe SOC Simulator
- **Alert Rule:** `Suspicious email from external domain.` (1000)
- **Severity:** Low (Escalated to High based on SIEM correlation)
- **Classification:** True Positive (Suspected Account Compromise)

---

## Time of Activity
November 24, 2026, between `00:48:39` and `01:14:16` (initial inbound phishing email received at `00:48:39`, followed by four unauthorized outbound spam emails sent between `00:52:58` and `01:14:16`).

## Affected Entities
- **Compromised Internal Account:** `support@tryhatme.com`
- **SIEM Collector Host:** `10.67.181.77`

## Investigation & Analysis
Alert 1000 was triggered by an inbound email from `eileen@trendymillineryco[.]me` to `support@tryhatme.com` at `00:48:39` (`Subject: "Inheritance Alert: Unknown Billionaire Relative Left You Their Hat Fortunes"`), requesting banking details.

- **Threat Intelligence:** Lookup via TryDetectThis returned no prior malicious flags for `trendymillineryco[.]me`, indicating a newly observed or unindexed domain.
- **SIEM Pivot & Correlation:** Pivoting on `support@tryhatme.com` in Splunk uncovered four subsequent **outbound** spam/scam emails originating from the internal account:
  - `00:52:58` — To `lucie@trendymillineryco[.]me` (`Subject: "Get Your Degree Online in Hat Design Not Accredited"`)
  - `01:08:00` — To `josephine@yahoo[.]com` (`Subject: "Scam Alert Fake Hat Hotel Vouchers Up for Grabs"`)
  - `01:13:30` — To `burns@hatindustryinsights[.]xyz` (`Subject: "Time Traveling Hat Adventure Explore Ancient Lands for Cheap"`)
  - `01:14:16` — To `tobias@fashionforwardhats[.]me` (`Subject: "Scam Alert Fake Hat Hotel Vouchers Up for Grabs"`)

## Escalation Rationale
Escalated immediately to Tier 2 / Incident Response due to strong indicators of mailbox compromise (`support@tryhatme.com` actively sending unauthorized outbound scam campaigns). Requires authentication log review, session revocation, and mailbox rule auditing.

## MITRE ATT&CK Mapping
- **Tactic:** Initial Access (`TA0001`)
  - **Technique:** Phishing (`T1566`) / Valid Accounts (`T1078`) — Adversary initiated contact via an inheritance scam email and subsequently leveraged an internal mailbox (`support@tryhatme.com`) to distribute scam messages.
- **Tactic:** Impact (`TA0040`)
  - **Technique:** Resource Hijacking / Email Spam Distribution (`T1496`) — Abuse of corporate email infrastructure to send unauthorized outbound scam campaigns to external recipients.

## Recommended Remediation Actions
- Immediately reset credentials and revoke all active sessions/tokens for `support@tryhatme.com`.
- Audit sign-in logs, OAuth app permissions, and inbox forwarding/transport rules on `support@tryhatme.com` to identify the root cause of unauthorized access.
- Block the sender domain `trendymillineryco[.]me` at the email security gateway and purge the inbound phishing email.
- Place temporary outbound rate limits or quarantine holds on queued spam messages originating from `support@tryhatme.com`.

## Indicators of Compromise (IOCs)
- **Inbound Phishing Sender:** `eileen@trendymillineryco[.]me`
- **Malicious Domain:** `trendymillineryco[.]me`
- **External Spam Recipients (Observed in Outbound Abuse):**
  - `lucie@trendymillineryco[.]me`
  - `josephine@yahoo[.]com`
  - `burns@hatindustryinsights[.]xyz`
  - `tobias@fashionforwardhats[.]me`
