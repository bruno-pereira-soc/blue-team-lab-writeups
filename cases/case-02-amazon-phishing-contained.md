# Case 02 — Amazon Brand Impersonation Phishing & Firewall Block (Alerts 8815 & 8816)

* **Environment:** TryHackMe SOC Simulator
* **Alert Rules:** `Inbound Email Containing Suspicious External Link` (8815) & `Access to Blacklisted External URL Blocked by Firewall` (8816)
* **Severity:** Medium / High
* **Classification:** True Positive (Contained by Firewall)

---

## Time of Activity
November 22, 2026, between `20:51:04` and `20:52:18` (inbound phishing email received at `20:51:04` and outbound connection blocked by the firewall at `20:52:18`).

## Affected Entities
* **User:** Hannah Harris (`h.harris@thetrydaily.thm`)
* **Internal Host / Source IP:** `10.20.2.17`

## Investigation & Analysis
Alerts 8815 and 8816 were triggered by an inbound phishing email from `urgents@amazon[.]biz` to `h.harris@thetrydaily.thm` containing a suspicious shortened link (`8815`), followed by an outbound web-browsing connection attempt from `10.20.2.17` to `67.199.248[.]11` on port `80` (`8816`).

* **Threat Intelligence:** Lookup via TryDetectThis showed that while the `amazon[.]biz` domain returned clean (acting as brand impersonation), both the shortened URL (`hxxp://bit[.]ly/3sHkX3da12340`) and the destination IP (`67.199.248[.]11`) were flagged as malicious.
* **SIEM & Firewall Correlation:** Logs confirmed that Hannah Harris clicked the phishing link, which was mitigated by the firewall under the `"Blocked Websites"` rule (`Action: blocked`). No other internal hosts communicated with the malicious IP.

## Escalation Rationale
Escalated to Tier 2 / Email Security team to verify whether other internal users received the same campaign from `urgents@amazon[.]biz`, execute an organization-wide email purge, and enforce permanent domain/sender blocks at the email gateway level.

## Recommended Remediation Actions
* Purge the phishing email (`"Your Amazon Package Couldn't Be Delivered – Action Required"`) from Hannah Harris's mailbox/trash and any other affected inboxes.
* Block the sender address (`urgents@amazon[.]biz`) and spoofed domain (`amazon[.]biz`) on the email security gateway.
* Ensure the malicious URL (`hxxp://bit[.]ly/3sHkX3da12340`) and destination IP (`67.199.248[.]11`) remain blocked on the firewall and web proxy.
* Conduct targeted Phishing Awareness Training for the user to reinforce safe email handling practices.

## Indicators of Compromise (IOCs)
* **Sender Email:** `urgents@amazon[.]biz`
* **Spoofed Domain:** `amazon[.]biz`
* **Malicious URL:** `hxxp://bit[.]ly/3sHkX3da12340`
* **Destination IP:** `67.199.248[.]11` (TCP/80)
