# Case 01 — Third-Party HR Onboarding Email (False Positive)

* **Environment:** TryHackMe SOC Simulator
* **Alert Rule:** `Inbound Email Containing Suspicious External Link`
* **Severity:** Medium
* **Classification:** False Positive

---

## Summary
An inbound email containing an external onboarding link triggered a phishing alert. Cross-referencing SIEM email logs with internal corporate communications confirmed the message was a legitimate onboarding workflow from an approved HR vendor.

## Investigation & Analysis
* **Threat Intelligence:** Domain and URL reputation checks via TryDetectThis returned clean with no malicious history or blacklist hits.
* **SIEM Log Correlation:** Reviewing historical internal email logs revealed prior correspondence between the internal HR department and IT confirming the onboarding of the third-party HR vendor (`hrconnex[.]thm`) and authorizing the onboarding link sent to the new hire.
* **Network & Endpoint Verification:** Firewall and proxy logs showed no suspicious outbound connections or post-click anomalies.

## Verdict & Closure Rationale
Classified as a **False Positive**. The external link and sender domain were verified as part of an authorized business onboarding process, requiring no containment or escalation.
