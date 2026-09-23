# Hack The Box: Sherlock — Brutus Writeup

* **Category:** DFIR / Linux Log Analysis
* **Primary Artifacts:** `/var/log/auth.log`, `/var/log/wtmp`, `/var/log/btmp`

---

## 1. Scenario Overview
An externally accessible Linux server was subjected to repeated unauthorized access attempts. The objective is to identify the threat actor's network origin, the attack mechanism, the compromised user account, and any subsequent command execution or privilege escalation.

---

## 2. Investigation Steps

### Step 1: Identifying Attack Patterns in `auth.log`
Filtering `/var/log/auth.log` for authentication failures highlighted high-velocity SSH attempts:
```bash
grep "Failed password" auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr
```
* **Observation:** A single remote IP address generated thousands of authentication failures in a compressed time frame, confirming an automated SSH credential brute-force or dictionary attack.
* **Target Identification:** Extracting targeted usernames revealed attempts across standard administrative accounts (`root`, `admin`) as well as specific local service and user accounts.

### Step 2: Pinpointing Successful Ingress
To identify if and when the attacker breached the system, the log was filtered for transitions to successful authentication:
```bash
grep -E "Accepted (password|publickey)" auth.log
```
* **Compromised Account:** The log confirmed an `Accepted password` entry originating from the attacker's IP address against a specific local account.
* **Initial Access Timestamp:** Documented the exact UTC timestamp of the first successful login to bracket the start of the intrusion window.

### Step 3: Interactive Session Corroboration via `wtmp`
The successful authentication was cross-referenced with binary login accounting records in `/var/log/wtmp` using the `last` utility:
```bash
last -f wtmp -F -i
```
* **Findings:** Verified that the remote IP opened an active pseudoterminal (`pts/X`) session. Documenting the login and logout timestamps established the total duration of the threat actor's interactive access.

### Step 4: Post-Exploitation & Privilege Escalation Triage
Returning to `auth.log`, records were filtered for `sudo` invocations during the established session:
```bash
grep "sudo:" auth.log | grep "<CompromisedUser>"
```
* **Findings:** The logs captured commands executed under elevated privileges (`sudo COMMAND=...`), exposing commands used for local enumeration, persistence creation, and defense evasion.

---

## 3. Key Findings
* **Attack Vector:** Automated SSH password brute-force.
* **Initial Access Point:** Interactive password compromise on an unhardened user profile.
* **Artifact Footprint:** Authentication records in `auth.log` correlated directly with interactive terminal sessions logged in `wtmp`.
