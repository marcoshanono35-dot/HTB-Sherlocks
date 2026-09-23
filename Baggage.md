# Hack The Box: Sherlock — Baggage Writeup

* **Category:** DFIR / Windows Endpoint Artifacts
* **Primary Artifacts:** Windows Shellbags (`UsrClass.dat`), `NTUSER.DAT`

---

## 1. Scenario Overview
A Windows host was accessed interactively by an unauthorized user. The investigation centers on tracking the threat actor's folder browsing history to confirm which local and network directories were navigated during the incident.

---

## 2. Investigation Steps

### Step 1: Shellbag Artifact Acquisition
Windows Shellbags store user viewing preferences and folder hierarchies accessed through Windows Explorer. The target artifact was located in the per-user registry hive:
```text
C:\Users\<SuspectUser>\AppData\Local\Microsoft\Windows\UsrClass.dat
```
Related subkeys were extracted from:
* `Local Settings\Software\Microsoft\Windows\Shell\BagMRU`
* `Local Settings\Software\Microsoft\Windows\Shell\Bags`

### Step 2: Parsing Registry Structures
`UsrClass.dat` was parsed with a dedicated Shellbag parser (such as `SBECmd` or `ShellBags Explorer`) to convert raw binary registry blobs into human-readable directory paths and timestamps:
```bash
SBECmd.exe -f "C:\path\to\UsrClass.dat" --csv "C:\investigation\output"
```

### Step 3: Reconstruction of Directory Reconnaissance
Analyzing the generated timeline established:
1. **Directory Tree Traversal:** The parsed MRU (Most Recently Used) structure documented navigation through directories, sensitive network shares, and external volumes.
2. **Persistence of Deleted Paths:** Because Shellbags preserve structural records of directories even after those folders have been unmounted, moved, or deleted, paths that no longer existed on the raw filesystem were confirmed to have been accessed.
3. **Timestamp Correlation:** Shellbag node timestamps (Target Creation, Target Modification, and Access dates) were matched with the timeline of known unauthorized access to filter out routine user activity from malicious reconnaissance.

---

## 3. Key Findings
* **Artifact Significance:** Shellbags confirmed interactive directory reconnaissance in Windows Explorer.
* **Evidence of Access:** Reconstructed exact directory paths navigated by the threat actor, isolating folders that were inspected for staging or data staging prior to remediation.
