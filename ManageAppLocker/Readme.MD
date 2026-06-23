# AppLocker Policy Builder for Intune

## Author : Lee Burridge
## Date : 23/06/2026

A Windows PowerShell 5.1 GUI tool for **scanning application files and generating granular AppLocker XML policies**, designed for **Microsoft Intune deployment**.

This tool gives you **full control over rule creation** (Publisher, Path, or Hash), avoids AppLocker cmdlet deduplication, and includes **safe merge functionality** with detailed clash reporting.

---

## 🚀 Features

- ✅ Scan folders for AppLocker-relevant files (`.exe`, `.dll`, `.ps1`, `.msi`, etc.)
- ✅ Interactive GUI with per-file rule selection:
  - Publisher rules
  - Path rules
  - Hash rules
  - Ignore option
- ✅ Generates **clean AppLocker XML (no deduping via `New-AppLockerPolicy`)**
- ✅ Publisher rules include:
  - `PublisherName`
  - `ProductName`
  - `BinaryName`
  - Wildcard version range (`*`)
- ✅ Rule names prefixed with scan folder for consistency
- ✅ Export full AppLocker XML policy
- ✅ Copy individual RuleCollections directly to clipboard (Intune-ready)
- ✅ Merge generated XML with existing AppLocker policies
- ✅ Detailed clash reporting (ID, Name, Effective Condition)

---

## 🧰 Requirements

- Windows PowerShell **5.1 (Desktop edition)**
- Must run in **STA mode**
- Built-in **AppLocker module**
- Windows OS with AppLocker support

---

## ▶️ How to Run

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -STA -File .\AppLocker-Merge.ps1
```
The script will:
Validate PowerShell edition
Relaunch itself in STA mode if required

## 🖥️ How It Works
1. Select Folder
Choose a folder containing applications to scan.

2. Scan Files
The tool:
Detects AppLocker-supported file types
Extracts metadata (publisher, version, hash)

3. Choose Rule Type
Each file can be set to:
Publisher
Path
Hash
Ignore

4. Generate Policy
Creates AppLocker XML manually (no deduplication)
Saves policy to disk
Enables merge functionality

5. Copy RuleCollections
Quickly copy policy sections for Intune:
./Vendor/MSFT/AppLocker/ApplicationLaunchRestrictions/{Grouping}/EXE/Policy

Available collections:
EXE
MSI
Script
DLL

## 🔗 Rule Behaviour
Publisher Rules
Generated using:

``PublisherName``

``ProductName``

``BinaryName``

Version range:

``BinaryVersionRange LowSection="*" HighSection="*"``

➡️ Allows all versions of the same binary from that publisher/product.

Path Rules
Based on file path
Best suited for controlled directories

Hash Rules
SHA256 based
Exact file matching
Ideal for unsigned binaries

## 🔀 Merge Capability
Merge generated policy into an existing AppLocker XML.
Behaviour:

  - `✅ Adds only non-conflicting rules`
  - `❌ Skips rules with clashes:`
    - `Rule ID`
    - `Rule Name`
    - `Effective condition`

Output:
  - `Merged XML file`
  - `Optional clash report .txt`

Example:

``SKIPPED [Exe] MyRuleName - clash: Name, Effective condition``

## 📋 Supported File Types
  - Executable : .exe, .com, .msc
  - DLL : .dll, .ocx
  - Script : .ps1, .vbs, .js, .bat, .cmd
  - Installer : .msi, .msp, .mst

## ⚠️ Recommendations
- ✅ Prefer Publisher rules
- ✅ Use Hash rules for unsigned binaries
- ⚠️ Use Path rules with caution
- ✅ Review merge reports before deployment
- ✅ Deploy in Audit mode first

