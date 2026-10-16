# KQL Hunting Lab - SC-200 Preparation

**Candidate:** SOC Analyst | SC-200 | Germiston, SA
**Workspace:** sc200-law

## Purpose
This repo documents my KQL hunting queries for Microsoft Sentinel, focusing on real-world attack detection mapped to MITRE ATT&CK.

## TFESP Method (How I read KQL)
Every query = T-F-E-S-P
- **T**able: Where to look
- **F**ilter: where / what to remove
- **E**xtend: New column, parse dynamic JSON with tostring()
- **S**ummarize: count(), dcount(), make_set(), bin(Time)
- **P**roject: Final output

## Queries Included

### 1. Pass-The-Hash Hunting - SecurityEvent (4624/4648)
- **ATT&CK:** T1550.002 Pass the Hash
- **Logic:** Detects NewCredentials logon (Type 9) followed by explicit credential use (4648) within 5 mins across multiple IPs.
- **Key KQL:** join kind=inner, dcount(IpAddr), tolower() !in~

### 2. Phishing with Malicious Attachment - EmailEvents + EmailAttachmentInfo + DeviceFileEvents
- **ATT&CK:** T1566.001 Phishing Attachment
- **Logic:** Inbound emails with dangerous filetypes (doc/xls/zip) where attachment SHA256 matches file created on endpoint.
- **Key KQL:** NetworkMessageId join, FileType in~, leftouter join on SHA256

### 3. Impossible Travel - SigninLogs
- **ATT&CK:** T1078 Valid Accounts - Compromised Credentials
- **Logic:** Same user successful login from 2+ countries within 10 minutes.
- **Key KQL:** ResultType == 0 (Success), LocationDetails dynamic JSON parsing, bin() + make_set() + array_length()

## Lab Environment
- Microsoft Sentinel: sc200-law
- Data Connectors: Defender for Endpoint, Entra ID, Office 365

## Next: Analytics Rules
These hunting queries will be converted to Scheduled Analytics Rules with MITRE mapping and automated incidents.
