# Incident 08 - BYOD Cross-Device Hunt - Windows10 + Android

**Workspace:** sc200-law
**Date:** 2026-10-18 21:04 UTC
**User:** admin@sc200lablearning.onmicrosoft.com
**Evidence:** 
- Windows10 | 41.24.136.x | ZA | Azure Portal | 21:04:18
- Android | 41.24.136.x | ZA | Microsoft Account Controls V2 | 21:04:05
- 6x Android logins 20:57-21:04 UTC

**KQL:**
SigninLogs
| where TimeGenerated > ago(24h)
| where UserPrincipalName == "admin@sc200lablearning.onmicrosoft.com"
| extend DeviceOS = tostring(DeviceDetail.operatingSystem)
| extend IP = tostring(IPAddress)
| project TimeGenerated, DeviceOS, IP, Location, AppDisplayName
| order by TimeGenerated desc

**Finding:** Confirmed BYOD scenario - privileged account accessed from both managed Windows10 and unmanaged Android Chrome Mobile 155.0.0 from same ZA IP. DeviceDetail.isManaged=false. Validates Conditional Access gap previously found in Incident 04 (45 notApplied).

**MITRE:** T1078 Valid Accounts, T1078.004 Cloud Accounts
**CIS:** 6.5 Ensure BYOD conditional access, 4.1 Unmanaged device block
**Recommendation:** Require compliant device + block unmanaged Android for Global Admin role, enforce MFA + Intune compliance.

**SOC Value:** Demonstrates ability to hunt cross-device sign-ins and BYOD risk - critical for JHB banking SOCs handling remote workers.
