# kql-hunting-lab
Microsoft Sentinel KQL Hunting Lab — SC200 Preparation

## Purpose
This repo documents my KQL hunting queries for Microsoft Sentinel, focusing on real-world attack detection mapped to MITRE ATT&CK. All queries tested in live sc200-law workspace with real baseline.

## TFESP Method (How I read KQL)
**T**able → **F**ilter → **E**xtend → **S**ummarize → **P**roject

## Lab Provenance
- **Workspace:** sc200-law
- **Tenant:** Trial tenant (SC200 Lab)
- **Focus:** Live KQL queries with screenshots for SOC Analyst preparation

---

## Latest Hunts - Oct 2026 (Live Lab sc200-law)

### Hunt 04 - PIM Elevation - CRITICAL FINDING
- **Query:** `queries/hunt-04-pim-elevation.kql` - `Add member to role` returned 0 results
- **RCA:** Entra Admin Center > My Roles > Global Admin = Permanent (not Eligible)
- **Evidence:** `incidents/incident-04-pim-permanent-admin.md`
- **Impact:** Violates JIT, CIS 5.4, NIST PR.AC-4 - Permanent assignment = persistence risk

### Hunt 06 - Conditional Access Gap - CRITICAL FINDING
- **Query:** `SigninLogs | summarize by ConditionalAccessStatus = notApplied 45`
- **Evidence:** `incidents/incident-06-conditional-access-failure.md` + `incident-06-conditional-access-rca.md`
- **Impact:** 45 sign-ins with no CA policy evaluated - CIS 6.5, Zero Trust gap

### Hunt 08 - BYOD Cross-Device ✅
Windows10 + Android | sc200-law

### Hunt 09 - Threat Intel ✅
Vodacom Mobile IP 0% Abuse | CGNAT explained

---

## Hunt 10 - Fix: Add Member to Group Failure -> Success

### Problem
AuditLogs showed `Result: failure` for `Add member to group` at 17:15. Only 8 logs.

### Root Cause
Used Microsoft 365 group type. Free trial blocks member adds — need Security + Assigned.

### Fix
Created Security group `Demo-Security-Group` with Assigned membership. New log at 18:57 shows `Result: success`.

### KQL Learning
- `TargetResources[0]` = first box (Group)
- `TargetResources[1]` = second box (Member/User)
- `tostring()` unwraps JSON to readable text
- Member = User in this lab

### MITRE ATT&CK
- **TA0003 Persistence** - User added to group for continued access
- **T1098 Account Manipulation** - Group membership change

### Queries
See: `queries/Hunt10-AddMemberToGroup-Fix.kql`

```kql
// Query 1 - Basic AuditLogs
AuditLogs
| where TimeGenerated > ago(7d)
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| extend Target = tostring(TargetResources[0].displayName)
| project TimeGenerated, OperationName, Actor, Target, Result
| sort by TimeGenerated desc

// Query 2 - Fixed Group Query
AuditLogs
| where TimeGenerated > ago(30m)
| where OperationName == "Add member to group"
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| extend GroupName = tostring(TargetResources[0].displayName)
| extend Member = tostring(TargetResources[1].displayName)
| project TimeGenerated, OperationName, Actor, GroupName, Member, Result
| sort by TimeGenerated desc

// Query 3 - MITRE Mapping
AuditLogs
| where TimeGenerated > ago(30m)
| where OperationName == "Add member to group"
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| extend GroupName = tostring(TargetResources[0].displayName)
| extend Member = tostring(TargetResources[1].displayName)
| extend MITRE_Tactic = "TA0003 - Persistence"
| extend MITRE_Technique = "T1098 - Account Manipulation"
| project TimeGenerated, OperationName, Actor, GroupName, Member, Result, MITRE_Tactic, MITRE_Technique
```

### Screenshots

**Before — Failure (Microsoft 365 Group):**
[Failure](./images/Hunt10-FAILURE-M365Group.png)

**After — Success + MITRE (Security Group):**
[Success](./images/Hunt10-SUCCESS-SecurityGroup-MITRE.png)

---

## Repo Structure
```
kql-hunting-lab/
├── images/
│   ├── Hunt10-FAILURE-M365Group.png
│   └── Hunt10-SUCCESS-SecurityGroup-MITRE.png
├── queries/
│   ├── hunt-04-pim-elevation.kql
│   ├── Hunt10-AddMemberToGroup-Fix.kql
├── incidents/
└── README.md
```

### Analytics - Production Rules

**Folder:** `analytics/`  
**Rules Enabled:** 4  
- SOC-Hunt10 - Persistence - Member Added to Group (TA0003, T1098) - Enabled ✅
- HUNT - Non-Interactive Logins - Enabled ✅
- Brute Force - 5 failed logins - Enabled ✅
- Impossible Travel - Enabled ✅

**Screenshots:** `analytics/Hunt10-Active-Rules.png`

This proves I can turn KQL hunting into production SOC detections.
