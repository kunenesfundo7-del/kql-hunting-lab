# Incident 25 - HUNT - Non-Interactive Sign-In Anomaly - _100/hr

**Incident ID:** 25  
**Title:** HUNT - Non-Interactive Sign-In Anomaly - _100/hr  
**Severity:** Medium  
**Status:** Active  
**Source:** Microsoft Sentinel Analytic Rule  
**First Activity:** Oct 26, 2026 11:00 PM  
**Last Activity:** Oct 27, 2026 12:00 AM  
**Creation Time:** Oct 27, 2026 12:03:07 AM  
**Active Alerts:** 2/2  
**Attack Story Tabs:** Attack story | Alerts (2) | Activities (2) | Assets (1) | Evidence and Response (1) | Summary

## Summary
Analytic rule triggered on high volume of non-interactive sign-ins (>100/hr). Non-interactive sign-ins are logins by service principals, managed identities, or apps using tokens — not a user typing a password. Spike indicates potential token replay, service account compromise, or app misconfiguration.

## Detection Logic
```kql
// Analytic Rule: SOC-Hunt - Non-Interactive Sign-In Anomaly - _100/hr
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(1h)
| summarize Count = count() by UserId, AppId
| where Count > 100
```

This rule is part of 4 active analytic rules in workspace `sc200-law`:
1. SOC-Hunt10 - Persistence - Member Added to Group
2. HUNT - Non-Interactive Sign-In Anomaly - _100/hr  <-- This incident
3. HUNT - Brute Force Attempt
4. HUNT - Impossible Travel

## MITRE ATT&CK
- **TA0001 Initial Access** - Using stolen service principal credentials
- **TA0006 Credential Access** - Token theft / service account credential abuse
- **T1078.001 Valid Accounts: Default Accounts** - Service principal abuse
- **T1110 Brute Force** - High volume auth attempts

## Investigation Steps (SC200 Exam Style)

### 1. Triage - Attack Story
Open incident ID 25 in Microsoft Sentinel > Check Attack Story:
- 2 active alerts, 1 category
- Timeline: First to Last activity ~1 hour
- Asset involved: 1 asset (IP redacted for portfolio)

### 2. Alerts Tab (2 alerts)
- Alert 1: Oct 26 11:00 PM - HUNT - Non-Interactive Sign-In Anomaly - _100/hr - Status: New
- Alert 2: Oct 27 12:00 AM - HUNT - Non-Interactive Sign-In Anomaly - _100/hr - Status: New
- Both from same analytic rule, indicating sustained activity

### 3. Entities
- User: Service principal / App (redacted for portfolio)
- IP: [REDACTED - private lab IP, not shown in public portfolio]
- Location: [REDACTED]

### 4. Evidence
- `AADNonInteractiveUserSignInLogs` count in workspace: 1734 logs (from earlier hunting)
- Pattern: Burst of 100+ non-interactive logins within 1 hour
- No interactive login failure, so not user password spray — app-based

### 5. Related Hunting Queries (Safe - No PII)

**Check non-interactive volume:**
```kql
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(7d)
| summarize HourlyCount = count() by bin(TimeGenerated, 1h)
| sort by HourlyCount desc
```

**Check which apps:**
```kql
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(1d)
| summarize count() by AppId, UserId
| sort by count_ desc
| take 10
```

## Response Actions

### Immediate (Containment)
1. Disable service principal if unknown: Entra ID > Enterprise Apps > Disable
2. Rotate secret/certificate for affected app
3. Revoke sessions: `Revoke-AzureADUserAllRefreshToken`

### Investigation (SC200)
1. Check AuditLogs for "Add service principal credentials" around same time
2. Check App registrations for new secrets added
3. Review SignInLogs for same IP with different accounts (lateral movement)

### Long-term
1. Enable Conditional Access for service principals (Workload Identities)
2. Enable Managed Identity instead of client secrets
3. Create Workbook to monitor non-interactive spikes

## Lessons Learned
- Non-interactive logs are high volume but important — service accounts are often overlooked
- 100/hr threshold works for small lab (1734 logs total), in production use dynamic threshold
- This incident validates that analytic rule "HUNT - Non-Interactive Sign-In Anomaly - _100/hr" works

## Screenshot Reference
- Original screenshot: `IncidentDetails.png` (private, contains lab IP - DO NOT UPLOAD)
- Portfolio-safe version: `images/Incident25-NonInteractive-Anomaly-SAFE.png` (redacted, safe for GitHub)

## Portfolio Mapping
- **File:** `incidents/Incident25.md` (this file)
- **Image:** `images/Incident25-NonInteractive-Anomaly-SAFE.png`
- **Analytic Rule:** `analytics/HUNT-NonInteractive-100hr.kql`
- **MITRE Navigator:** Layer includes TA0001, TA0006, T1078.001, T1110
