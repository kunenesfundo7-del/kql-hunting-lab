# Incident 03 - MFA Fatigue Triage

**Workspace:** sc200-law (southafricanorth) - Connected in sc200-lab-rg
**Query Used:** mfa-fatigue-hunt.kql
**Finding:** Multiple failed MFA for SC200 test users, correlated with MS-PIM elevation

**Triage:**
- Validated SigninLogs ResultType 500121, 500123
- IP: 41.24.136.73 - ZA - Germiston
- User Agent: console-m365d (lab infra)
- Action: Escalated to create scheduled detection (Hunt 06)

**SC-200 Skill:** Incident investigation & response
