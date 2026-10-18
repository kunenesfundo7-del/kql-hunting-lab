# Incident 06 - Sign-in Failure RCA - ResultType 50126

**Date:** Oct 17, 2026 19:09:05
**Workspace:** sc200-law (southafricanorth)
**User:** admin@sc200lablearning.onmicrosoft.com
**IP:** 41.24.136.73 | Location: ZA

**Query:** hunt-06-conditional-access-rca.kql - 11 items in 14d

**Findings:**
- ConditionalAccessStatus: notApplied (auth failed pre-CA)
- ResultType: 50126 - Error validating credentials due to invalid username or password
- App: Microsoft 365 Security and Compliance Center - relevant to Purview DLP role
- Triage: Verified Entra ID Protection, checked SigninLogs for brute force pattern, no MFA fatigue, no impossible travel correlation

**Action:** Password reset guidance, confirmed legitimate admin activity from ZA IP, documented for ServiceNow KB

**Framework:** NIST PR.AC-1, CIS 5.2, ISO 27001 A.9.2, POPIA Sec 19 - Zero Trust verification failed at identity layer

**Evidence:** images/hunt-06-advanced-hunting-11-items.jpg, hunt-06-detail-50126-invalid-creds.jpg
