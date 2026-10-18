# Incident 06 - Conditional Access Block Triage

**Ticket Type:** Conditional Access / Sign-in Failure
**Severity:** Medium | **Source:** sc200-law | **Region:** southafricanorth / ZA IP 41.24.136.73

**Alert:** User blocked by Conditional Access (ResultType 53003)

**Investigation:**
- Query: hunt-06-conditional-access-failure.kql
- Evidence: Location ZA, Device Policy Failure, App: M365
- Checks: Entra ID Protection risk, MFA status, Device compliance in Intune, PIM elevation history
- Framework: Zero Trust - continuous verification failed, CIS 5.2 Account Management

**Resolution:** Verified legitimate user, re-applied Conditional Access exception for compliant device, enabled MFA re-registration, documented per POPIA

**Lesson Learned:** Added to ServiceNow KB — Conditional Access troubleshooting steps

**Evidence:** images/hunt-06-conditional-access.jpg
