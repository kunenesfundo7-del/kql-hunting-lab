# Incident 04 - Permanent Global Admin - PIM Bypass

**Workspace:** sc200-law
**Hunt:** PIM Elevation
**Evidence:** 
- images/hunt-04-permanent-global-admin-proof.jpg (My Roles > Permanent)
- images/hunt-04-pim-elevation-0-results.jpg (AuditLogs Add member to role = 0)

**Finding:** Global Administrator assigned as Permanent, not Eligible. No PIM activation required. Hunt query returned 0 because role is persistent.

**Risk:** Critical - violates JIT, CIS 5.4, NIST PR.AC-4. If admin@sc200lablearn... compromised, attacker has permanent Global Admin.

**Recommendation:** Convert to Eligible + Require MFA + Approval + 4h max + Alert on Permanent assignments.

**KQL:** queries/hunt-04-pim-elevation.kql
