# Incident 06 - Conditional Access Not Applied - 45 Events

**Date:** Oct 2026
**Workspace:** sc200-law
**Query:** SigninLogs | summarize Count=count() by ConditionalAccessStatus
**Result:** notApplied = 45, failure = 0, success = 0

**Finding:**
45 sign-ins in 30d with ConditionalAccessStatus=notApplied. No CA policies evaluated. Lab tenant SC200 Lab Learning has no CA policy enforcing MFA / compliant device.

**Root Cause:**
SC200 lab intentionally without CA policies to test hunting. Real prod would be critical gap.

**Risk:** 
Violates CIS 6.5, NIST PR.AC-1, Zero Trust - identities accessing without policy evaluation. If attacker compromises admin@sc200lablearn..., no CA blocks them.

**Recommendation:**
1. Deploy CA policies: Require MFA + Compliant Device + Block legacy auth
2. Enable CA reporting-only mode first, then enforce
3. Alert on SigninLogs where ConditionalAccessStatus == "notApplied" and UserPrincipalName has "admin"

**Evidence:** hunt-06-conditional-access-notapplied-45.jpg - Shows 45 notApplied in sc200-law
**Framework:** NIST PR.AC-1, CIS Controls 6.5, Microsoft Zero Trust CA
