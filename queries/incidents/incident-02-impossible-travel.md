# Incident 02 - Impossible Travel - Multiple Countries in 10m - LAB

**ID:** 2 | **Severity:** High | **Status:** Active
**Rule:** Impossible Travel - Multiple Countries in 10m - LAB
**Workspace:** sc200-law | **Service Source:** Microsoft Sentinel
**Date:** Oct 16, 2026 | **Location:** Germiston, SA

### Attack Story
- **12 Alerts** aggregated into single incident (now 70 alerts / 71 activities)
- **Activities:** First: 10:21 AM - Last: 4:26 PM
- **Tactic:** Identity - Initial Access / Impossible Travel
- **User:** admin@sc200lablearning.onmicrosoft.com (Sfundo Kunene)

### The Lab Blocker (Real Troubleshooting)

**Error:** Analytics Rule Wizard failed validation on Review + Create - Red X

**Root Cause:** Entity Mapping pointing to columns that don't exist in query output.
Query returned: UserPrincipalName, Country, count_
Mapping was: AccountCustomEntity / IPCustomEntity (template error)

**Fix:**
In Set rule logic > Entity mapping > Alert Details:
1. Account Entity: Identifier Name -> Value UserPrincipalName (not AccountCustomEntity)
2. Deleted IP Entity row (no IP in this query version)

Final mapping:
- UserPrincipalName = Account Entity
- Country = Geo Location

### Key Finding from Asset Panel
MFA Status: Disabled
MFA Type: Authenticator push / Software OTP
This is why Impossible Travel was possible.

### Evidence
- images/impossible-travel-asset-mfa-disabled.jpg
