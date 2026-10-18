# KQL Hunting Lab - SC-200 Preparation

**Candidate:** SOC Analyst | SC-200 | Germiston, SA  
**Workspace:** sc200-law (Microsoft Sentinel)  
**Lab Environment (Live Proven):**
- Location: ZA - Germiston, South Africa (41.24.136.73)
- User: admin@sc200lablearning.onmicrosoft.com
- Lab Type: Solo (1 user) - Baseline validated
- Evidence: images/mfa-hunt-results.jpg
- Chain: Incident-03 proves baseline (ZA + IP) -> Incident-02 hunts deviation

**Purpose**
This repo documents my KQL hunting queries for Microsoft Sentinel, focusing on real-world attack detection mapped to MITRE ATT&CK. All queries tested in live sc200-law workspace with real baseline.

**TFESP Method (How I read KQL)**


## Latest Hunts - Oct 2026 (Live Lab sc200-law)

### Hunt 04 - PIM Elevation - CRITICAL FINDING
- **Query:** `queries/hunt-04-pim-elevation.kql` - `Add member to role` returned 0 results
- **RCA:** Entra Admin Center > My Roles > Global Admin = Permanent (not Eligible)
- **Evidence:** `incidents/incident-04-pim-permanent-admin.md`
- **Impact:** Violates JIT, CIS 5.4, NIST PR.AC-4 - Permanent assignment = persistence risk

### Hunt 06 - Conditional Access Gap - CRITICAL FINDING  
- **Query:** `SigninLogs | summarize by ConditionalAccessStatus` = notApplied 45
- **Evidence:** `incidents/incident-06-conditional-access-failure.md` + `incident-06-conditional-access-rca.md`
- **Impact:** 45 sign-ins with no CA policy evaluated - CIS 6.5, Zero Trust gap

**Lab Provenance:** Workspace sc200-law, User admin@sc200lablearning.onmicrosoft.com, IP 41.24.136.73 Germiston ZA, Live queries with screenshots.

- *Hunt 08:* BYOD Cross-Device ✅ Windows10 + Android | sc200-law | Germiston 41.24.136.73
- *Hunt 09:* Threat Intel ✅ Vodacom Mobile IP 0% Abuse | Johannesburg | CGNAT explained
