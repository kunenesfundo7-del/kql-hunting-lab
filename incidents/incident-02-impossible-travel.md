# Incident 02 - Impossible Travel Detection

**Date:** 2026-10-17
**Analyst:** Sfundo (Germiston, ZA)
**Status:** No Threat Found - Baseline Validated

**Hunt Objective:** Detect impossible travel / credential theft for solo lab user

**Baseline (Known Good - Proven in Incident 03):**
- User: admin@sc200lablearning.onmicrosoft.com
- Legit Location: ZA - Germiston, South Africa
- Legit IP: 41.24.136.73
- Legit Time: 2026-10-17 17:52
- Lab Type: Solo - 1 user only

**KQL Query File:** queries/impossible-travel.kql

**Query Logic:**
1. Filter successful logins (Result == 0) for sc200 user
2. Require Location and IPAddress not empty
3. Summarize by User + 1h bin: dcount(Country), make_set(Countries, Locations, IPs)
4. Trigger when CountryCount > 1
5. Add Risk field: flag travel originating from ZA

**KQL:**
```kql
SigninLogs
| where Result == 0
| where UserPrincipalName contains "sc200"
| where isnotempty(Location) and isnotempty(IPAddress)
| summarize 
    CountryCount = dcount(Country),
    Countries = make_set(Country),
    Locations = make_set(Location),
    IPs = make_set(IPAddress),
    LastSeen = max(TimeGenerated)
    by UserPrincipalName, bin(TimeGenerated, 1h)
| where CountryCount > 1
| extend Risk = iff(Countries has "ZA", "Possible Travel from ZA", "Foreign Login")
