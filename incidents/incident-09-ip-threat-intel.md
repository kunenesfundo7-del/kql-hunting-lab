# Incident 09 - Threat Intel - Vodacom Mobile IP Reputation

**IP:** 41.24.136.73
**ISP:** Vodacom - AS36994 - Mobile ISP - vodacom.com
**Location:** Johannesburg, Gauteng, ZA - matches SigninLogs Location
**AbuseIPDB:** Reported 11 times, Confidence 0% - CLEAN (Green)
**Reason for 11 reports:** CGNAT shared mobile pool - Vodacom reuses public IP across thousands of users in Gauteng - false positive noise.

**KQL Evidence (sc200-law):**
SigninLogs | where IPAddress == "41.24.136.73" | project TimeGenerated, DeviceDetail.operatingSystem, Location
Result: Windows10 + Android both from same Vodacom IP, same day, same ZA location.

**Finding:** IP validated as legitimate ZA mobile ISP, not anonymizer. BYOD sign-ins (Hunt 08) confirmed as true user, not impossible travel. No block needed.

**SOC Action:** Create Named Location "Germiston-Vodacom-Mobile" in Entra ID Conditional Access - Add 41.24.136.0/24 to trusted locations. Monitor for future spike in Confidence %.

**Framework:** MITRE T1078, Threat Intel Enrichment, MITRE T1090.003 - ISP validation
**Value:** Demonstrates ability to enrich raw SigninLogs IP with external TI (AbuseIPDB, IPInfo) and explain CGNAT false positives - critical for SA SOC with high mobile ISP traffic.
