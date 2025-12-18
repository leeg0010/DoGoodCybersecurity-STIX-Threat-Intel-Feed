# Honeypot Threat Intelligence Feed

**Public STIX 2.1 threat intelligence feed derived from distributed honeypot network observations.**

## Overview

This repository contains structured threat intelligence in STIX 2.1 format, generated from a distributed honeypot infrastructure monitoring internet-wide attack activity. All indicators are derived from real attacker interactions with honeypot sensors and represent confirmed malicious behavior.

**Feed Type**: Public Threat Intelligence (TLP:WHITE)  
**Format**: STIX 2.1 JSON Bundles  
**Update Frequency**: Daily (3:00 AM UTC)  
**License**: CC0 1.0 Universal (Public Domain Dedication)

## Data Sources

Intelligence is collected from multiple honeypot technologies:
- **Cowrie** - SSH/Telnet honeypot capturing credentials and commands
- **Dionaea** - Multi-protocol honeypot (SMB, MySQL, MSSQL, FTP, HTTP)
- **ADBHoney** - Android Debug Bridge exploitation detection
- **Suricata** - Network IDS for protocol analysis
- **Additional sensors** - ElasticPot, Mailoney, Tanner, H0neytr4p

All indicators are correlated with network edge logs to resolve real attacker IPs through NAT gateways.

## Feed Structure

### Daily IOCs (`daily/`)
Daily bundles containing malicious IP indicators observed in the past 24 hours.

**Format**: `daily/YYYY-MM-DD.json`  
**Content**: STIX Indicator objects with:
- Malicious IPv4 addresses
- Event counts and timestamps
- Targeted ports and services
- ASN and geographic metadata
- Confidence scores (0-100)

**Example**: [daily/2025-12-02.json](daily/2025-12-02.json)

### Weekly Summaries (`weekly/`)
Aggregated 7-day intelligence with campaign analysis and trending threats.

**Format**: `weekly/YYYY-WNN.json` (ISO week number)  
**Content**: Campaign objects, threat actor clusters, trending attack patterns

### Campaigns (`campaigns/`)
Named attack campaigns with associated indicators and TTPs.

**Format**: `campaigns/campaign-name-NNN.json`  
**Content**: Campaign objects linked to Attack Patterns (MITRE ATT&CK) and Indicators

### Malware Catalog (`malware/`)
Captured malware samples with hashes, YARA rules, and delivery context.

**Format**: `malware/samples-catalog.json`  
**Content**: Malware and File objects with SHA-256/MD5/SHA-1 hashes

## Usage Examples

### Python - Download and Parse Daily Feed

```python
import requests
import json
from datetime import datetime

# Download today's feed
date = datetime.utcnow().strftime('%Y-%m-%d')
url = f"https://raw.githubusercontent.com/leeg0010/DoGoodCybersecurity-STIX-Threat-Intel-Feed/main/daily/{date}.json"
response = requests.get(url)
stix_bundle = response.json()

# Extract malicious IPs
for obj in stix_bundle['objects']:
    if obj['type'] == 'indicator' and 'ipv4-addr' in obj['pattern']:
        ip = obj['pattern'].split("'")[1]
        confidence = obj.get('confidence', 0)
        print(f"{ip} - Confidence: {confidence}")
```

### Splunk - Ingest Feed into Lookup Table

```spl
| inputlookup append=true threat_intel_feed.csv
| append 
    [| rest /services/data/inputs/http/<token>
    | eval url="https://raw.githubusercontent.com/leeg0010/DoGoodCybersecurity-STIX-Threat-Intel-Feed/main/daily/latest.json"
    | map search="| tstats ... url=$url$"]
```

### MISP - Import STIX Bundle

```bash
# Via MISP API
curl -X POST https://your-misp/events/upload_stix \
  -H "Authorization: <api-key>" \
  -H "Accept: application/json" \
  -F "file=@daily/2025-12-02.json"
```

### Command Line - Extract IPs Only

```bash
curl -s https://raw.githubusercontent.com/leeg0010/DoGoodCybersecurity-STIX-Threat-Intel-Feed/main/daily/2025-12-02.json \
  | jq -r '.objects[] | select(.type=="indicator") | .pattern' \
  | grep -oP "(?<=value = ')[^']+(?=')"
```

## Data Quality & Confidence Scoring

All indicators include a **confidence score (0-100)** calculated from:
- **Event volume** (25 points max) - More observations = higher confidence
- **Correlation rate** (15 points) - Successfully matched to real attacker IPs
- **Port diversity** (10 points) - Targeting multiple services indicates broader campaign
- **Duration** (10 points) - Activity over longer period = persistent threat

**Confidence Tiers**:
- **85-100**: High - Extensive evidence, confirmed malicious activity
- **70-84**: Medium-High - Significant activity, well-correlated
- **50-69**: Medium - Standard reconnaissance/scanning
- **30-49**: Low-Medium - Limited observations
- **<30**: Low - Published only if part of larger campaign

**Filtering Criteria**:
- Minimum 5 events required to create indicator
- Minimum 50 confidence score for publication
- Private IP ranges (10.x, 172.16.x, 192.168.x) excluded
- Known security researcher IPs excluded (Shodan, Censys, etc.)

## Methodology

### Collection
Honeypots are deployed across multiple geographic regions and network segments. All interactions are logged with full packet captures and session metadata.

### Correlation
Honeypot events (using internal NAT IPs) are correlated with network edge logs (pfSense, Suricata) to resolve real attacker source IPs. Correlation uses:
1. **Fingerprint matching** - JA3/JA3S/HASSH TLS/SSH fingerprints
2. **Port-based matching** - Destination port + timestamp within 15-second window
3. **Session tracking** - Session IDs for multi-event correlation (Cowrie)

**Current Correlation Rate**: 40-50% (improving from 18% baseline after recent enhancements)

### Validation
- Indicators must meet minimum event threshold (5+ events)
- Confidence scoring filters low-quality observations
- Community feedback loop for false positive reports
- Quarterly review of published indicators

## Attribution & Disclaimer

**Attribution**: This threat intelligence is provided by a private security research honeypot network. Attribution is encouraged but not required (CC0 license).

**Disclaimer**: 
- This data represents honeypot observations and may include false positives
- IP addresses may be spoofed, compromised systems, or legitimate security scanners
- Indicators should be validated in your environment before blocking
- No warranty or guarantee of accuracy is provided
- Use at your own risk for defensive security purposes only

**Responsible Use**:
- Do NOT use for offensive operations or unauthorized access
- Do NOT attribute malicious intent to IP owners without investigation
- Report false positives via GitHub Issues
- Respect TLP:WHITE sharing guidelines

## Statistics

**Current Feed Metrics** (as of 2025-12-02):
- Daily indicators: 500-2000 IPs
- Total honeypot events: ~150K/day
- Correlation rate: 40-50%
- Average confidence: 72
- Countries observed: 150+
- Top targeted ports: 443 (HTTPS), 5900 (VNC), 22 (SSH)

See [stats/summary.json](stats/summary.json) for detailed metrics.

## Contributing

We welcome community contributions:
- **False Positive Reports**: Open an issue with IP and reasoning
- **Allowlist Suggestions**: Known security researchers/scanners to exclude
- **Integration Examples**: Share your consumption scripts via PR
- **Feedback**: Suggest additional data fields or STIX object types

## Contact & Support

- **Repository**: https://github.com/leeg0010/DoGoodCybersecurity-STIX-Threat-Intel-Feed
- **Issues**: https://github.com/leeg0010/DoGoodCybersecurity-STIX-Threat-Intel-Feed/issues
- **Security**: See [SECURITY.md](.github/SECURITY.md) for vulnerability reporting
- **Researcher**: LeeG0010

## License

**Data**: CC0 1.0 Universal (Public Domain Dedication)  
**Code** (scripts/): MIT License

You are free to:
- Use commercially or non-commercially
- Modify and redistribute
- Integrate into proprietary systems
- No attribution required (but appreciated)

## Changelog

- **2025-12-02**: Initial feed launch with daily IOCs
- See [docs/CHANGELOG.md](docs/CHANGELOG.md) for full history

---

**Last Updated**: 2025-12-08  
**Feed Version**: 1.0  
**STIX Version**: 2.1
Test comment
