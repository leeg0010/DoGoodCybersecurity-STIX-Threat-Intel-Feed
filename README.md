# 🛡️ Honeypot Threat Intelligence Feed

> **Public STIX 2.1 threat intelligence from a distributed honeypot network**  
> Real-world attack data • Daily updates • Free to use

[![License: CC0](https://img.shields.io/badge/License-CC0-blue.svg)](LICENSE-DATA)
[![STIX 2.1](https://img.shields.io/badge/STIX-2.1-green.svg)](https://oasis-open.github.io/cti-documentation/stix/intro.html)
[![Update Frequency](https://img.shields.io/badge/Updates-Daily-orange.svg)](daily/)

## 🎯 What is This?

A **free, public threat intelligence feed** containing real attack indicators observed on honeypot sensors. Every IP address in this feed has been observed conducting malicious activity against decoy systems.

**Key Details:**
- 📊 **500-2,000 malicious IPs** identified daily
- 🔄 **Updated every 24 hours** at 3:00 AM UTC
- 🌍 **Global coverage** - attackers from 150+ countries
- ✅ **Validated** - All indicators confirmed through real interactions
- 💯 **Free to use** - CC0 Public Domain, no attribution required

---

## 🚀 Quick Start

### Get Today's Malicious IPs

```bash
# Download today's feed
DATE=$(date -u +%Y-%m-%d)
curl -s "https://raw.githubusercontent.com/leeg0010/DoGoodCybersecurity-STIX-Threat-Intel-Feed/main/daily/${DATE}.json" | jq -r '.objects[] | select(.type=="indicator") | .pattern' | grep -oP "(?<=value = ')[^']+(?=')"
```
# How Collection Works

1. **Honeypots capture attacks** - Decoy systems record all malicious interactions
2. **Edge correlation** - Network logs resolve real attacker IPs behind NAT
3. **Validation** - Minimum 5 events required, confidence scoring applied
4. **Publication** - High-confidence indicators (≥50 score) published daily

**Correlation Methods:**
- JA3/JA3S/HASSH fingerprinting (TLS/SSH patterns)
- Port + timestamp matching (15-second window)
- Session ID tracking for multi-event attacks

---

## ⭐ Confidence Scoring

Every indicator includes a **confidence score (0-100)** based on:

| Factor | Weight | Description |
|--------|--------|-------------|
| Event Volume | 25 pts | More observations = higher confidence |
| Correlation Rate | 15 pts | Successfully matched to real IPs |
| Port Diversity | 10 pts | Attacks across multiple services |
| Duration | 10 pts | Persistent activity over time |

### Confidence Tiers

- **🔴 85-100 (High)** - Extensive evidence, confirmed malicious
- **🟠 70-84 (Medium-High)** - Significant activity, well-correlated  
- **🟡 50-69 (Medium)** - Standard reconnaissance/scanning
- **⚪ <50 (Low)** - Limited observations or campaign-only

**Quality Controls:**
- ✅ Minimum 5 events per indicator
- ✅ Minimum confidence 50 for publication
- ✅ Private IPs excluded (10.x, 172.16.x, 192.168.x)
- ✅ Known security scanners filtered (Shodan, Censys)
**File Format:** `daily/YYYY-MM-DD.json`

Each daily bundle contains:
- 🎯 Malicious IPv4 addresses
- 📈 Confidence scores (0-100) 
- 🌐 ASN and geographic data
- 🔌 Targeted ports and services
- 📊 Event counts and timestamps

**Example:** [View latest feed →](daily/)

---

## 🔍 Data Collection

### Honeypot Sensors

Our network includes multiple honeypot types monitoring real-world attacks:

- **Cowrie** → SSH/Telnet brute force and command injection
- **Dionaea** → SMB, MySQL, MSSQL, FTP, HTTP exploits
- **ADBHoney** → Android Debug Bridge attacks
- **Suricata** → Network IDS detecting protocol anomalies
- **Custom Sensors** → Web, email, and IoT attack surface

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
---

## 💻 Integration Examples

### MISP Platform

```bash
# Import STIX bundle into MISP
curl -X POST https://your-misp/events/upload_stix \
  -H "Authorization: YOUR_API_KEY" \
  -F "file=@daily/$(date -u +%Y-%m-%d).json"
```

### Firewall Blocklist

```bash
# Generate firewall blocklist from feed
curl -s "https://raw.githubusercontent.com/leeg0010/DoGoodCybersecurity-STIX-Threat-Intel-Feed/main/daily/$(date -u +%Y-%m-%d).json" \
  | jq -r '.objects[] | select(.type=="indicator" and .confidence >= 70) | .pattern' \
  | grep -oP "(?<=value = ')[^']+(?=')" > blocklist.txt
```

### SIEM Integration

**Splunk:**
```spl
| inputlookup threat_intel_stix.csv
| append [| rest /services/data/inputs/http/stix_feed]
```

**Elastic Security:**
```json
PUT _ingest/pipeline/stix-feed
{
  "processors": [
    {
      "script": {
        "source": "ctx.threat_ip = params.stix.objects.findAll(o -> o.type == 'indicator').pattern"
      }
    }
  ]
}

```bash
curl -s https://raw.githubusercontent.com/leeg0010/DoGoodCybersecurity-STIX-Threat-Intel-Feed/main/daily/2025-12-02.json \
  | jq -r '.objects[] | select(.type=="indicator") | .pattern' \
  | grep -oP "(?<=value = ')[^']+(?=')"
```

## Data Quality & Confidence Scoring

---

## 📊 Feed Statistics

**Daily Metrics:**
- **500-2,000** malicious IPs per day
- **~150,000** honeypot events analyzed daily
- **40-50%** correlation rate (honeypot → real IP)
- **150+** countries observed
- **Average confidence:** 72/100

**Most Targeted Services:**
1. Port 443 (HTTPS) - Web attacks
2. Port 5900 (VNC) - Remote desktop brute force
3. Port 22 (SSH) - Credential stuffing
4. Port 3306 (MySQL) - Database exploits
5. Port 445 (SMB) - Windows file sharing attacks

See [stats/summary.json](stats/summary.json) for real-time metrics.

### Collection
---

## ⚖️ License & Usage Terms

### Data License
**CC0 1.0 Universal (Public Domain Dedication)**

You may:
- ✅ Use commercially or non-commercially
- ✅ Modify and redistribute freely
- ✅ Integrate into proprietary systems
- ✅ No attribution required (but appreciated!)

### Responsible Use

**DO:**
- Use for defensive security and threat hunting
- Validate indicators in your environment before blocking
- Report false positives to help improve quality
- Share integration examples with the community

**DON'T:**
- Use for offensive operations or unauthorized access
- Assume malicious intent without investigation
- # ⚠️ Disclaimer

This feed provides honeypot observations representing **potential threats**. Please note:

- May include false positives or compromised legitimate systems
- IP addresses could be spoofed or behind VPNs/proxies
- No warranty or guarantee of accuracy provided
- Validate in your environment before taking action
- Use at your own risk

## Statistics

**Current Feed Metrics** (as of 2025-12-02):
- Daily indicators: 500-2000 IPs
- Total honeypot events: ~150K/day
- Correlation rate: 40-50%
- Average confidence: 72
---

## 🤝 Contributing

Help improve this feed:

- 🐛 **Report False Positives** - Open an [issue](https://github.com/leeg0010/DoGoodCybersecurity-STIX-Threat-Intel-Feed/issues) with IP and evidence
- 📝 **Share Integrations** - Submit your consumption scripts via PR
- 💡 **Suggest Improvements** - Request additional data fields or STIX objects
- 🛡️ **Allowlist Requests** - Identify legitimate scanners to exclude

---

## 📞 Support & Contact

- **Issues:** [GitHub Issues](https://github.com/leeg0010/DoGoodCybersecurity-STIX-Threat-Intel-Feed/issues)
- **Security:** Report vulnerabilities via [SECURITY.md](.github/SECURITY.md)
- **Maintainer:** [@leeg0010](https://github.com/leeg0010)

---

## 📜 Changelog

- **2025-12-08** - Removed internal scripts, feed-only repository
- **2025-12-02** - Initial public feed launch
- See [docs/CHANGELOG.md](docs/CHANGELOG.md) for full history

---

<div align="center">

**Feed Version:** 1.0 • **STIX Version:** 2.1 • **Last Updated:** 2026-02-10

Made with 🛡️ by the security research community

</div>