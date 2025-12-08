# Changelog

All notable changes to this STIX threat intelligence feed will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-12-08

### Added
- Initial public release of DoGoodCybersecurity STIX Threat Intel Feed
- Daily IOC feeds in STIX 2.1 format
- Automated GitHub Actions workflow for daily feed generation
- Python generation scripts for STIX bundle creation
- Confidence scoring algorithm for indicator quality assessment
- Statistics generation and tracking
- README with usage examples for Python, Splunk, and MISP
- CC0 1.0 Universal license for threat intelligence data
- MIT license for generation scripts

### Features
- Minimum 5 events required per indicator
- Minimum 50 confidence score for publication
- IP correlation with network edge logs
- ASN and geographic metadata enrichment
- Attack pattern classification (SSH brute-force, HTTPS scanning, etc.)
- TLP:WHITE marking for public distribution
- Valid-until timestamp (7 days from observation)

### Data Sources
- Cowrie SSH/Telnet honeypot
- Dionaea multi-protocol honeypot
- ADBHoney Android exploitation detection
- Suricata network IDS
- Additional sensors: ElasticPot, Mailoney, Tanner

### Metrics (Launch Day)
- Daily indicators: 500-2000 IPs
- Correlation rate: 40-50%
- Average confidence: 72
- Countries observed: 150+
- Top ports: 443 (HTTPS), 5900 (VNC), 22 (SSH)

## [Unreleased]

### Planned
- Weekly summary feeds with campaign analysis
- Malware sample catalog with YARA rules
- Named attack campaigns with MITRE ATT&CK mapping
- Threat actor clustering by ASN/geography
- Password spray dataset export
- TAXII 2.1 server endpoint
- Historical data backfill (90 days)
