"""
STIX 2.1 Threat Intelligence Feed Generator

This module generates STIX 2.1 compliant threat intelligence bundles from
honeypot data stored in Elasticsearch. It queries the honeypot-normalized-*
indices to extract malicious indicators, attack patterns, campaigns, and
malware samples for public threat intelligence sharing.

Key Functions:
    - generate_daily_feed(): Creates daily STIX bundle with IOCs
    - generate_weekly_summary(): Aggregates 7 days into campaign intelligence
    - generate_malware_catalog(): Exports malware samples with hashes
    - calculate_confidence(): Scores indicator reliability based on evidence

STIX Object Types Generated:
    - Indicator: Malicious IPs, file hashes
    - Attack Pattern: TTPs mapped to MITRE ATT&CK
    - Campaign: Coordinated attack activity clusters
    - Malware: Binary samples with delivery context
    - Threat Actor: Geographic/ASN-based actor groupings
    - Relationship: Links between objects

Output Format: STIX 2.1 JSON bundles
Data Source: Elasticsearch honeypot-normalized-*, passwords-*, samples-*
License: CC0 1.0 Universal (Public Domain Dedication)

Author: Igor Threat Intelligence Team
Created: December 2, 2025
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from uuid import uuid4

# STIX 2.1 library
try:
    from stix2 import (
        Bundle, Indicator, Malware, Campaign, AttackPattern,
        Identity, MarkingDefinition, Relationship, File,
        ThreatActor, Infrastructure, ObservedData, TLP_WHITE
    )
    STIX2_AVAILABLE = True
except ImportError:
    STIX2_AVAILABLE = False
    logging.warning("stix2 library not available. Install with: pip install stix2")

# Elasticsearch client
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import NotFoundError, RequestError

# Configure logging
logger = logging.getLogger(__name__)


class STIXFeedGenerator:
    """
    Generates STIX 2.1 threat intelligence feeds from honeypot data.
    
    This class queries Elasticsearch indices containing honeypot events,
    extracts indicators of compromise (IOCs), identifies attack patterns,
    and exports structured threat intelligence in STIX 2.1 format.
    
    Attributes:
        es_client: Elasticsearch client instance
        identity: STIX Identity object representing the honeypot network
        tlp_white: TLP:WHITE marking definition for public data
        min_events: Minimum event count to qualify as indicator
        confidence_threshold: Minimum confidence score to publish
    """
    
    def __init__(
        self,
        es_host: str = "10.0.3.9",
        es_port: int = 9200,
        es_user: Optional[str] = None,
        es_password: Optional[str] = None,
        min_events: int = 5,
        confidence_threshold: int = 50
    ):
        """
        Initialize STIX feed generator with Elasticsearch connection.
        
        Args:
            es_host: Elasticsearch hostname or IP
            es_port: Elasticsearch port (default 9200)
            es_user: Optional username for authentication
            es_password: Optional password for authentication
            min_events: Minimum events required to create indicator (default 5)
            confidence_threshold: Minimum confidence score to publish (0-100, default 50)
        """
        if not STIX2_AVAILABLE:
            raise ImportError("stix2 library is required. Install with: pip install stix2")
        
        # Initialize Elasticsearch client
        es_config = {
            'hosts': [{'host': es_host, 'port': es_port, 'scheme': 'http'}],
            'request_timeout': 30,
            'headers': {'accept': 'application/json', 'content-type': 'application/json'}
        }
        
        if es_user and es_password:
            es_config['basic_auth'] = (es_user, es_password)
        
        self.es_client = Elasticsearch(**es_config)
        
        # Configuration
        self.min_events = min_events
        self.confidence_threshold = confidence_threshold
        
        # Create STIX Identity for the honeypot network
        self.identity = Identity(
            id="identity--550e8400-e29b-41d4-a716-446655440000",
            name="Distributed Honeypot Network",
            identity_class="system",
            created="2025-01-01T00:00:00.000Z",
            modified=datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            contact_information="https://github.com/leeg0010/DoGoodCybersecurity-STIX-Threat-Intel-Feed"
        )
        
        # TLP:WHITE marking (public distribution) - use built-in from stix2 library
        self.tlp_white = TLP_WHITE
        
        logger.info(
            f"STIX Feed Generator initialized: min_events={min_events}, "
            f"confidence_threshold={confidence_threshold}"
        )
    
    def calculate_confidence(
        self,
        event_count: int,
        correlation_rate: float,
        targeted_ports: List[int],
        duration_hours: float
    ) -> int:
        """
        Calculate STIX confidence score (0-100) based on evidence quality.
        
        Higher scores indicate more reliable indicators based on:
        - Event volume (more observations = higher confidence)
        - Correlation rate (successfully correlated to real IPs)
        - Port diversity (targeting multiple services indicates scanning)
        - Duration (activity over longer period = persistent threat)
        
        Args:
            event_count: Number of events observed from this indicator
            correlation_rate: Percentage of events correlated to real IPs (0.0-1.0)
            targeted_ports: List of destination ports targeted
            duration_hours: Duration of activity in hours
        
        Returns:
            Confidence score (0-100), where:
                85-100: High confidence (extensive evidence)
                70-84: Medium-high (significant activity)
                50-69: Medium (standard reconnaissance)
                30-49: Low-medium (limited activity)
                0-29: Low (minimal evidence)
        """
        base_score = 50
        
        # Event volume component (0-25 points)
        if event_count >= 1000:
            volume_score = 25
        elif event_count >= 100:
            volume_score = 20
        elif event_count >= 50:
            volume_score = 15
        elif event_count >= 10:
            volume_score = 10
        else:
            volume_score = 5
        
        # Correlation rate component (0-15 points)
        # Higher correlation means we have real attacker IPs, not just gateway
        correlation_score = int(correlation_rate * 15)
        
        # Port diversity component (0-10 points)
        # Multiple ports indicate scanning/broader campaign
        port_count = len(set(targeted_ports))
        if port_count >= 5:
            diversity_score = 10
        elif port_count >= 3:
            diversity_score = 7
        elif port_count >= 2:
            diversity_score = 5
        else:
            diversity_score = 3
        
        # Duration component (0-10 points)
        # Longer duration indicates persistent threat actor
        if duration_hours >= 12:
            duration_score = 10
        elif duration_hours >= 6:
            duration_score = 7
        elif duration_hours >= 1:
            duration_score = 5
        else:
            duration_score = 2
        
        confidence = base_score + volume_score + correlation_score + diversity_score + duration_score
        
        return min(confidence, 100)  # Cap at 100
    
    def _query_daily_indicators(self, date: datetime) -> List[Dict[str, Any]]:
        """
        Query Elasticsearch for malicious indicators from a specific date.
        
        Extracts unique source IPs with metadata including event counts,
        targeted ports, ASN information, and geographic data.
        
        Args:
            date: Date to query (datetime object)
        
        Returns:
            List of indicator dictionaries with metadata
        """
        index_name = f"honeypot-normalized-{date.strftime('%Y.%m.%d')}"
        
        query = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"term": {"edge.matched": True}}
                    ],
                    "should": [
                        {"exists": {"field": "edge.source.ip"}},
                        {"exists": {"field": "source.ip"}}
                    ],
                    "minimum_should_match": 1,
                    "must_not": [
                        # Exclude private IP ranges
                        {"prefix": {"edge.source.ip": "10."}},
                        {"prefix": {"edge.source.ip": "172.16."}},
                        {"prefix": {"edge.source.ip": "192.168."}},
                        {"prefix": {"source.ip": "10."}},
                        {"prefix": {"source.ip": "172.16."}},
                        {"prefix": {"source.ip": "192.168."}},
                        # Exclude owner's static IP
                        {"term": {"source.ip.keyword": "98.163.174.142"}}
                    ]
                }
            },
            "aggs": {
                "malicious_ips": {
                    "terms": {
                        "field": "source.ip.keyword",
                        "size": 10000
                    },
                    "aggs": {
                        "first_seen": {"min": {"field": "@timestamp"}},
                        "last_seen": {"max": {"field": "@timestamp"}},
                        "targeted_ports": {
                            "terms": {"field": "destination.port", "size": 20}
                        },
                        "tools_targeted": {
                            "terms": {"field": "honeypot.tool.keyword", "size": 20}
                        },
                        "asn_number": {
                            "terms": {"field": "source.as.number", "size": 1}
                        },
                        "asn_name": {
                            "terms": {"field": "source.as.organization.name.keyword", "size": 1}
                        },
                        "country": {
                            "terms": {"field": "source.geo.country_iso_code.keyword", "size": 1}
                        },
                        "correlated_events": {
                            "filter": {"exists": {"field": "edge.source.ip"}}
                        }
                    }
                }
            }
        }
        
        try:
            response = self.es_client.search(index=index_name, body=query)
        except NotFoundError:
            logger.warning(f"Index {index_name} not found")
            return []
        except RequestError as e:
            logger.error(f"Elasticsearch query error: {e}")
            return []
        
        indicators = []
        
        for bucket in response['aggregations']['malicious_ips']['buckets']:
            ip = bucket['key']
            event_count = bucket['doc_count']
            
            # Skip if below minimum event threshold
            if event_count < self.min_events:
                continue
            
            # Calculate correlation rate
            correlated_count = bucket['correlated_events']['doc_count']
            correlation_rate = correlated_count / event_count if event_count > 0 else 0
            
            # Extract metadata
            first_seen = bucket['first_seen']['value_as_string']
            last_seen = bucket['last_seen']['value_as_string']
            
            targeted_ports = [p['key'] for p in bucket['targeted_ports']['buckets']]
            tools_targeted = [t['key'] for t in bucket['tools_targeted']['buckets']]
            
            asn_number = bucket['asn_number']['buckets'][0]['key'] if bucket['asn_number']['buckets'] else None
            asn_name = bucket['asn_name']['buckets'][0]['key'] if bucket['asn_name']['buckets'] else None
            country = bucket['country']['buckets'][0]['key'] if bucket['country']['buckets'] else None
            
            # Calculate duration in hours
            first_dt = datetime.fromisoformat(first_seen.replace('Z', '+00:00'))
            last_dt = datetime.fromisoformat(last_seen.replace('Z', '+00:00'))
            duration_hours = (last_dt - first_dt).total_seconds() / 3600
            
            # Calculate confidence score
            confidence = self.calculate_confidence(
                event_count=event_count,
                correlation_rate=correlation_rate,
                targeted_ports=targeted_ports,
                duration_hours=duration_hours
            )
            
            # Skip if below confidence threshold
            if confidence < self.confidence_threshold:
                logger.debug(f"Skipping {ip}: confidence {confidence} below threshold {self.confidence_threshold}")
                continue
            
            indicators.append({
                'ip': ip,
                'event_count': event_count,
                'correlated_count': correlated_count,
                'correlation_rate': correlation_rate,
                'first_seen': first_seen,
                'last_seen': last_seen,
                'targeted_ports': targeted_ports,
                'tools_targeted': tools_targeted,
                'asn_number': asn_number,
                'asn_name': asn_name,
                'country': country,
                'duration_hours': duration_hours,
                'confidence': confidence
            })
        
        logger.info(f"Extracted {len(indicators)} indicators from {index_name} (filtered from {response['aggregations']['malicious_ips']['buckets'].__len__()} total IPs)")
        
        return indicators
    
    def _create_indicator_from_ip(self, ip_data: Dict[str, Any], date: datetime) -> Indicator:
        """
        Create STIX Indicator object from IP metadata.
        
        Args:
            ip_data: Dictionary containing IP and metadata
            date: Date of observation
        
        Returns:
            STIX Indicator object
        """
        ip = ip_data['ip']
        
        # Determine primary activity type based on targeted ports
        activity_labels = []
        primary_activity = "malicious-activity"
        
        if 22 in ip_data['targeted_ports']:
            activity_labels.append("ssh-brute-force")
            primary_activity = "SSH Brute Force"
        if 443 in ip_data['targeted_ports']:
            activity_labels.append("https-scanning")
            if primary_activity == "malicious-activity":
                primary_activity = "HTTPS Scanning"
        if 5900 in ip_data['targeted_ports']:
            activity_labels.append("vnc-scanning")
            if primary_activity == "malicious-activity":
                primary_activity = "VNC Scanning"
        if any(p in ip_data['targeted_ports'] for p in [3306, 1433, 5432]):
            activity_labels.append("database-scanning")
            if primary_activity == "malicious-activity":
                primary_activity = "Database Scanning"
        if 5555 in ip_data['targeted_ports']:
            activity_labels.append("adb-exploitation")
            if primary_activity == "malicious-activity":
                primary_activity = "ADB Exploitation"
        
        if not activity_labels:
            activity_labels = ["reconnaissance"]
        
        # Generate indicator name
        name = f"Malicious IP - {primary_activity}"
        
        # Generate description
        port_list = ', '.join(map(str, ip_data['targeted_ports'][:5]))
        if len(ip_data['targeted_ports']) > 5:
            port_list += f" (+{len(ip_data['targeted_ports']) - 5} more)"
        
        description = (
            f"IP observed conducting {primary_activity.lower()} against honeypot infrastructure. "
            f"Activity recorded over {ip_data['duration_hours']:.1f} hours with {ip_data['event_count']} events. "
            f"Targeted ports: {port_list}."
        )
        
        if ip_data['asn_name']:
            description += f" ASN: {ip_data['asn_name']}."
        
        # Create STIX indicator
        indicator = Indicator(
            name=name,
            description=description,
            pattern=f"[ipv4-addr:value = '{ip}']",
            pattern_type="stix",
            pattern_version="2.1",
            valid_from=ip_data['first_seen'],
            valid_until=(datetime.fromisoformat(ip_data['last_seen'].replace('Z', '+00:00')) + timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            labels=activity_labels,
            confidence=ip_data['confidence'],
            created_by_ref=self.identity.id,
            object_marking_refs=[self.tlp_white.id],
            external_references=[
                {
                    "source_name": "honeypot-network",
                    "description": f"Observed in distributed honeypot network on {date.strftime('%Y-%m-%d')}"
                }
            ],
            custom_properties={
                "x_honeypot_metadata": {
                    "event_count": ip_data['event_count'],
                    "correlated_events": ip_data['correlated_count'],
                    "correlation_rate": round(ip_data['correlation_rate'], 3),
                    "first_seen": ip_data['first_seen'],
                    "last_seen": ip_data['last_seen'],
                    "targeted_ports": ip_data['targeted_ports'],
                    "honeypot_tools": ip_data['tools_targeted'],
                    "asn": f"AS{ip_data['asn_number']}" if ip_data['asn_number'] else None,
                    "asn_name": ip_data['asn_name'],
                    "country": ip_data['country'],
                    "duration_hours": round(ip_data['duration_hours'], 2)
                }
            },
            allow_custom=True
        )
        
        return indicator
    
    def generate_daily_feed(
        self,
        date: Optional[datetime] = None,
        output_path: Optional[str] = None
    ) -> Tuple[Bundle, str]:
        """
        Generate daily STIX feed with IOCs from honeypot data.
        
        Creates a STIX 2.1 Bundle containing Indicator objects for all
        malicious IPs observed on the specified date. Includes metadata
        such as event counts, targeted ports, ASN information, and
        confidence scores.
        
        Args:
            date: Date to generate feed for (default: yesterday)
            output_path: Optional file path to save bundle JSON
        
        Returns:
            Tuple of (STIX Bundle object, JSON string)
        
        Example:
            >>> generator = STIXFeedGenerator()
            >>> bundle, json_output = generator.generate_daily_feed()
            >>> print(f"Generated {len(bundle.objects)} STIX objects")
        """
        if date is None:
            date = datetime.utcnow() - timedelta(days=1)
        
        logger.info(f"Generating daily STIX feed for {date.strftime('%Y-%m-%d')}")
        
        # Query indicators from Elasticsearch
        indicators_data = self._query_daily_indicators(date)
        
        # Create STIX objects
        stix_objects = [self.identity, self.tlp_white]
        
        for ip_data in indicators_data:
            indicator = self._create_indicator_from_ip(ip_data, date)
            stix_objects.append(indicator)
        
        # Create STIX bundle with valid UUID
        bundle_uuid = str(uuid4())
        bundle = Bundle(
            id=f"bundle--{bundle_uuid}",
            objects=stix_objects,
            allow_custom=True
        )
        
        # Serialize to JSON
        bundle_json = bundle.serialize(pretty=True)
        
        # Optionally save to file
        if output_path:
            with open(output_path, 'w') as f:
                f.write(bundle_json)
            logger.info(f"Saved daily feed to {output_path}")
        
        logger.info(
            f"Generated daily feed: {len(indicators_data)} indicators, "
            f"{len(bundle.objects)} total STIX objects"
        )
        
        return bundle, bundle_json
    
    def generate_weekly_summary(
        self,
        end_date: Optional[datetime] = None,
        output_path: Optional[str] = None
    ) -> Tuple[Bundle, str]:
        """
        Generate weekly summary STIX feed with campaign intelligence.
        
        Aggregates 7 days of honeypot data to identify campaigns, trending
        attack patterns, and threat actor clusters. Includes top attackers,
        targeted services, and geographic distribution.
        
        Args:
            end_date: End date for 7-day window (default: yesterday)
            output_path: Optional file path to save bundle JSON
        
        Returns:
            Tuple of (STIX Bundle object, JSON string)
        """
        if end_date is None:
            end_date = datetime.utcnow() - timedelta(days=1)
        
        start_date = end_date - timedelta(days=6)
        
        logger.info(
            f"Generating weekly summary for {start_date.strftime('%Y-%m-%d')} "
            f"to {end_date.strftime('%Y-%m-%d')}"
        )
        
        # TODO: Implement weekly aggregation logic
        # This will query 7 days of data and create Campaign objects
        
        stix_objects = [self.identity, self.tlp_white]
        
        bundle = Bundle(
            id=f"bundle--honeypot-weekly-{end_date.strftime('%Y-W%W')}",
            objects=stix_objects
        )
        
        bundle_json = bundle.serialize(pretty=True)
        
        if output_path:
            with open(output_path, 'w') as f:
                f.write(bundle_json)
            logger.info(f"Saved weekly summary to {output_path}")
        
        logger.info(f"Generated weekly summary: {len(bundle.objects)} STIX objects")
        
        return bundle, bundle_json
    
    def generate_malware_catalog(
        self,
        output_path: Optional[str] = None
    ) -> Tuple[Bundle, str]:
        """
        Generate malware catalog with all captured samples.
        
        Queries samples-* indices to create STIX Malware and File objects
        for all captured binaries, including hashes, delivery methods,
        and source information.
        
        Args:
            output_path: Optional file path to save bundle JSON
        
        Returns:
            Tuple of (STIX Bundle object, JSON string)
        """
        logger.info("Generating malware catalog")
        
        # TODO: Implement malware catalog generation
        # Query samples-* indices for captured binaries
        
        stix_objects = [self.identity, self.tlp_white]
        
        bundle = Bundle(
            id=f"bundle--honeypot-malware-catalog",
            objects=stix_objects
        )
        
        bundle_json = bundle.serialize(pretty=True)
        
        if output_path:
            with open(output_path, 'w') as f:
                f.write(bundle_json)
            logger.info(f"Saved malware catalog to {output_path}")
        
        logger.info(f"Generated malware catalog: {len(bundle.objects)} STIX objects")
        
        return bundle, bundle_json


def main():
    """
    Command-line interface for STIX feed generation.
    
    Usage:
        python stix.py --daily --date 2025-12-02 --output /path/to/output.json
        python stix.py --weekly --output /path/to/weekly.json
        python stix.py --malware --output /path/to/malware-catalog.json
    """
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate STIX 2.1 threat intelligence feeds")
    parser.add_argument('--daily', action='store_true', help='Generate daily IOC feed')
    parser.add_argument('--weekly', action='store_true', help='Generate weekly summary')
    parser.add_argument('--malware', action='store_true', help='Generate malware catalog')
    parser.add_argument('--date', type=str, help='Date for daily feed (YYYY-MM-DD), default: yesterday')
    parser.add_argument('--output', type=str, help='Output file path')
    parser.add_argument('--es-host', type=str, default='10.0.3.9', help='Elasticsearch host')
    parser.add_argument('--es-port', type=int, default=9200, help='Elasticsearch port')
    parser.add_argument('--min-events', type=int, default=5, help='Minimum events for indicator')
    parser.add_argument('--confidence', type=int, default=50, help='Minimum confidence threshold')
    
    args = parser.parse_args()
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Initialize generator
    generator = STIXFeedGenerator(
        es_host=args.es_host,
        es_port=args.es_port,
        min_events=args.min_events,
        confidence_threshold=args.confidence
    )
    
    # Parse date if provided
    date = None
    if args.date:
        date = datetime.strptime(args.date, '%Y-%m-%d')
    
    # Generate requested feed
    if args.daily:
        bundle, json_output = generator.generate_daily_feed(date=date, output_path=args.output)
        if not args.output:
            print(json_output)
    elif args.weekly:
        bundle, json_output = generator.generate_weekly_summary(end_date=date, output_path=args.output)
        if not args.output:
            print(json_output)
    elif args.malware:
        bundle, json_output = generator.generate_malware_catalog(output_path=args.output)
        if not args.output:
            print(json_output)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
