#!/usr/bin/env python3
"""
Generate statistics summary for STIX feed repository.

Reads all daily feeds and generates aggregate statistics including:
- Total indicators published
- Average confidence scores
- Top targeted ports
- Geographic distribution
- Temporal trends
"""

import json
import os
from datetime import datetime
from collections import Counter
from pathlib import Path


def generate_stats():
    """Generate summary statistics from daily feeds."""
    
    daily_dir = Path(__file__).parent.parent / "daily"
    
    total_indicators = 0
    confidence_scores = []
    all_ports = []
    countries = []
    asns = []
    labels = []
    
    # Process all daily feed files
    for feed_file in daily_dir.glob("*.json"):
        if feed_file.name == "latest.json":
            continue
        
        try:
            with open(feed_file) as f:
                bundle = json.load(f)
            
            for obj in bundle.get("objects", []):
                if obj.get("type") == "indicator":
                    total_indicators += 1
                    
                    # Collect confidence scores
                    if "confidence" in obj:
                        confidence_scores.append(obj["confidence"])
                    
                    # Collect labels
                    labels.extend(obj.get("labels", []))
                    
                    # Collect custom metadata
                    metadata = obj.get("x_honeypot_metadata", {})
                    all_ports.extend(metadata.get("targeted_ports", []))
                    
                    if metadata.get("country"):
                        countries.append(metadata["country"])
                    
                    if metadata.get("asn_name"):
                        asns.append(metadata["asn_name"])
        
        except Exception as e:
            print(f"Error processing {feed_file}: {e}")
    
    # Calculate statistics
    avg_confidence = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0
    top_ports = Counter(all_ports).most_common(10)
    top_countries = Counter(countries).most_common(10)
    top_asns = Counter(asns).most_common(10)
    top_labels = Counter(labels).most_common(10)
    
    # Create summary
    summary = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "total_indicators": total_indicators,
        "total_feeds": len(list(daily_dir.glob("*.json"))) - 1,  # Exclude latest.json
        "confidence": {
            "average": round(avg_confidence, 2),
            "min": min(confidence_scores) if confidence_scores else 0,
            "max": max(confidence_scores) if confidence_scores else 0
        },
        "top_targeted_ports": [
            {"port": port, "count": count} for port, count in top_ports
        ],
        "top_countries": [
            {"country": country, "count": count} for country, count in top_countries
        ],
        "top_asns": [
            {"asn": asn, "count": count} for asn, count in top_asns
        ],
        "top_activity_types": [
            {"label": label, "count": count} for label, count in top_labels
        ]
    }
    
    # Save to file
    stats_file = Path(__file__).parent.parent / "stats" / "summary.json"
    stats_file.parent.mkdir(exist_ok=True)
    
    with open(stats_file, 'w') as f:
        json.dump(summary, f, indent=2)
    
    print(f"Generated statistics: {total_indicators} indicators across {summary['total_feeds']} feeds")
    print(f"Average confidence: {avg_confidence:.2f}")


if __name__ == "__main__":
    generate_stats()
