#!/bin/bash
#
# Daily STIX Feed Generation and Publication
# Runs at 3:00 AM daily via cron
#

set -e  # Exit on error

# Change to repository directory
cd /home/lee/igor/admin/STIX\ feed

# Activate virtual environment
source venv/bin/activate

# Calculate yesterday's date
YESTERDAY=$(date -u -d "yesterday" +%Y-%m-%d)
OUTPUT_FILE="daily/${YESTERDAY}.json"

echo "[$(date -u)] Starting daily STIX feed generation for ${YESTERDAY}"

# Generate daily feed
python3 scripts/generate_feed.py \
    --daily \
    --date ${YESTERDAY} \
    --output ${OUTPUT_FILE} \
    --es-host 192.168.1.100 \
    --es-port 9200 \
    --min-events 25 \
    --confidence 70

if [ $? -eq 0 ]; then
    echo "[$(date -u)] Successfully generated ${OUTPUT_FILE}"
else
    echo "[$(date -u)] ERROR: Failed to generate feed"
    exit 1
fi

# Create/update symlink to latest
cd daily
ln -sf $(basename ${OUTPUT_FILE}) latest.json
cd ..

# Generate statistics
echo "[$(date -u)] Generating statistics..."
python3 scripts/generate_stats.py

# Git operations
echo "[$(date -u)] Committing and pushing to GitHub..."

# Pull latest changes first to avoid conflicts
git fetch origin
if ! git diff --quiet origin/main; then
    echo "[$(date -u)] Remote changes detected, rebasing..."
    git pull --rebase origin main
fi

git add daily/*.json stats/summary.json

if git diff --staged --quiet; then
    echo "[$(date -u)] No changes to commit"
else
    git commit -m "Daily STIX feed update - ${YESTERDAY}

Generated $(jq '.objects | length' ${OUTPUT_FILE}) STIX objects
$(jq '[.objects[] | select(.type=="indicator")] | length' ${OUTPUT_FILE}) indicators published"
    
    # Retry push with rebase if rejected
    if ! git push origin main; then
        echo "[$(date -u)] Push rejected, pulling and retrying..."
        git pull --rebase origin main
        git push origin main
    fi
    
    if [ $? -eq 0 ]; then
        echo "[$(date -u)] Successfully pushed to GitHub"
    else
        echo "[$(date -u)] ERROR: Failed to push to GitHub"
        exit 1
    fi
fi

echo "[$(date -u)] Daily feed generation complete"
