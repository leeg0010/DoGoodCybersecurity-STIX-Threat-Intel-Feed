#!/bin/bash
# Setup Git credential storage for automated STIX feed pushes
# Run this once to configure authentication

echo "=== GitHub Credential Setup for STIX Feed ==="
echo ""
echo "You need a GitHub Personal Access Token with 'repo' scope."
echo "Create one at: https://github.com/settings/tokens"
echo ""
echo "Token scopes required:"
echo "  ✓ repo (Full control of private repositories)"
echo ""
read -p "Press Enter to continue or Ctrl+C to exit..."
echo ""

read -p "Enter your GitHub username (leeg0010): " GH_USERNAME
GH_USERNAME=${GH_USERNAME:-leeg0010}

read -sp "Enter your GitHub Personal Access Token: " GH_TOKEN
echo ""

# Store credentials in ~/.git-credentials
echo "https://${GH_USERNAME}:${GH_TOKEN}@github.com" > ~/.git-credentials
chmod 600 ~/.git-credentials

# Configure git to use credential store globally
git config --global credential.helper store

echo ""
echo "✓ Credentials stored in ~/.git-credentials (secure)"
echo "✓ Git configured to use credential helper"
echo ""
echo "Testing authentication..."

cd "/home/lee/igor/admin/STIX feed"
git ls-remote origin HEAD >/dev/null 2>&1

if [ $? -eq 0 ]; then
    echo "✓ Authentication successful!"
    echo ""
    echo "Your cron job will now push automatically."
else
    echo "✗ Authentication failed. Please check your token."
    rm ~/.git-credentials
    exit 1
fi
