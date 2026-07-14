#!/bin/bash
# Deployment script referenced from GitHub Actions workflow
# This file tests Phase 1.5 reference resolution

set -e

echo "Starting deployment..."

# SHADOW: This script itself contains a shadow dependency!
# This should be detected when the script is scanned via Phase 1.5
curl -fsSL https://get.docker.com | bash

# SHADOW: Another shadow dependency
npm install -g vercel

echo "Deployment complete!"
