#!/bin/bash
# QEMU Setup Script for Linux/WSL
# Installs QEMU system emulators and utilities via apt

set -e

echo "Installing QEMU for Linux/WSL..."

# Update package list
sudo apt update

# Install QEMU packages
sudo apt install -y qemu-system-x86 qemu-system-arm qemu-utils

# Optional: Install Docker if needed for VM containerization
echo "Optional: Install Docker (uncomment next line if needed)"
# sudo apt install -y docker.io
# sudo systemctl start docker
# sudo usermod -aG docker $USER

echo "QEMU installation complete."
echo "Run 'qemu-system-x86_64 --version' to verify."
echo "Make the script executable: chmod +x scripts/qemu/setup.sh"