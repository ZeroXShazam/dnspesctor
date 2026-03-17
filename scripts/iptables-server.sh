#!/bin/bash
# iptables rules for rust-dns SERVER (run as root on the VPS).
# Allows: loopback, established/related, SSH, and UDP 53/5353 for the tunnel.
#
# IMPORTANT: Open a second SSH session to the server before running. If you
# lock yourself out, you can fix from the host's console (e.g. Cherry Servers).

set -e

# Use these tables (IPv4). For IPv6 duplicate with ip6tables if needed.
IPTABLES="${IPTABLES:-iptables}"

# Optional: restrict DNS to your client IP(s). Uncomment and set.
# CLIENT_IP="1.2.3.4"
# Then use -s "$CLIENT_IP" in the UDP rules below.

echo "Setting iptables rules for rust-dns server..."

# Allow loopback
$IPTABLES -A INPUT -i lo -j ACCEPT

# Allow established and related (return traffic)
$IPTABLES -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow SSH (do this early so you don't lock yourself out)
$IPTABLES -A INPUT -p tcp --dport 22 -j ACCEPT

# Allow UDP 53 (DNS) — for rust-dns server on port 53
$IPTABLES -A INPUT -p udp --dport 53 -j ACCEPT

# Allow UDP 5353 — if you run rust-dns on 5353 instead (e.g. to avoid conflict with system DNS)
$IPTABLES -A INPUT -p udp --dport 5353 -j ACCEPT

# Optional: set default policy to DROP (uncomment only if you want a strict firewall)
# $IPTABLES -P INPUT DROP

echo "Done. Current INPUT chain (top):"
$IPTABLES -L INPUT -v -n | head -20

echo ""
echo "To make rules persistent (Debian/Ubuntu):"
echo "  iptables-save | sudo tee /etc/iptables/rules.v4"
echo "  # or: sudo netfilter-persistent save"
echo ""
echo "To restrict UDP 53/5353 to a specific client IP, edit this script and set CLIENT_IP,"
echo "then use: \$IPTABLES -A INPUT -p udp --dport 53 -s \$CLIENT_IP -j ACCEPT"
