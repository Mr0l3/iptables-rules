#!/bin/bash

# Clear all rules
iptables -F

# Changes policy of incoming traffic
iptables -P INPUT DROP

# Allows established traffic
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 

# Allows loopback
iptables -A INPUT -i lo -m comment --comment "Allows loopback" -j ACCEPT

# Allows DNS communication
iptables -A INPUT -p tcp --dport 53 -j ACCEPT
iptables -A INPUT -p udp --dport 53 -j ACCEPT

# Allows DHCP to work
#iptables -A INPUT -p udp --dport 67 -j ACCEPT

# Allows HTTP/HTTPS traffic
iptables -A INPUT -p tcp -m multiport --sports 80,443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT 

# Drops PING requests
iptables -A INPUT -p icmp --icmp-type echo-request -j DROP

# Allows others ICMP packets
iptables -A INPUT -p icmp -j ACCEPT

# Allows communication with a SSH server
iptables -A INPUT -p tcp --sport 22 -j ACCEPT

# Allows ftp, ftps and sftp communication
iptables -A INPUT -p tcp -m multiport --sports 20,21,69,115,989,990 -j ACCEPT

# Allow BitTorrent incoming traffic
iptables -A INPUT -p tcp --destination-port 6881:6999 -m comment --comment "Accepts BitTorrent incoming traffic" -j ACCEPT

# Blocks all outgoing ICMP destination-unreachable
iptables -A OUTPUT -p icmp --icmp-type destination-unreachable -j DROP
