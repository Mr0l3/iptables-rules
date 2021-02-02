#!/bin/bash

#######################
#                     #
#    INITIAL SETUP    #
#	              #
#######################

# Clear all rules
iptables -F

# Change policy of incoming traffic
iptables -P INPUT DROP

# Allow established traffic
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 

# Allow loopback
iptables -A INPUT -i lo -m comment --comment "Allows loopback" -j ACCEPT

#######################
#                     #
# RULES FOR NMAP SCAN #
#	              #
#######################

## Block fragmented packets
iptables -A INPUT -f -m comment --comment "Drop fragmented packets"  -j DROP 

## Create an 1 hour ban blacklist
## Attacker has to be quiet for 1 hour to be removed from blacklist
# Path to blacklist: /proc/net/xt_recent/blacklist_3600
iptables -A INPUT -m recent --name blacklist_3600 --update --seconds 3600 -m comment --comment "Drop packet from IP inserted in blacklist last 3600 sec (1 hour)" -j DROP

## Null Scan
# Log Attack
iptables -A INPUT -p tcp --tcp-flags ALL NONE -m limit --limit 3/m --limit-burst 5 -j LOG --log-prefix "Firewall> Null scan "

# Drops and blacklists IP of attacker for 1 hour 
iptables -A INPUT -p tcp --tcp-flags ALL NONE -m recent --name blacklist_3600 --set -m comment --comment "Drop/Blacklist Null scan" -j DROP

## Xmas Scan
# Log Attacks
iptables -A INPUT -p tcp --tcp-flags ALL FIN,PSH,URG -m limit --limit 3/m --limit-burst 5 -j LOG --log-prefix "Firewall> XMAS scan "
iptables -A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -m limit --limit 3/m --limit-burst 5 -j LOG --log-prefix "Firewall> XMAS-PSH scan "
iptables -A INPUT -p tcp --tcp-flags ALL ALL -m limit --limit 3/m --limit-burst 5 -j LOG --log-prefix "Firewall> XMAS-ALL scan "

# Drop and blacklist IP of attacker for 1 hour
iptables -A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -m recent --name blacklist_3600 --set  -m comment --comment "Drop/Blacklist Xmas/PSH scan" -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL FIN,PSH,URG -m recent --name blacklist_3600 --set -m comment --comment "Drop/Blacklist Xmas scan" -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL ALL -m recent --name blacklist_3600 --set -m comment --comment "Drop/Blacklist Xmas/All scan" -j DROP

## FIN scan
# Log Attacks
iptables -A INPUT -p tcp --tcp-flags ALL FIN -m limit --limit 3/m --limit-burst 5 -j LOG --log-prefix "Firewall> FIN scan "

# Drop and blacklist IP of attacker for 1 hour
iptables -A INPUT -p tcp --tcp-flags ALL FIN -m recent --name blacklist_3600 --set -m comment --comment "Drop/Blacklist FIN scan" -j DROP

## ACK scan
# Log Attacks
iptables -A INPUT -p tcp ! --syn -m state --state NEW -m limit --limit 3/m --limit-burst 5 -j LOG --log-prefix "Firewall> ACK scan "

# Drop and blacklist IP of attacker for 1 hour
iptables -A INPUT -p tcp ! --syn -m state --state NEW -m comment --comment "Drop TCP connection not starting by SYN" -j DROP

## SYN scan
# We use trap ports to detect scan
# Log Attacks
iptables -A INPUT -p tcp  -m multiport --dports 23,79 --tcp-flags ALL SYN -m limit --limit 3/m --limit-burst 5 -j LOG --log-prefix "Firewall>SYN scan trap:" 

# Drop and blacklist IP of attacker for 1 hour
iptables -A  INPUT -p tcp  -m multiport --dports 23,79 --tcp-flags ALL SYN -m recent --name blacklist_3600 --set -j DROP

## UDP scan
# We look for the behavior of sending UDP packets with no content, just header
# Log Attacks
iptables -A INPUT -p udp  -m limit --limit 6/h --limit-burst 1 -m length --length 0:28 -j LOG --log-prefix "Firewall>0 length udp "

# Drop and blacklist IP of attacker for 1 hour
iptables -A INPUT -p udp -m length --length 0:28 -m recent --name blacklist_3600 --set -m comment --comment "Drop UDP packet with no content" -j DROP


#######################
#                     #
#   STANDARD TRAFFIC  #
#	              #
#######################

# Allow HTTP/HTTPS traffic
iptables -A INPUT -p tcp -m multiport --sports 80,443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT 

# Drops PING requests
iptables -A INPUT -p icmp --icmp-type echo-request -j DROP

# Allow others ICMP packets
iptables -A INPUT -p icmp -j ACCEPT

# Allow communication with a SSH server
iptables -A INPUT -p tcp --sport 22 -j ACCEPT

# Allow ftp, ftps and sftp communication
iptables -A INPUT -p tcp -m multiport --sports 20,21,69,115,989,990 -j ACCEPT

# Allow BitTorrent incoming traffic
iptables -A INPUT -p tcp --destination-port 6881:6999 -m comment --comment "Accepts BitTorrent incoming traffic" -j ACCEPT

# Block all outgoing ICMP destination-unreachable
iptables -A OUTPUT -p icmp --icmp-type destination-unreachable -j DROP

