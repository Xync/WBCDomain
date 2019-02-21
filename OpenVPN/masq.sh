#!/bin/bash

#CONFIG SECTION
IPTABLES="/sbin/iptables"
PATH="/usr/sbin"
IFCONFIG="/sbin/ifconfig"
GREP="/bin/grep"
CUT="/usr/bin/cut"

# The outside address and the network device that supports it.
OUT_DEV="eth0"
OUT_IP=`$IFCONFIG $OUT_DEV | $GREP inet | $CUT -f2 -d: | $CUT -f1 -d" "`

#Internal Devices
#IN_DEV="eth0"
IN_DEV2="tun+"
IN_DEV3="dns+"

#Loopback stuff
LO_NET="127.0.0.0/8"
LO_DEV="lo"

# Anything else
ANYADDR="0/0"

#make sure IP_TABLES modules are there
/sbin/modprobe ip_tables
/sbin/modprobe ip_conntrack
/sbin/modprobe iptable_nat
/sbin/modprobe ipt_MASQUERADE

#first flush all of the rules
$IPTABLES -F
$IPTABLES -t nat -F
$IPTABLES -t filter -F
$IPTABLES -X

#Now set default policies
$IPTABLES -P INPUT ACCEPT
$IPTABLES -P OUTPUT ACCEPT

#Put in Masquerade stuff
#$IPTABLES -A FORWARD -i $IN_DEV -j ACCEPT
$IPTABLES -A FORWARD -i $IN_DEV2 -j ACCEPT
$IPTABLES -A FORWARD -i $IN_DEV3 -j ACCEPT
$IPTABLES -A FORWARD -i $LO_DEV -j ACCEPT

$IPTABLES -A POSTROUTING -t nat -o $OUT_DEV -j MASQUERADE

# We should accept fragments, in $IPTABLES we must do this explicitly.
$IPTABLES -A FORWARD -f -j ACCEPT
$IPTABLES -A INPUT -f -j ACCEPT
$IPTABLES -A OUTPUT -f -j ACCEPT

#Existing Connections
$IPTABLES -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT


#And finally enable forwarding
echo "0" > /proc/sys/net/ipv4/conf/all/rp_filter
echo "1" > /proc/sys/net/ipv4/ip_forward

