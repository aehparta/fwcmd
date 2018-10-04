#!/bin/bash

### BEGIN INIT INFO
# Provides:             fwcmd
# Required-Start:       $network
# Required-Stop:
# Default-Start:        2 3 4 5
# Default-Stop:         0 1 6
# Short-Description:    Basic firewall
# Description:          Basic firewall
### END INIT INFO

# Author: Antti Partanen <aehparta@iki.fi>

DESC="Basic firewall"

#################################################
#################################################
# NOTE: Usually don't touch anything here       #
# rather modify /etc/fwcmd-rules.conf           #
#################################################
#################################################

# some defaults
WAN=""
LAN=""
TRUSTED=""
SSH=1
NAT=0

# rules
RULES=()

# commands
IPTABLES=/sbin/iptables
IFCONFIG=/sbin/ifconfig

# files
CONF="/etc/fwcmd-rules.conf"
if [ "$1" != "" ]; then
	CONF="$1"
fi

# critical error
crit()
{
	echo "$@" 1>&2;
	exit 1
}

# validate ip
valid_ip()
{
	local ip
	local mask
	local stat=1

	ip=${1%/*}
	mask=${1##*/}
	if [ "$mask" != "$ip" ]; then
		if [ "$mask" -lt "0" ]; then
			return 1
		elif [ "$mask" -gt "32" ]; then
			return 1
		fi
	fi

	if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
		OIFS=$IFS
		IFS='.'
		ip=($ip)
		IFS=$OIFS
		[[ ${ip[0]} -le 255 && ${ip[1]} -le 255 \
		    && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
		stat=$?
	fi

	return $stat
}

# parse single rule
parse_single_rule()
{
	local rule=""
	local proto=""
	local src=""
	local dst=""
	local src_ip=""
	local src_port=""
	local dst_ip=""
	local dst_port=""
	local i=0

	# check optional proto
	proto=${2%% *}
	if [ "$proto" == "icmp" ] || [ "$proto" == "tcp" ] || [ "$proto" == "udp" ]; then
		rule="-p $proto"
	else
		proto=""
		i=1
	fi

	for x in $2; do
		if [ "$i" -eq "1" ]; then
			src="$x"
		elif [ "$i" -eq "2" ]; then
			dst="$x"
		fi
		i=$((i+1))
	done

	# check source
	if [ "$src" != "" ]; then
		ip_not=""
		port_not=""
		src_ip=${src%:*}
		src_port=${src##*:}
		if [ "${src_ip:0:1}" == "!" ]; then
			ip_not="!"
			src_ip=${src_ip:1}
		fi
		if [ "${src_port:0:1}" == "!" ]; then
			port_not="!"
			src_port=${src_port:1}
		fi
		if [ "$src_ip" != "$src_port" ]; then
			if [ "$proto" == "icmp" ] || [ "$proto" == "" ]; then
				crit "Port not allowed for this kind of rule: $1 $2"
			elif [ "$src_port" -lt "1" ]; then
				crit "Invalid source port for rule: $1 $2"
			elif [ "$src_port" -gt "65535" ]; then
				crit "Invalid source port for rule: $1 $2"
			fi
			rule="$rule --sport $src_port"
		fi
		if [ "$src_ip" == "any" ]; then
			src_ip="0.0.0.0/0"
		elif ! valid_ip $src_ip; then
			crit "Invalid source address for rule: $1 $2"
		fi
		rule="$rule -s $src_ip"
	fi

	# check destination
	if [ "$dst" != "" ]; then
		ip_not=""
		port_not=""
		dst_ip=${dst%:*}
		dst_port=${dst##*:}
		if [ "${dst_ip:0:1}" == "!" ]; then
			ip_not="!"
			dst_ip=${dst_ip:1}
		fi
		if [ "${dst_port:0:1}" == "!" ]; then
			port_not="!"
			dst_port=${dst_port:1}
		fi
		if [ "$dst_ip" != "$dst_port" ]; then
			if [ "$proto" == "icmp" ] || [ "$proto" == "" ]; then
				crit "Port not allowed for this kind of rule: $1 $2"
			elif [ "$dst_port" -lt "1" ]; then
				crit "Invalid destination port for rule: $1 $2"
			elif [ "$dst_port" -gt "65535" ]; then
				crit "Invalid destination port for rule: $1 $2"
			fi
			rule="$rule $port_not --dport $dst_port"
		fi
		if [ "$dst_ip" == "any" ]; then
			dst_ip="0.0.0.0/0"
		elif ! valid_ip $dst_ip; then
			crit "Invalid destination address for rule: $1 $2"
		fi
		rule="$rule $ip_not -d $dst_ip"
	fi

	# add target
	if [ "$1" == "drop" ]; then
		rule="-A INPUT $rule -j DROP"
	elif [ "$1" == "accept" ]; then
		rule="-A INPUT $rule -j ACCEPT"
	else
		crit "Invalid rule: $1 $2"
	fi

	RULES+=("$rule")
}

# parse rules
do_parse()
{
	echo "Reading rules from $CONF"
	if [ ! -f "$CONF" ]; then
		crit "Configuration is missing"
	fi

	# parse rules file
	while read line; do
		if [ "${#line}" -lt "1" ]; then
		    continue
		fi
		if [ "${line:0:1}" == "#" ]; then
		    continue
		fi

		# separate command and argument(s)
		command=${line%% *}
		args=${line#* }
		# trim leading spaces from arguments
		args=${args#"${args%%[![:space:]]*}"}

		if [ "$command" == "wan" ]; then
			WAN="$args"
		elif [ "$command" == "lan" ]; then
			LAN="$args"
		elif [ "$command" == "trust" ]; then
			TRUSTED="$TRUSTED $args"
		elif [ "$command" == "nossh" ]; then
			SSH=0
		elif [ "$command" == "nat" ]; then
			NAT=1
		elif [ "$command" == "drop" ]; then
			parse_single_rule "$command" "$args"
		elif [ "$command" == "accept" ]; then
			parse_single_rule "$command" "$args"
		fi
	done < $CONF

	# check interfaces
	$IFCONFIG "$WAN" &> /dev/null
	if [ "$?" != "0" ]; then
		crit "WAN interface is invalid"
	fi
	if [ "$LAN" != "" ]; then
		$IFCONFIG "$LAN" &> /dev/null
		if [ "$?" != "0" ]; then
			crit "LAN interface is invalid"
		fi
	fi
	# check trusted ips
	for ip in $TRUSTED; do
		if ! valid_ip $ip; then
			crit "Trusted ip $ip is not valid"
		fi
	done
}

# setup firewall
do_start()
{
	echo "Setup firewall"

	# parse rules file
	do_parse

	# set default rules
	$IPTABLES -P INPUT DROP
	$IPTABLES -P FORWARD DROP
	$IPTABLES -P OUTPUT ACCEPT

	# clear all tables
	$IPTABLES -F -t filter
	$IPTABLES -F -t nat
	$IPTABLES -F -t mangle
	$IPTABLES -F -t raw

	# add rules
	for i in ${!RULES[*]}; do
		echo ${RULES[$i]}
		$IPTABLES ${RULES[$i]}
	done

	# accept icmp (if not blocked in rules)
	$IPTABLES -A INPUT -p icmp -j ACCEPT

	# accept all from local networks
	$IPTABLES -I INPUT -i lo -j ACCEPT
	if [ "$LAN" != "" ]; then
		$IPTABLES -I INPUT -i $LAN -j ACCEPT
	fi

	# accept all from trusted
	for ip in $TRUSTED; do
		$IPTABLES -I INPUT -s $ip -j ACCEPT
	done

	# always accept ssh if not specifically disabled
	if [ "$SSH" != "0" ]; then
		$IPTABLES -I INPUT -p tcp --dport ssh -j ACCEPT
	fi

	# always accept open connections
	$IPTABLES -I INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
	$IPTABLES -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT

	#################################################
	#################################################
	# CUSTOM ########################################
	#################################################
	#################################################

	if [ "$NAT" == "1" ]; then
		# enable forwarding
		echo 1 > /proc/sys/net/ipv4/ip_forward
		# enable nat
		$IPTABLES -t nat -A POSTROUTING -o $WAN -j MASQUERADE
		# add LAN interface forward
		if [ "$LAN" != "" ]; then
			$IPTABLES -A FORWARD -i $LAN -j ACCEPT
		fi
	fi

	#################################################
	# END CUSTOM ####################################
	#################################################

	# deny anything else
	#$IPTABLES -A INPUT -p tcp -j DROP
	#$IPTABLES -A INPUT -p udp --dport 0:1024 -j DROP
	#$IPTABLES -A FORWARD -p tcp -j DROP
	#$IPTABLES -A FORWARD -p udp --dport 0:1024 -j DROP

	echo "Firewall up"
}
# end setup firewall

do_start
