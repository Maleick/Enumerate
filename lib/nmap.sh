#!/usr/bin/env bash

HostScan (){
	$NMAP -sn -iL $IPLIST --excludefile $EXCLUD -oG - | awk '/Up/{print $2}' > nmap/hosts.nmap
}

PortScan (){
	$NMAP -sSU -iL nmap/hosts.nmap -p $PORTS -oA nmap/ports
}

VulnerScan (){
	$NMAP -sV -iL nmap/hosts.nmap --script vulners --script-args mincvss=5.0 -oA nmap/vulners
}
