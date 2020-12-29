#!/usr/bin/env bash

PortScan (){
	$NMAP -sSU -Pn -iL $IPLIST -p $PORTS -oA nmap/ports
}

