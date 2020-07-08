#!/usr/bin/env bash

PortScan (){
	$NMAP -sSU -iL $IPLIST --excludefile $EXCLUD -p $PORTS -oA ports -v
}
