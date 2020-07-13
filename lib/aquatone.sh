#!/usr/bin/env bash

EnumAqua (){
	$CAT nmap/ports.xml | $AQUA -nmap -ports xlarge -out aquatone/
}

