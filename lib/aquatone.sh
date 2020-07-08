#!/usr/bin/env bash

EnumAqua (){
	$CAT ports.xml | $AQUA -nmap -out aquatone/ &
}
