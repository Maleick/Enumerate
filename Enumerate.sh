#!/usr/bin/env bash
#
# Enumerate.sh 
# Version: 1.4
# Author: Maleick
# Date: 01/25/21

cat << "EOF"                                                                 

$$$$$$$$\                                                                 $$\               
$$  _____|                                                                $$ |              
$$ |      $$$$$$$\  $$\   $$\ $$$$$$\$$$$\   $$$$$$\   $$$$$$\  $$$$$$\ $$$$$$\    $$$$$$\  
$$$$$\    $$  __$$\ $$ |  $$ |$$  _$$  _$$\ $$  __$$\ $$  __$$\ \____$$\\_$$  _|  $$  __$$\ 
$$  __|   $$ |  $$ |$$ |  $$ |$$ / $$ / $$ |$$$$$$$$ |$$ |  \__|$$$$$$$ | $$ |    $$$$$$$$ |
$$ |      $$ |  $$ |$$ |  $$ |$$ | $$ | $$ |$$   ____|$$ |     $$  __$$ | $$ |$$\ $$   ____|
$$$$$$$$\ $$ |  $$ |\$$$$$$  |$$ | $$ | $$ |\$$$$$$$\ $$ |     \$$$$$$$ | \$$$$  |\$$$$$$$\ 
\________|\__|  \__| \______/ \__| \__| \__| \_______|\__|      \_______|  \____/  \_______|

EOF

# Define Variables

LIB='/opt/Enumerate/lib'
EXE='/opt/Enumerate/exe'

# Import
. $LIB/colors.sh
. $LIB/ports.sh
. $LIB/tools.sh
. $LIB/nmap.sh
. $LIB/cme.sh
. $LIB/aquatone.sh
. $LIB/misc.sh

# Usage
if [ $# -eq 0 ]; then
	echo "$red Usage: $0 iplist.txt exclusions.txt"
	exit 1
else
	IPLIST=$1
	EXCLUD=$2
fi

# Make Directories
$MKDIR -p aquatone cme ftp logs nmap ports

# Call Functions
echo "$green Enumerating Hosts $white"
HostScan
echo "$green Enumerating Ports $white"
PortScan
echo "$green Enumerate Ports into Files $white"
python2 $LIB/NmapParser.py
echo "$green Enumerate FTP $white"
EnumFTP
echo "$green Enumerate Anonymous Shares $white"
EnumCME
echo "$green Enumerate Signing False $white"
GenListCME
echo "$green Enumerate Metasploit $white"
EnumMSF
echo "$green Enumerate Webs $white"
EnumAqua
echo "$green Enumerate Egress Ports $white"
EgadzScan
echo "$red Enumerated!"
