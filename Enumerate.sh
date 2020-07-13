#!/usr/bin/env bash
#
# Enumerate.sh Version: 1.2
# Author: Maleick
# Date: 7/13/20

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
echo
echo "$green Enumerating Ports $white"
PortScan
echo
echo "$green Enumerate Ports into Files $white"
python $LIB/NmapParser.py
echo
echo "$green Enumerate CVE $white-$red BG $white"
VulnerScan
echo
echo "$green Enumerate FTP $white-$red BG $white"
EnumFTP
echo
echo "$green Enumerate Anonymous Shares $white-$red BG $white"
EnumCME
echo
echo "$green Enumerate SMB Signing False $white-$red BG $white"
GenListCME
echo
echo "$green Enumerate Metasploit $white-$red BG $white"
EnumMSF
echo
echo "$green Enumerate Webs $white-$red BG $white"
EnumAqua

# Wait for jobs to complete
wait

echo "$red Enumerated!"
