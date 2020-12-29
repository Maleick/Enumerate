#!/usr/bin/env bash
#
# Enumerate.sh Version: 1.0
# External Branch
# Author: Maleick
# Date: 12/28/20

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
. $LIB/aquatone.sh
. $LIB/misc.sh

# Usage
if [ $# -eq 0 ]; then
	echo "$red Usage: $0 iplist.txt"
	exit 1
else
	IPLIST=$1
fi

# Make Directories
$MKDIR -p aquatone ftp logs nmap ports

# Call Functions
echo "$green Enumerating Ports $white"
PortScan
echo "$green Enumerate Ports into Files $white"
python $LIB/NmapParser.py
echo "$green Enumerate FTP $white"
EnumFTP
echo "$green Enumerate Metasploit $white"
EnumMSF
echo "$green Enumerate Webs $white"
EnumAqua
echo "$red Enumerated!"
