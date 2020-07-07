#!/usr/bin/env bash
#
# Enumerate.sh Version: 1.01
# Author: Maleick
# Date: 7/7/20

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

# Import Variables
source /opt/enumerate/lib/variables.sh  
source /opt/enumerate/lib/functions.sh

# Help Text
if [ $# -eq 0 ]; then
	echo "${RED}Usage: $0 iplist.txt exclusions.txt"
	exit 1
else
	IPLIST=$1
	EXCLUD=$2
fi

	echo "${YELLOW}Enumerate Hosts"
NmapHosts
wait
	echo "${GREEN}Enumerate Ports"
NmapPorts
wait
	echo "${RED}Enumerate Ports"
EnumPorts
wait
# Threading
	echo "${GREEN}Enumerate Anonymous Shares"
EnumCME &
P1=$!
	echo "${YELLOW}Emumerate Null Sessions"
EnumDomain &
P2=$!
	echo "${RED}Enumerate FTP"
EnumFTP &
P3=$!
	echo "${GREEN}Enumerate Metasploit Auxiliary"
EnumMSF &
P4=$!
	echo "${YELLOW}Enumerate the Webs"
EnumWeb &
P5=$!

wait $P1 $P2 $P3 $P4 $P5

echo "${RED}Finn!"
