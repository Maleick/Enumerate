#!/usr/bin/env bash
# functions.sh

# Enumerate Hosts
NmapHosts(){
        nmap -sn -iL $IPLIST --excludefile $EXCLUD -oG - | awk '/Up/{print $2}' > hosts
}

# Enumerate Ports
NmapPorts(){
        nmap -sSU -iL hosts -p $PORTS -oA ports -v
}

# Enumerate open ports 
EnumPorts(){
        $MODS/NmapParser.py
}

# Enumerate Anonymous Shares
EnumCME(){
        $MODS/cme smb ports/445 -u '' -p '' --shares | tee cme_anon
}

# Enumerate Anonymous Domain Enumeration
EnumDomain(){
        DEnum='ports/389'
        mkdir DomEnum
        while read -r DEnum; do
        rpcclient -U "" -N -c enumdomusers $DEnum > DomEnum/enumdom$DEnum
done < "$DEnum"
}

# Enumerate FTP
EnumFTP(){
        FTPEnum='ports/21'
        mkdir FTP
        while read -r FTPEnum; do
        curl --connect-timeout 30 ftp://$FTPEnum/ > FTP/ftpscan$FTPEnum
done < "$FTPEnum"
}

# Enumerate with Metasploit
EnumMSF(){
        mkdir logs
        msfconsole -r $MODS/MSFenum.rc
}

# Enumerate the Webs
EnumWeb(){
        mkdir aquatone
        cat ports.xml | $MODS/aquatone -out aquatone/
}
