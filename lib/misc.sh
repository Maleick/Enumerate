#!/usr/bin/env bash

EnumDomain (){
	DEnum='ports/389'
	while read -r DEnum; do
	$RPC -U "" -N -c enumdomusers $DEnum > DomEnum/enumdom$DEnum &
done < "$DEnum"
}

EnumFTP (){
	FTPEnum='ports/21'
	while read -r FTPEnum; do
	$CURL --connect-timeout 30 ftp://$FTPEnum/ > FTP/ftpscan$FTPEnum &
done < "$FTPEnum"
}

EnumMSF (){
	$MSF -r $LIB/MSFenum.rc &
}
