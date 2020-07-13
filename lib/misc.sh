#!/usr/bin/env bash

EnumFTP (){
	FTPEnum='ports/21'
	while read -r FTPEnum; do
	$CURL --connect-timeout 30 ftp://$FTPEnum/ > ftp/ftpscan$FTPEnum 
done < "$FTPEnum"
}

EnumMSF (){
	$MSF -r $LIB/MSFenum.rc
}
