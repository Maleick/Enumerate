#!/usr/bin/env bash

EnumCME (){
	$CME smb ports/445 > cme/cme_anon
}

GenListCME (){
	$CME smb ports/445 --gen-relay-list cme/signing.false
}
