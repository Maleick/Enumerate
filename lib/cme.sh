#!/usr/bin/env bash

EnumCME (){
	$CME smb ports/445 -u '' -p '' --shares > cme/cme_anon
}

GenListCME (){
	$CME smb ports/445 --gen-relay-list cme/signing.false
}
