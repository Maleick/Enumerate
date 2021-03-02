#!/usr/bin/env bash

EnumCME (){
	$CME smb ports/445 | $TEE cme/cme_enum
}

GenListCME (){
	$CME smb ports/445 --gen-relay-list cme/signing.false
}
