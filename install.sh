#!/usr/bin/env bash

DIRPATH="/opt/Enumerate"
EXEPATH="/opt/Enumerate/exe"

ln -sf $EXEPATH/aquatone /usr/local/bin
ln -sf $DIRPATH/Enumerate.sh /usr/local/bin/enumerate

echo "aquatone added to path"
echo "enumerate added to path"

