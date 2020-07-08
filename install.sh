#!/usr/bin/env bash

git clone https://github.com/Maleick/Enumerate.git /opt/Enumerate

DIRPATH="/opt/Enumerate"
EXEPATH="/opt/Enumerate/exe"

ln -sf $EXEPATH/aquatone /usr/local/bin
ln -sf $EXEPATH/cme /usr/local/bin
ln -sf $DIRPATH/Enumerate.sh /usr/local/bin/enumerate

echo "aquatone added to path"
echo "crackmapexec added to path"
echo "enumerate added to path"

