Enumerate
======

Enumerate all the things!

### Installation
```bash
sudo git clone https://github.com/Maleick/Enumerate.git /opt/Enumerate
```

### Global Usage
```bash
ln -s /opt/Enumerate/Enumerate.sh /usr/local/bin
```

### Usage
Enumerate requires both a iplist (can be CIDR) and exclusions to be fed to it even if it is an empty file.
```bash
/opt/Enumerate.sh iplist.txt exclusions.txt
```

### Thanks
Enumerate uses the following binaries:
- https://github.com/michenriksen/aquatone
- https://github.com/byt3bl33d3r/CrackMapExec
