Enumerate
======

Enumerate all the things!

### Installation
```bash
sudo git clone https://github.com/Maleick/Enumerate.git /opt/enumerate
```

### Global Usage
```bash
ln -s /opt/enumerate/enumerate.sh /usr/local/bin
```

### Usage
Enumerate requires both a iplist (can be CIDR) and exclusions to be fed to it even if it is an empty file.
```bash
/opt/enumerate.sh iplist.txt exclusions.txt
```

### Thanks
Enumerate uses the following binaries:
- https://github.com/michenriksen/aquatone
- https://github.com/byt3bl33d3r/CrackMapExec
