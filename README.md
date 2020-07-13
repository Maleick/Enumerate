Enumerate
======

Enumerate all the things!

## Install

```shell
sudo git clone https://github.com/Maleick/Enumerate.git /opt/Enumerate
cd /opt/Enumerate
sudo ./install.sh
```

## Usage

Enumerate requires:
- root privileges
- list of IP addresses
- list of IP exclusions even if it is an empty file

```shell
sudo enumerate iplist.txt exclusions.txt
```

## Depends

Enumerate depends on the following binaries:

- https://github.com/michenriksen/aquatone
- https://github.com/byt3bl33d3r/CrackMapExec
