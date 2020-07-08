Enumerate
======

Enumerate all the things!

### Install

You can install this via the command-line with either `curl` or `wget`, whichever is installed on your machine.

#### via curl

```shell
sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"
```

#### via wget

```shell
sh -c "$(wget -O- https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"
```

### Usage

Enumerate requires root, iplist (can be CIDR), and exclusions to be fed to it even if it is an empty file.

```shell
sudo enumerate iplist.txt exclusions.txt
```

### Special thanks to these folks

Enumerate uses the following binaries:

- https://github.com/michenriksen/aquatone
- https://github.com/byt3bl33d3r/CrackMapExec
