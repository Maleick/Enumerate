Enumerate
======

Enumerate all the things!

## Install

```shell
sudo git clone https://github.com/Maleick/Enumerate.git /opt/Enumerate
cd /opt/Enumerate
go build -o enumerate
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

## Modules

Enumerate supports the following modules:

- `--all`: Run all modules
- `--nmap-live`: Run a live host discovery with Nmap
- `--scan-ports`: Scan specific ports with Nmap (e.g., Aquatone ports)
- `--metasploit`: Run selected Metasploit auxiliary modules for open ports
- `--aquatone`: Run Aquatone for web screenshots
- `--enum4linux`: Run Enum4Linux for SMB enumeration
- `--netexec`: Run Netexec for SMB enumeration and signing checks
- `--vulners-scan`: Run Nmap with Vulners script for vulnerability detection
- `--nmap-vuln-scan`: Run Nmap with 'vuln' scripts for vulnerability detection
- `--nmap-service-scan`: Run Nmap service-specific scripts on detected services
- `--nikto`: Run Nikto against detected web servers
- `--ftp-anon`: Check for FTP anonymous login
- `--snmp-enum`: Run SNMP enumeration
- `--ssl-tls-checks`: Run SSL/TLS vulnerability checks
- `--open-databases`: Check for open databases (MongoDB, Redis, Elasticsearch)
- `--default-creds`: Check for default credentials on services
- `--ssh-login`: Attempt SSH login on detected hosts
- `--telnet-login`: Attempt Telnet login on detected hosts
- `--ipmi-scan`: Enumerate IPMI services
- `--concurrency`: Set the maximum number of concurrent tasks (default: 5)
- `--target-file`: Path to the file containing target IP addresses or CIDRs
- `--exclude-file`: Path to the file containing IP addresses to exclude from the scan
- `--help`: Show this help menu

## Development

This project is written in Go. To build the project, run:

```shell
go build -o enumerate
```
```

This update includes the new modules and mentions that the project is written in Go.