```markdown
# Enumerate

Enumerate all the things!

## Install

To install Enumerate, clone the repository and build the binary:

```shell
sudo git clone https://github.com/Maleick/Enumerate.git /opt/Enumerate
cd /opt/Enumerate
go build -o enumerate
```

Ensure you have [Go](https://golang.org/doc/install) installed on your system.

## Usage

Enumerate requires:
- Root privileges
- A list of IP addresses
- A list of IP exclusions, even if it is an empty file

To run Enumerate, use the following command:

```shell
sudo enumerate iplist.txt exclusions.txt
```

## Dependencies

Enumerate depends on the following binaries:

- [Aquatone](https://github.com/michenriksen/aquatone)

Ensure that you have these dependencies installed and available in your `$PATH`.

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
For development, ensure you have Go installed and set up your environment accordingly. You can refer to the [Go documentation](https://golang.org/doc/) for more details.
