// Enumerate v1.0.0 - Penetration Testing Enumeration Script
// Developed by Michael Miles (Improved by OpenAI Assistant)
// Rewritten in Go

package main

import (
	"bufio"
	"encoding/xml"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ASCII Banner
func displayBanner() {
	banner := `
$$$$$$$$\                                                                 $$\               
$$  _____|                                                                $$ |              
$$ |      $$$$$$$\  $$\   $$\ $$$$$$\$$$$\   $$$$$$\   $$$$$$\  $$$$$$\ $$$$$$\    $$$$$$\  
$$$$$\    $$  __$$\ $$ |  $$ |$$  _$$  _$$\ $$  __$$\ $$  __$$\ \____$$\\_$$  _|  $$  __$$\ 
$$  __|   $$ |  $$ |$$ |  $$ |$$ / $$ / $$ |$$$$$$$$ |$$ |  \__|$$$$$$$ | $$ |    $$$$$$$$ |
$$ |      $$ |  $$ |$$ |  $$ |$$ | $$ | $$ |$$   ____|$$ |     $$  __$$ | $$ |$$\ $$   ____|
$$$$$$$$\ $$ |  $$ |\$$$$$$  |$$ | $$ | $$ |\$$$$$$$\ $$ |     \$$$$$$$ | \$$$$  |\$$$$$$$\ 
\________|\__|  \__| \______/ \__| \__| \__| \_______|\__|      \_______|  \____/  \_______|
                                                                                              
    `
	fmt.Println(banner)
}

// Help Menu
func displayHelp() {
	helpText := `
Usage: ./enumerate [options]

Options:
  --nmap-live         : Run a live host discovery with Nmap
  --scan-ports        : Scan specific ports with Nmap (e.g., Aquatone ports)
  --metasploit        : Run selected Metasploit auxiliary modules for open ports
  --aquatone          : Run Aquatone for web screenshots
  --enum4linux        : Run Enum4Linux for SMB enumeration
  --netexec           : Run Netexec for SMB enumeration and signing checks
  --vulners-scan      : Run Nmap with Vulners script for vulnerability detection
  --nmap-vuln-scan    : Run Nmap with 'vuln' scripts for vulnerability detection
  --nmap-service-scan : Run Nmap service-specific scripts on detected services
  --nikto             : Run Nikto against detected web servers
  --ftp-anon          : Check for FTP anonymous login
  --snmp-enum         : Run SNMP enumeration
  --ssl-tls-checks    : Run SSL/TLS vulnerability checks
  --open-databases    : Check for open databases (MongoDB, Redis, Elasticsearch)
  --default-creds     : Check for default credentials on services
  --ssh-login         : Attempt SSH login on detected hosts
  --telnet-login      : Attempt Telnet login on detected hosts
  --ipmi-scan         : Enumerate IPMI services
  --all               : Run all the above scripts sequentially
  --help, -h          : Show this help menu
    `
	fmt.Println(helpText)
}

// Function to Run Live Host Discovery with Nmap
func nmapLive(targetFile, excludeFile string) {
	if _, err := os.Stat(excludeFile); os.IsNotExist(err) {
		fmt.Printf("[WARNING] Exclusion file '%s' not found. Creating an empty exclusion file.\n", excludeFile)
		os.Create(excludeFile)
	}
	proceed := getUserInput("[PROMPT] Proceed with the scan using the provided files? (yes/no): ")
	if strings.ToLower(proceed) != "yes" {
		fmt.Println("[INFO] Scan aborted by user.")
		return
	}

	fmt.Println("\n[INFO] Running Nmap for live host discovery...")
	cmd := exec.Command("nmap", "-sn", "-iL", targetFile, "--excludefile", excludeFile, "-oA", "nmap/live_hosts")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
}

// Function to Scan Specific Ports with Nmap (e.g., Aquatone Ports)
func scanPorts(targetFile, excludeFile string) {
	if _, err := os.Stat(excludeFile); os.IsNotExist(err) {
		fmt.Printf("[WARNING] Exclusion file '%s' not found. Creating an empty exclusion file.\n", excludeFile)
		os.Create(excludeFile)
	}
	proceed := getUserInput("[PROMPT] Proceed with the port scan using the provided files? (yes/no): ")
	if strings.ToLower(proceed) != "yes" {
		fmt.Println("[INFO] Port scan aborted by user.")
		return
	}

	fmt.Println("\n[INFO] Scanning specific ports with Nmap...")
	ports := "U:111,161,623,T:21,22,23,25,53,80,81,88,135,137,139,300,443,445,591,593,832,981,1010,1311,1433,2082,2087,2095,2096,2480,3000,3128,3306,3333,3389,4243,4567,4711,4712,4993,5000,5104,5108,5432,5800,5900,5985,5986,6543,7000,7396,7474,8000,8001,8008,8014,8042,8069,8080,8081,8088,8090,8091,8118,8123,8172,8222,8243,8280,8281,8333,8443,8500,8834,8880,8888,8983,9000,9043,9060,9080,9090,9091,9200,9443,9800,9981,12443,16080,18091,18092,20720,28017,49751,50911"
	nmapOutputPrefix := "nmap/ports"
	cmd := exec.Command("nmap", "-sSU", "-iL", targetFile, "--excludefile", excludeFile, "-p", ports, "-oA", nmapOutputPrefix)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()

	parseNmapOutput(nmapOutputPrefix + ".xml")
}

// Function to Parse Nmap XML Output
func parseNmapOutput(nmapXMLFile string) {
	fmt.Println("\n[INFO] Parsing Nmap XML output and generating 'ports/PORT_NUMBER' files...")

	xmlFile, err := os.Open(nmapXMLFile)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer xmlFile.Close()

	byteValue, _ := ioutil.ReadAll(xmlFile)
	var nmapRun NmapRun
	xml.Unmarshal(byteValue, &nmapRun)

	portsDir := "ports"
	if _, err := os.Stat(portsDir); os.IsNotExist(err) {
		os.Mkdir(portsDir, 0755)
	}

	portFiles := make(map[string]*os.File)

	for _, host := range nmapRun.Hosts {
		addr := host.Address.Addr
		for _, port := range host.Ports.Port {
			if port.State.State != "open" {
				continue
			}
			portNumber := port.PortID
			portFile := filepath.Join(portsDir, portNumber)
			if _, exists := portFiles[portFile]; !exists {
				f, _ := os.OpenFile(portFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
				portFiles[portFile] = f
			}
			portFiles[portFile].WriteString(addr + "\n")
		}
	}

	for _, file := range portFiles {
		file.Close()
	}
}

// Nmap XML Structs
type NmapRun struct {
	XMLName xml.Name `xml:"nmaprun"`
	Hosts   []Host   `xml:"host"`
}

type Host struct {
	Address Address `xml:"address"`
	Ports   Ports   `xml:"ports"`
}

type Address struct {
	Addr string `xml:"addr,attr"`
}

type Ports struct {
	Port []Port `xml:"port"`
}

type Port struct {
	PortID string `xml:"portid,attr"`
	State  State  `xml:"state"`
}

type State struct {
	State string `xml:"state,attr"`
}

// Function to Run Metasploit Modules
func metasploitModules() {
	fmt.Println("\n[INFO] Running selected Metasploit auxiliary modules...")
	modules := []string{
		"auxiliary/scanner/ssh/ssh_login",
		"auxiliary/scanner/telnet/telnet_login",
		"auxiliary/scanner/ipmi/ipmi_dumphashes",
		"auxiliary/scanner/ipmi/ipmi_version",
		"auxiliary/scanner/smb/smb_enum_shares",
		"auxiliary/scanner/smb/smb_enum_users",
	}

	for _, module := range modules {
		var cmd *exec.Cmd
		if module == "auxiliary/scanner/ssh/ssh_login" {
			cmd = exec.Command("msfconsole", "-q", "-x", fmt.Sprintf("use %s; set RHOSTS file:ports/22; set USERNAME root; set PASSWORD password; run; exit;", module))
		} else if module == "auxiliary/scanner/telnet/telnet_login" {
			cmd = exec.Command("msfconsole", "-q", "-x", fmt.Sprintf("use %s; set RHOSTS file:ports/23; set USERNAME admin; set PASSWORD admin; run; exit;", module))
		} else if module == "auxiliary/scanner/ipmi/ipmi_dumphashes" {
			cmd = exec.Command("msfconsole", "-q", "-x", fmt.Sprintf("use %s; set RHOSTS file:ports/623; run; exit;", module))
		} else {
			cmd = exec.Command("msfconsole", "-q", "-x", fmt.Sprintf("use %s; set RHOSTS file:ports/445; run; exit;", module))
		}
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Run()
	}
}

// Function to Run Aquatone
func runAquatone() {
	fmt.Println("\n[INFO] Running Aquatone for web screenshots...")
	cmd := exec.Command("aquatone", "-nmap", "nmap/ports.xml", "-ports", "xlarge", "-out", "aquatone/reports")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
}

// Function to Run Enum4Linux for SMB Enumeration
func runEnum4linux() {
	fmt.Println("\n[INFO] Running Enum4Linux for SMB enumeration...")
	if _, err := os.Stat("ports/445"); os.IsNotExist(err) {
		fmt.Println("[WARNING] No hosts with port 445 open found.")
		return
	}
	ips := readLines("ports/445")
	for _, ip := range ips {
		outputFile := fmt.Sprintf("logs/enum4linux_%s.log", ip)
		cmd := exec.Command("enum4linux", "-a", ip)
		output, _ := cmd.CombinedOutput()
		ioutil.WriteFile(outputFile, output, 0644)
	}
}

// Function to Run Netexec
func runNetexec() {
	fmt.Println("\n[INFO] Running Netexec for SMB signing checks, null shares, and null user enumeration...")
	if _, err := os.Stat("ports/445"); os.IsNotExist(err) {
		fmt.Println("[WARNING] No hosts with port 445 open found.")
		return
	}
	cmd := exec.Command("netexec", "-f", "ports/445", "-o", "logs/netexec_output.txt")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
}

// Function to Run Nmap with Vulners Script
func vulnersScan(targetFile, excludeFile string) {
	if _, err := os.Stat(excludeFile); os.IsNotExist(err) {
		fmt.Printf("[WARNING] Exclusion file '%s' not found. Creating an empty exclusion file.\n", excludeFile)
		os.Create(excludeFile)
	}
	proceed := getUserInput("[PROMPT] Proceed with the Vulners scan using the provided files? (yes/no): ")
	if strings.ToLower(proceed) != "yes" {
		fmt.Println("[INFO] Vulners scan aborted by user.")
		return
	}

	fmt.Println("\n[INFO] Running Nmap with Vulners script for vulnerability detection...")
	cmd := exec.Command("nmap", "-sV", "--script", "vulners", "-iL", targetFile, "--excludefile", excludeFile, "-oA", "nmap/vulners_scan")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
}

// Function to Run Nmap with 'vuln' Scripts
func nmapVulnScan(targetFile, excludeFile string) {
	if _, err := os.Stat(excludeFile); os.IsNotExist(err) {
		fmt.Printf("[WARNING] Exclusion file '%s' not found. Creating an empty exclusion file.\n", excludeFile)
		os.Create(excludeFile)
	}
	proceed := getUserInput("[PROMPT] Proceed with the Nmap 'vuln' scripts scan using the provided files? (yes/no): ")
	if strings.ToLower(proceed) != "yes" {
		fmt.Println("[INFO] Nmap 'vuln' scripts scan aborted by user.")
		return
	}

	fmt.Println("\n[INFO] Running Nmap with 'vuln' scripts for vulnerability detection...")
	outputPrefix := "nmap/nmap_vuln_scripts_scan"
	cmd := exec.Command("nmap", "-sV", "--script", "vuln", "-iL", targetFile, "--excludefile", excludeFile, "-oA", outputPrefix)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
}

// Function to Run Nmap Service-Specific Scripts
func nmapServiceScan() {
	fmt.Println("\n[INFO] Running Nmap service-specific scripts on detected services...")
	portsDir := "ports"
	if _, err := os.Stat(portsDir); os.IsNotExist(err) {
		fmt.Println("[WARNING] Ports directory not found. Run port scans first.")
		return
	}

	portFiles, _ := ioutil.ReadDir(portsDir)

	for _, portFile := range portFiles {
		port := portFile.Name()
		ips := readLines(filepath.Join(portsDir, port))
		for _, ip := range ips {
			var nmapScripts []string
			switch port {
			case "21":
				nmapScripts = []string{"ftp-anon", "ftp-vsftpd-backdoor", "ftp-proftpd-backdoor"}
			case "22":
				nmapScripts = []string{"ssh2-enum-algos", "ssh-hostkey"}
			case "23":
				nmapScripts = []string{"telnet-encryption", "telnet-ntlm-info"}
			case "25":
				nmapScripts = []string{"smtp-enum-users", "smtp-open-relay"}
			case "53":
				nmapScripts = []string{"dns-zone-transfer", "dns-recursion"}
			case "80", "81", "443", "8080", "8000", "8443":
				nmapScripts = []string{"http-enum", "http-title", "http-server-header", "http-default-accounts"}
			case "139", "445":
				nmapScripts = []string{"smb-enum-shares", "smb-enum-users", "smb-os-discovery", "smb-vuln-*"}
			case "3389":
				nmapScripts = []string{"rdp-enum-encryption", "rdp-vuln-ms12-020"}
			case "3306":
				nmapScripts = []string{"mysql-empty-password", "mysql-vuln-cve2012-2122"}
			case "161":
				nmapScripts = []string{"snmp-info", "snmp-sysdescr"}
			default:
				continue
			}
			scriptList := strings.Join(nmapScripts, ",")
			outputFile := fmt.Sprintf("logs/nmap_%s_%s.log", ip, port)
			cmd := exec.Command("nmap", "-sV", "-p", port, "--script", scriptList, ip, "-oN", outputFile)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cmd.Run()
		}
	}
}

// Function to Run Nikto
func runNikto() {
	fmt.Println("\n[INFO] Running Nikto against detected web servers...")
	webPorts := []string{"80", "81", "443", "8080", "8000", "8443"}
	ips := make(map[string]bool)
	for _, port := range webPorts {
		portFile := filepath.Join("ports", port)
		if _, err := os.Stat(portFile); err == nil {
			lines := readLines(portFile)
			for _, line := range lines {
				ips[line] = true
			}
		}
	}
	if len(ips) == 0 {
		fmt.Println("[WARNING] No web servers found on common ports.")
		return
	}
	for ip := range ips {
		outputFile := fmt.Sprintf("logs/nikto_%s.log", ip)
		cmd := exec.Command("nikto", "-h", ip)
		output, _ := cmd.CombinedOutput()
		ioutil.WriteFile(outputFile, output, 0644)
	}
}

// Function to Check FTP Anonymous Login
func checkFTPAnonymous() {
	fmt.Println("\n[INFO] Checking for FTP anonymous login...")
	if _, err := os.Stat("ports/21"); os.IsNotExist(err) {
		fmt.Println("[WARNING] No hosts with port 21 open found.")
		return
	}
	ips := readLines("ports/21")
	for _, ip := range ips {
		outputFile := fmt.Sprintf("logs/ftp_anonymous_%s.log", ip)
		cmd := exec.Command("nmap", "-p", "21", "--script", "ftp-anon", ip, "-oN", outputFile)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Run()
	}
}

// Function to Run SNMP Enumeration
func snmpEnum() {
	fmt.Println("\n[INFO] Running SNMP enumeration...")
	if _, err := os.Stat("ports/161"); os.IsNotExist(err) {
		fmt.Println("[WARNING] No hosts with port 161 open found.")
		return
	}
	ips := readLines("ports/161")
	for _, ip := range ips {
		outputFile := fmt.Sprintf("logs/snmpwalk_%s.log", ip)
		cmd := exec.Command("snmpwalk", "-v1", "-c", "public", ip)
		output, _ := cmd.CombinedOutput()
		ioutil.WriteFile(outputFile, output, 0644)
	}
}

// Function to Check for Open Databases
func checkOpenDatabases() {
	fmt.Println("\n[INFO] Checking for open databases (MongoDB, Redis, Elasticsearch)...")
	dbPorts := map[string]string{
		"27017": "mongodb",
		"6379":  "redis",
		"9200":  "elasticsearch",
	}
	for port, dbName := range dbPorts {
		portFile := filepath.Join("ports", port)
		if _, err := os.Stat(portFile); err == nil {
			ips := readLines(portFile)
			for _, ip := range ips {
				outputFile := fmt.Sprintf("logs/%s_%s.log", dbName, ip)
				var cmd *exec.Cmd
				if dbName == "mongodb" {
					cmd = exec.Command("nmap", "-sV", "-p", port, "--script", "mongodb-info", ip, "-oN", outputFile)
				} else if dbName == "redis" {
					cmd = exec.Command("nmap", "-sV", "-p", port, "--script", "redis-info", ip, "-oN", outputFile)
				} else if dbName == "elasticsearch" {
					cmd = exec.Command("nmap", "-sV", "-p", port, "--script", "http-enum", ip, "-oN", outputFile)
				}
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				cmd.Run()
			}
		}
	}
}

// Function to Run SSL/TLS Vulnerability Checks
func nmapSSLScan() {
	fmt.Println("\n[INFO] Running Nmap SSL/TLS scripts on detected services...")
	sslPorts := []string{"443", "8443", "9443"}
	for _, port := range sslPorts {
		portFile := filepath.Join("ports", port)
		if _, err := os.Stat(portFile); err == nil {
			ips := readLines(portFile)
			for _, ip := range ips {
				outputFile := fmt.Sprintf("logs/nmap_ssl_%s_%s.log", ip, port)
				cmd := exec.Command("nmap", "-sV", "-p", port, "--script", "ssl-enum-ciphers,ssl-cert,ssl-dh-params", ip, "-oN", outputFile)
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				cmd.Run()
			}
		}
	}
}

// Function to Check for Default Credentials
func defaultCredentialsCheck() {
	fmt.Println("\n[INFO] Checking for default credentials on services...")
	webPorts := []string{"80", "81", "443", "8080", "8000", "8443"}
	ips := make(map[string]bool)
	for _, port := range webPorts {
		portFile := filepath.Join("ports", port)
		if _, err := os.Stat(portFile); err == nil {
			lines := readLines(portFile)
			for _, line := range lines {
				ips[line] = true
			}
		}
	}
	if len(ips) == 0 {
		fmt.Println("[WARNING] No web servers found for default credential checks.")
		return
	}
	for ip := range ips {
		proceed := getUserInput(fmt.Sprintf("[PROMPT] Proceed with default credential check on %s? (yes/no): ", ip))
		if strings.ToLower(proceed) != "yes" {
			continue
		}
		outputFile := fmt.Sprintf("logs/nmap_default_creds_%s.log", ip)
		cmd := exec.Command("nmap", "-p", "80,443", "--script", "http-default-accounts", ip, "-oN", outputFile)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Run()
	}
}

// Function to Attempt SSH Login
func sshLogin() {
	fmt.Println("\n[INFO] Attempting SSH login on detected hosts...")
	if _, err := os.Stat("ports/22"); os.IsNotExist(err) {
		fmt.Println("[WARNING] No hosts with port 22 open found.")
		return
	}
	ips := readLines("ports/22")
	for _, ip := range ips {
		outputFile := fmt.Sprintf("logs/ssh_login_%s.log", ip)
		cmd := exec.Command("sshpass", "-p", "password", "ssh", "-o", "StrictHostKeyChecking=no", fmt.Sprintf("root@%s", ip))
		output, _ := cmd.CombinedOutput()
		ioutil.WriteFile(outputFile, output, 0644)
	}
}

// Function to Attempt Telnet Login
func telnetLogin() {
	fmt.Println("\n[INFO] Attempting Telnet login on detected hosts...")
	if _, err := os.Stat("ports/23"); os.IsNotExist(err) {
		fmt.Println("[WARNING] No hosts with port 23 open found.")
		return
	}
	ips := readLines("ports/23")
	for _, ip := range ips {
		outputFile := fmt.Sprintf("logs/telnet_login_%s.log", ip)
		cmd := exec.Command("telnet", ip)
		output, _ := cmd.CombinedOutput()
		ioutil.WriteFile(outputFile, output, 0644)
	}
}

// Function to Enumerate IPMI Services
func ipmiScan() {
	fmt.Println("\n[INFO] Enumerating IPMI services on detected hosts...")
	if _, err := os.Stat("ports/623"); os.IsNotExist(err) {
		fmt.Println("[WARNING] No hosts with port 623 open found.")
		return
	}
	ips := readLines("ports/623")
	for _, ip := range ips {
		outputFile := fmt.Sprintf("logs/ipmi_scan_%s.log", ip)
		cmd := exec.Command("ipmitool", "-I", "lanplus", "-H", ip, "-U", "admin", "-P", "password", "chassis", "status")
		output, _ := cmd.CombinedOutput()
		ioutil.WriteFile(outputFile, output, 0644)
	}
}

// Helper Functions
func getUserInput(prompt string) string {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

func readLines(path string) []string {
	file, err := os.Open(path)
	if err != nil {
		log.Fatalf("readLines: %s", err)
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, strings.TrimSpace(scanner.Text()))
	}
	return lines
}

// isExcluded checks if a CIDR is in the exclusions list
func isExcluded(cidr string, exclusions []string) bool {
	for _, exclusion := range exclusions {
		if exclusion == cidr {
			return true
		}
	}
	return false
}

// Main Function
func main() {
	nmapLiveFlag := flag.Bool("nmap-live", false, "Run a live host discovery with Nmap")
	scanPortsFlag := flag.Bool("scan-ports", false, "Scan specific ports with Nmap")
	metasploitFlag := flag.Bool("metasploit", false, "Run selected Metasploit auxiliary modules for open ports")
	aquatoneFlag := flag.Bool("aquatone", false, "Run Aquatone for web screenshots")
	enum4linuxFlag := flag.Bool("enum4linux", false, "Run Enum4Linux for SMB enumeration")
	netexecFlag := flag.Bool("netexec", false, "Run Netexec for SMB enumeration and signing checks")
	vulnersScanFlag := flag.Bool("vulners-scan", false, "Run Nmap with Vulners script for vulnerability detection")
	nmapVulnScanFlag := flag.Bool("nmap-vuln-scan", false, "Run Nmap with 'vuln' scripts for vulnerability detection")
	nmapServiceScanFlag := flag.Bool("nmap-service-scan", false, "Run Nmap service-specific scripts on detected services")
	niktoFlag := flag.Bool("nikto", false, "Run Nikto against detected web servers")
	ftpAnonFlag := flag.Bool("ftp-anon", false, "Check for FTP anonymous login")
	snmpEnumFlag := flag.Bool("snmp-enum", false, "Run SNMP enumeration")
	sslTLSChecksFlag := flag.Bool("ssl-tls-checks", false, "Run SSL/TLS vulnerability checks")
	openDatabasesFlag := flag.Bool("open-databases", false, "Check for open databases (MongoDB, Redis, Elasticsearch)")
	defaultCredsFlag := flag.Bool("default-creds", false, "Check for default credentials on services")
	sshLoginFlag := flag.Bool("ssh-login", false, "Attempt SSH login on detected hosts")
	telnetLoginFlag := flag.Bool("telnet-login", false, "Attempt Telnet login on detected hosts")
	allFlag := flag.Bool("all", false, "Run all the above scripts sequentially")
	ipmiScanFlag := flag.Bool("ipmi-scan", false, "Enumerate IPMI services")
	targetFile := flag.String("target-file", "", "Path to the file containing target IP addresses or CIDRs")
	excludeFile := flag.String("exclude-file", "excluded_hosts.txt", "Path to the file containing IP addresses to exclude from the scan")
	helpFlag := flag.Bool("help", false, "Show this help menu")
	hFlag := flag.Bool("h", false, "Show this help menu")

	flag.Parse()

	if *helpFlag || *hFlag {
		displayHelp()
		return
	}

	displayBanner()

	if _, err := os.Stat("logs"); os.IsNotExist(err) {
		os.Mkdir("logs", 0755)
	}
	if *nmapLiveFlag || *allFlag {
		nmapLive(*targetFile, *excludeFile)
	}

	if *nmapLiveFlag {
		if *targetFile == "" {
			fmt.Println("[ERROR] --target-file is required for --nmap-live")
			return
		}
		nmapLive(*targetFile, *excludeFile)
	}

	if *scanPortsFlag || *allFlag {
		scanPorts(*targetFile, *excludeFile)
	}

	if *scanPortsFlag {
		if *targetFile == "" {
			fmt.Println("[ERROR] --target-file is required for --scan-ports")
			return
		}
		scanPorts(*targetFile, *excludeFile)
	}

	if *metasploitFlag || *allFlag {
		metasploitModules()
	}

	if *metasploitFlag {
		metasploitModules()
	}

	if *aquatoneFlag || *allFlag {
		runAquatone()
	}

	if *aquatoneFlag {
		runAquatone()
	}

	if *enum4linuxFlag || *allFlag {
		runEnum4linux()
	}

	if *enum4linuxFlag {
		runEnum4linux()
	}

	if *netexecFlag || *allFlag {
		runNetexec()
	}

	if *netexecFlag {
		runNetexec()
	}

	if *vulnersScanFlag || *allFlag {
		if *targetFile == "" {
			fmt.Println("[ERROR] --target-file is required for --vulners-scan")
			return
		}
		vulnersScan(*targetFile, *excludeFile)
	}

	if *vulnersScanFlag {
		if *targetFile == "" {
			fmt.Println("[ERROR] --target-file is required for --vulners-scan")
			return
		}
		vulnersScan(*targetFile, *excludeFile)
	}

	if *nmapVulnScanFlag || *allFlag {
		nmapVulnScan(*targetFile, *excludeFile)
	}

	if *nmapVulnScanFlag {
		if *targetFile == "" {
			fmt.Println("[ERROR] --target-file is required for --nmap-vuln-scan")
			return
		}
		nmapVulnScan(*targetFile, *excludeFile)
	}

	if *nmapServiceScanFlag || *allFlag {
		nmapServiceScan()
	}

	if *nmapServiceScanFlag {
		nmapServiceScan()
	}

	if *niktoFlag || *allFlag {
		runNikto()
	}

	if *niktoFlag {
		runNikto()
	}

	if *ftpAnonFlag || *allFlag {
		checkFTPAnonymous()
	}

	if *ftpAnonFlag {
		checkFTPAnonymous()
	}

	if *snmpEnumFlag || *allFlag {
		snmpEnum()
	}

	if *snmpEnumFlag {
		snmpEnum()
	}

	if *sslTLSChecksFlag || *allFlag {
		nmapSSLScan()
	}

	if *sslTLSChecksFlag {
		nmapSSLScan()
	}

	if *openDatabasesFlag || *allFlag {
		checkOpenDatabases()
	}

	if *openDatabasesFlag {
		checkOpenDatabases()
	}

	if *defaultCredsFlag || *allFlag {
		defaultCredentialsCheck()
	}

	if *defaultCredsFlag {
		defaultCredentialsCheck()
	}

	if *sshLoginFlag || *allFlag {
		sshLogin()
	}

	if *sshLoginFlag {
		sshLogin()
		if *ipmiScanFlag || *allFlag {
			ipmiScan()
		}

		// Process CIDR ranges and exclusions if targetFile and excludeFile are provided
		if *targetFile != "" && *excludeFile != "" {
			cidrRanges := readLines(*targetFile)
			exclusions := readLines(*excludeFile)

			for _, cidr := range cidrRanges {
				if _, _, err := net.ParseCIDR(cidr); err != nil {
					log.Printf("Invalid CIDR: %s\n", cidr)
					continue
				}
				if isExcluded(cidr, exclusions) {
					log.Printf("Excluded CIDR: %s\n", cidr)
					continue
				}
				fmt.Printf("Scanning CIDR: %s\n", cidr)
				// Add your scanning logic here
			}
		}
		telnetLogin()
	}

	if *telnetLoginFlag {
		telnetLogin()
	}

	if *ipmiScanFlag || *allFlag {
		ipmiScan()
	}

	if *ipmiScanFlag {
		ipmiScan()
	}

	if !*nmapLiveFlag && !*scanPortsFlag && !*metasploitFlag && !*aquatoneFlag && !*enum4linuxFlag && !*netexecFlag &&
		!*vulnersScanFlag && !*nmapVulnScanFlag && !*nmapServiceScanFlag && !*niktoFlag && !*ftpAnonFlag &&
		!*snmpEnumFlag && !*sslTLSChecksFlag && !*openDatabasesFlag && !*defaultCredsFlag && !*sshLoginFlag &&
		!*telnetLoginFlag && !*ipmiScanFlag {
		displayHelp()
	}
}
