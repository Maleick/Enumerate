// enumerate.go
package main

import (
	"archive/zip"
	"bufio"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
)

// Download Aquatone zip file
func downloadAquatone(url, dest string) error {
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download Aquatone: %v", err)
	}
	defer resp.Body.Close()

	out, err := os.Create(dest)
	if err != nil {
		return fmt.Errorf("failed to create file: %v", err)
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to save Aquatone: %v", err)
	}

	return nil
}

// Install Aquatone in the current directory
// This function has been removed to avoid redeclaration error.

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
  --all                 Run all modules
  --nmap-live           Run a live host discovery with Nmap
  --scan-ports          Scan specific ports with Nmap (e.g., Aquatone ports)
  --metasploit          Run selected Metasploit auxiliary modules for open ports
  --aquatone            Run Aquatone for web screenshots
  --enum4linux          Run Enum4Linux for SMB enumeration
  --netexec             Run Netexec for SMB enumeration and signing checks
  --vulners-scan        Run Nmap with Vulners script for vulnerability detection
  --nmap-vuln-scan      Run Nmap with 'vuln' scripts for vulnerability detection
  --nmap-service-scan   Run Nmap service-specific scripts on detected services
  --nikto               Run Nikto against detected web servers
  --ftp-anon            Check for FTP anonymous login
  --snmp-enum           Run SNMP enumeration
  --ssl-tls-checks      Run SSL/TLS vulnerability checks
  --open-databases      Check for open databases (MongoDB, Redis, Elasticsearch)
  --default-creds       Check for default credentials on services
  --ssh-login           Attempt SSH login on detected hosts
  --telnet-login        Attempt Telnet login on detected hosts
  --ipmi-scan           Enumerate IPMI services
  --concurrency         Set the maximum number of concurrent tasks (default: 5)
  --target-file         Path to the file containing target IP addresses or CIDRs
  --exclude-file        Path to the file containing IP addresses to exclude from the scan
  --help                Show this help menu
	`
	fmt.Println(helpText)
}

// Execute a command and return its output
func executeCommand(cmdName string, args []string) (string, error) {
	cmd := exec.Command(cmdName, args...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// Check if a tool is available in PATH
func checkToolAvailability(toolName string) error {
	_, err := exec.LookPath(toolName)
	if err != nil {
		return fmt.Errorf("required tool '%s' is not installed or not in PATH", toolName)
	}

	return nil
}

// Get user confirmation
func getUserConfirmation(prompt string) bool {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(prompt)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(strings.ToLower(input))
	return input == "yes" || input == "y"
}

// Get IPs from port file
func getIPsFromPortFile(port string) ([]string, error) {
	portFile := filepath.Join("ports", port)
	if _, err := os.Stat(portFile); os.IsNotExist(err) {
		return nil, fmt.Errorf("port file '%s' does not exist", portFile)
	}

	file, err := os.Open(portFile)
	if err != nil {
		return nil, fmt.Errorf("unable to open port file '%s': %v", portFile, err)
	}
	defer file.Close()

	var ips []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ip := strings.TrimSpace(scanner.Text())
		if ip != "" {
			ips = append(ips, ip)
		}
	}
	return ips, nil
}

// Nmap Live Host Discovery
func nmapLive(targetFile, excludeFile string) error {
	fmt.Println("\n[INFO] Running Nmap for live host discovery...")

	if err := checkToolAvailability("nmap"); err != nil {
		return err
	}

	if _, err := os.Stat(excludeFile); os.IsNotExist(err) {
		fmt.Printf("[WARNING] Exclusion file '%s' not found. Creating an empty exclusion file.\n", excludeFile)
		err := ioutil.WriteFile(excludeFile, []byte{}, 0644)
		if err != nil {
			return fmt.Errorf("unable to create exclusion file: %v", err)
		}
	}

	if !getUserConfirmation("[PROMPT] Proceed with the scan using the provided files? (yes/no): ") {
		fmt.Println("[INFO] Scan aborted by user.")
		return nil
	}

	args := []string{"-sn", "-iL", targetFile, "--excludefile", excludeFile, "-oA", "nmap/live_hosts"}
	output, err := executeCommand("nmap", args)
	if err != nil {
		return fmt.Errorf("Nmap live host discovery failed: %v\nOutput: %s", err, output)
	}

	fmt.Println("[INFO] Nmap live host discovery completed.")
	return nil
}

// Scan Specific Ports with Nmap
func scanPorts(targetFile, excludeFile string) error {
	fmt.Println("\n[INFO] Scanning specific ports with Nmap...")

	if err := checkToolAvailability("nmap"); err != nil {
		return err
	}

	if _, err := os.Stat(excludeFile); os.IsNotExist(err) {
		fmt.Printf("[WARNING] Exclusion file '%s' not found. Creating an empty exclusion file.\n", excludeFile)
		err := ioutil.WriteFile(excludeFile, []byte{}, 0644)
		if err != nil {
			return fmt.Errorf("unable to create exclusion file: %v", err)
		}
	}

	if !getUserConfirmation("[PROMPT] Proceed with the port scan using the provided files? (yes/no): ") {
		fmt.Println("[INFO] Port scan aborted by user.")
		return nil
	}

	ports := "U:111,161,623,T:21,22,23,25,53,80,81,88,135,137,139,300,443,445,591,593,832,981,1010,1311,1433,2082,2087,2095,2096,2480,3000,3128,3306,3333,3389,4243,4567,4711,4712,4993,5000,5104,5108,5432,5800,5900,5985,5986,6543,7000,7396,7474,8000,8001,8008,8014,8042,8069,8080,8081,8088,8090,8091,8118,8123,8172,8222,8243,8280,8281,8333,8443,8500,8834,8880,8888,8983,9000,9043,9060,9080,9090,9091,9200,9443,9800,9981,12443,16080,18091,18092,20720,28017,49751,50911"
	nmapOutputPrefix := "nmap/ports"

	args := []string{"-sSU", "-iL", targetFile, "--excludefile", excludeFile, "-p", ports, "-oA", nmapOutputPrefix}
	output, err := executeCommand("nmap", args)
	if err != nil {
		return fmt.Errorf("Nmap port scan failed: %v\nOutput: %s", err, output)
	}

	fmt.Println("[INFO] Nmap port scan completed.")

	err = parseNmapOutput(nmapOutputPrefix + ".xml")
	if err != nil {
		return fmt.Errorf("Error parsing Nmap output: %v", err)
	}

	return nil
}

// Parse Nmap XML Output
func parseNmapOutput(nmapXMLFile string) error {
	fmt.Println("\n[INFO] Parsing Nmap XML output and generating 'ports/PORT_NUMBER' files...")

	xmlFile, err := os.Open(nmapXMLFile)
	if err != nil {
		return fmt.Errorf("unable to open Nmap XML file: %v", err)
	}
	defer xmlFile.Close()

	byteValue, _ := ioutil.ReadAll(xmlFile)
	var nmapRun NmapRun
	err = xml.Unmarshal(byteValue, &nmapRun)
	if err != nil {
		return fmt.Errorf("unable to parse Nmap XML file: %v", err)
	}

	portsDir := "ports"
	if _, err := os.Stat(portsDir); os.IsNotExist(err) {
		os.Mkdir(portsDir, 0755)
	}

	portFiles := make(map[string]*os.File)
	defer func() {
		for _, file := range portFiles {
			file.Close()
		}
	}()

	for _, host := range nmapRun.Hosts {
		addr := host.Address.Addr
		for _, port := range host.Ports.Ports {
			if port.State.State != "open" {
				continue
			}
			portNumber := port.PortID
			portFilePath := filepath.Join(portsDir, portNumber)
			if _, exists := portFiles[portNumber]; !exists {
				portFile, err := os.OpenFile(portFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
				if err != nil {
					log.Printf("[ERROR] Unable to create port file '%s': %v", portFilePath, err)
					continue
				}
				portFiles[portNumber] = portFile
			}
			portFiles[portNumber].WriteString(addr + "\n")
		}
	}

	return nil
}

// Nmap XML Structs
type NmapRun struct {
	Hosts []Host `xml:"host"`
}

type Host struct {
	Address Address `xml:"address"`
	Ports   Ports   `xml:"ports"`
}

type Address struct {
	Addr string `xml:"addr,attr"`
}

type Ports struct {
	Ports []Port `xml:"port"`
}

type Port struct {
	Protocol string `xml:"protocol,attr"`
	PortID   string `xml:"portid,attr"`
	State    State  `xml:"state"`
}

type State struct {
	State string `xml:"state,attr"`
}

// Download and Install Aquatone if not available
func installAquatone() error {
	fmt.Println("[INFO] Aquatone not found. Attempting to download and install Aquatone...")

	// Download URL for Aquatone
	url := "https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip"
	zipFile := "aquatone.zip"

	// Download the zip file
	out, err := os.Create(zipFile)
	if err != nil {
		return fmt.Errorf("unable to create zip file: %v", err)
	}
	defer out.Close()

	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download Aquatone: %v", err)
	}
	defer resp.Body.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to save Aquatone zip file: %v", err)
	}

	// Unzip the file
	err = unzip(zipFile, ".")
	if err != nil {
		return fmt.Errorf("failed to unzip Aquatone: %v", err)
	}

	// Remove the zip file after extraction
	os.Remove(zipFile)

	// Set executable permissions
	err = os.Chmod("aquatone", 0755)
	if err != nil {
		return fmt.Errorf("failed to set permissions on Aquatone binary: %v", err)
	}

	fmt.Println("[INFO] Aquatone has been installed in the current directory.")

	return nil
}

// Unzip a zip archive, extracting all files and folders
func unzip(src, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		fpath := filepath.Join(dest, f.Name)

		// Check for ZipSlip vulnerability
		if !strings.HasPrefix(fpath, filepath.Clean(dest)+string(os.PathSeparator)) {
			return fmt.Errorf("illegal file path: %s", fpath)
		}

		if f.FileInfo().IsDir() {
			// Make Folder
			os.MkdirAll(fpath, os.ModePerm)
			continue
		}

		// Make File
		if err := os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			return err
		}

		inFile, err := f.Open()
		if err != nil {
			return err
		}
		defer inFile.Close()

		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return err
		}
		defer outFile.Close()

		_, err = io.Copy(outFile, inFile)
		if err != nil {
			return err
		}
	}
	return nil
}

// Run Aquatone
func runAquatone() error {
	fmt.Println("\n[INFO] Running Aquatone for web screenshots...")

	// Check if Aquatone is installed
	err := checkToolAvailability("aquatone")
	if err != nil {
		// Attempt to install Aquatone
		err = installAquatone()
		if err != nil {
			return err
		}
	}

	// Update PATH to include current directory if necessary
	if !strings.Contains(os.Getenv("PATH"), ".") {
		os.Setenv("PATH", fmt.Sprintf(".:%s", os.Getenv("PATH")))
	}

	args := []string{"-nmap", "nmap/ports.xml", "-ports", "xlarge", "-out", "aquatone/reports"}
	output, err := executeCommand("aquatone", args)
	if err != nil {
		return fmt.Errorf("Aquatone execution failed: %v\nOutput: %s", err, output)
	}
	fmt.Println("[INFO] Aquatone completed.")
	return nil
}

// Run Enum4Linux
func runEnum4linux(concurrencyLimit int) {
	fmt.Println("\n[INFO] Running Enum4Linux for SMB enumeration...")

	if err := checkToolAvailability("enum4linux"); err != nil {
		log.Println(err)
		return
	}

	ips, err := getIPsFromPortFile("445")
	if err != nil {
		fmt.Println("[WARNING] No hosts with port 445 open found.")
		return
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrencyLimit)

	for _, ip := range ips {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			sem <- struct{}{}
			fmt.Printf("[INFO] Running Enum4Linux against %s\n", ip)
			outputFile := filepath.Join("logs", fmt.Sprintf("enum4linux_%s.log", ip))
			args := []string{"-a", ip}
			cmd := exec.Command("enum4linux", args...)
			output, err := cmd.CombinedOutput()
			if err != nil {
				log.Printf("[ERROR] Enum4Linux failed for %s: %v\nOutput: %s", ip, err, string(output))
			} else {
				err = ioutil.WriteFile(outputFile, output, 0644)
				if err != nil {
					log.Printf("[ERROR] Unable to write Enum4Linux output for %s: %v", ip, err)
				}
			}
			<-sem
		}(ip)
	}
	wg.Wait()
	fmt.Println("[INFO] Enum4Linux scans completed.")
}

// Run Nikto
func runNikto(concurrencyLimit int) {
	fmt.Println("\n[INFO] Running Nikto against detected web servers...")

	if err := checkToolAvailability("nikto"); err != nil {
		log.Println(err)
		return
	}

	webPorts := []string{"80", "81", "443", "8080", "8000", "8443"}
	ipsSet := make(map[string]bool)

	for _, port := range webPorts {
		ips, err := getIPsFromPortFile(port)
		if err != nil {
			log.Println(err)
			continue
		}
		for _, ip := range ips {
			ipsSet[ip] = true
		}
	}

	if len(ipsSet) == 0 {
		fmt.Println("[WARNING] No web servers found on common ports.")
		return
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrencyLimit)

	for ip := range ipsSet {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			sem <- struct{}{}
			fmt.Printf("[INFO] Running Nikto against %s\n", ip)
			outputFile := filepath.Join("logs", fmt.Sprintf("nikto_%s.log", ip))
			args := []string{"-h", ip}
			cmd := exec.Command("nikto", args...)
			output, err := cmd.CombinedOutput()
			if err != nil {
				log.Printf("[ERROR] Nikto scan failed for %s: %v\nOutput: %s", ip, err, string(output))
			} else {
				err = ioutil.WriteFile(outputFile, output, 0644)
				if err != nil {
					log.Printf("[ERROR] Unable to write Nikto output for %s: %v", ip, err)
				}
			}
			<-sem
		}(ip)
	}
	wg.Wait()
	fmt.Println("[INFO] Nikto scans completed.")
}

// Main Function
func main() {
	// Example usage
	err := unzip("example.zip", "output_directory")
	if err != nil {
		fmt.Println("Error:", err)
	} else {
		fmt.Println("Unzip successful")
	}

	displayBanner()

	// Command-line flags
	var (
		runAll           = flag.Bool("all", false, "Run all modules")
		nmapLiveFlag     = flag.Bool("nmap-live", false, "Run a live host discovery with Nmap")
		scanPortsFlag    = flag.Bool("scan-ports", false, "Scan specific ports with Nmap")
		metasploit       = flag.Bool("metasploit", false, "Run selected Metasploit auxiliary modules for open ports")
		aquatone         = flag.Bool("aquatone", false, "Run Aquatone for web screenshots")
		enum4linux       = flag.Bool("enum4linux", false, "Run Enum4Linux for SMB enumeration")
		netexec          = flag.Bool("netexec", false, "Run Netexec for SMB enumeration and signing checks")
		vulnersScan      = flag.Bool("vulners-scan", false, "Run Nmap with Vulners script for vulnerability detection")
		nmapVulnScan     = flag.Bool("nmap-vuln-scan", false, "Run Nmap with 'vuln' scripts for vulnerability detection")
		nmapServiceScan  = flag.Bool("nmap-service-scan", false, "Run Nmap service-specific scripts on detected services")
		nikto            = flag.Bool("nikto", false, "Run Nikto against detected web servers")
		ftpAnon          = flag.Bool("ftp-anon", false, "Check for FTP anonymous login")
		snmpEnum         = flag.Bool("snmp-enum", false, "Run SNMP enumeration")
		sslTLSChecks     = flag.Bool("ssl-tls-checks", false, "Run SSL/TLS vulnerability checks")
		openDatabases    = flag.Bool("open-databases", false, "Check for open databases (MongoDB, Redis, Elasticsearch)")
		defaultCreds     = flag.Bool("default-creds", false, "Check for default credentials on services")
		sshLogin         = flag.Bool("ssh-login", false, "Attempt SSH login on detected hosts")
		telnetLogin      = flag.Bool("telnet-login", false, "Attempt Telnet login on detected hosts")
		ipmiScan         = flag.Bool("ipmi-scan", false, "Enumerate IPMI services")
		concurrencyLimit = flag.Int("concurrency", 5, "Maximum number of concurrent tasks")
		targetFile       = flag.String("target-file", "", "Path to the file containing target IP addresses or CIDRs")
		excludeFile      = flag.String("exclude-file", "excluded_hosts.txt", "Path to the file containing IP addresses to exclude from the scan")
		showHelp         = flag.Bool("help", false, "Show help menu")
	)
	flag.Parse()

	if *showHelp {
		displayHelp()
		return
	}

	// Create necessary directories
	if _, err := os.Stat("logs"); os.IsNotExist(err) {
		os.Mkdir("logs", 0755)
	}
	if _, err := os.Stat("nmap"); os.IsNotExist(err) {
		os.Mkdir("nmap", 0755)
	}

	// Signal handling for graceful shutdown
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		fmt.Println("\n[INFO] Received interrupt signal, shutting down...")
		os.Exit(0)
	}()

	// Run all modules if --all is set
	if *runAll {
		*nmapLiveFlag = true
		*scanPortsFlag = true
		*metasploit = true
		*aquatone = true
		*enum4linux = true
		*netexec = true
		*vulnersScan = true
		*nmapVulnScan = true
		*nmapServiceScan = true
		*nikto = true
		*ftpAnon = true
		*snmpEnum = true
		*sslTLSChecks = true
		*openDatabases = true
		*defaultCreds = true
		*sshLogin = true
		*telnetLogin = true
		*ipmiScan = true
	}

	// Execute modules based on flags
	if *nmapLiveFlag {
		if *targetFile == "" {
			log.Println("[ERROR] --target-file is required for --nmap-live")
			return
		}
		err := nmapLive(*targetFile, *excludeFile)
		if err != nil {
			log.Println(err)
			return
		}
	}

	if *scanPortsFlag {
		if *targetFile == "" {
			log.Println("[ERROR] --target-file is required for --scan-ports")
			return
		}
		err := scanPorts(*targetFile, *excludeFile)
		if err != nil {
			log.Println(err)
			return
		}
	}

	if *aquatone {
		err := runAquatone()
		if err != nil {
			log.Println(err)
			return
		}
	}

	if *enum4linux {
		runEnum4linux(*concurrencyLimit)
	}

	if *nikto {
		runNikto(*concurrencyLimit)
	}

	// Implement other functionalities similarly, ensuring to check for tool availability and handling errors.

	// If no flags are set, display help
	if !*runAll && !*nmapLiveFlag && !*scanPortsFlag && !*aquatone && !*enum4linux && !*nikto && !*metasploit && !*netexec && !*vulnersScan && !*nmapVulnScan && !*nmapServiceScan && !*ftpAnon && !*snmpEnum && !*sslTLSChecks && !*openDatabases && !*defaultCreds && !*sshLogin && !*telnetLogin && !*ipmiScan {
		displayHelp()
		return
	}
}
