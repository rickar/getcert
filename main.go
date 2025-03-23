// (c) 2019 Rick Arnold. Licensed under the BSD license (see LICENSE).

package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var (
	fType        = flag.String("type", "https", "connection `protocol` to use (\"https\" or direct \"tcp\")")
	fHost        = flag.String("host", "", "`host` to use when making direct TCP connection")
	fPort        = flag.Int("port", 443, "`port` to use when making a direct TCP connection")
	fURL         = flag.String("url", "", "`url` to use when retrieving https certificate")
	fProxy       = flag.String("proxy", "", "proxy server `url` to use when retreiving https certificate")
	fVerify      = flag.Bool("verify", true, "verify certificates")
	fChain       = flag.Bool("chain", false, "output entire trust chain")
	fName        = flag.String("out", "", "output `filename`")
	fDir         = flag.String("dir", "", "output cert(s) to `path` directory using subject CN for filename")
	fFormat      = flag.String("format", "pem", "output file `type` (\"pem\" or \"der\")")
	fTimeout     = flag.String("timeout", "60s", "connection timeout `duration`")
	fClientCert  = flag.String("clientCert", "", "client certificate `file` (pem format)")
	fClientKey   = flag.String("clientKey", "", "client private key `file` (pem format)")
	fMethod      = flag.String("method", "HEAD", "HTTP method (GET, HEAD, OPTIONS, etc.) to use with url")
	fInteractive = flag.Bool("interactive", false, "interactive mode")

	fileSafeChars = regexp.MustCompile(`[^a-zA-Z0-9_\-.]+`)

	timeout  time.Duration
	proxyURL *url.URL
)

func main() {
	flag.Parse()
	if *fInteractive {
		interactiveFlags()
	}
	validateFlags()

	// connect and perform cert exchange
	var state tls.ConnectionState
	var conn io.Closer
	switch *fType {
	case "https":
		state, conn = connectHTTPS()
	case "tcp":
		state, conn = connectTCP()
	}
	defer conn.Close()

	// if available, use VerifiedChains for full chain
	certs := state.PeerCertificates
	if len(state.VerifiedChains) > 0 {
		certs = state.VerifiedChains[0]
	}
	if len(certs) == 0 {
		fmt.Printf("no certificates available\n")
		os.Exit(3)
	}

	// write the leaf cert
	if *fDir == "" {
		write(*fName, certs[0])
	} else {
		if certs[0].Subject.CommonName == "" {
			write(createFilename("No Subject CN"), certs[0])
		} else {
			write(createFilename(certs[0].Subject.CommonName), certs[0])
		}
	}

	// write the cert chain if requested and available
	if *fChain && len(certs) > 1 {

		if *fDir == "" {
			// create filenames with numeric index based on main output file
			dir := filepath.Dir(*fName)
			ext := filepath.Ext(*fName)
			basename := strings.TrimSuffix(filepath.Base(*fName), ext)

			for i, cert := range certs[1:] {
				write(filepath.Join(dir, fmt.Sprintf("%s-%d%s", basename, (i+1), ext)), cert)
			}
		} else {
			for _, cert := range certs[1:] {
				if cert.Subject.CommonName == "" {
					write(createFilename("No Subject CN"), cert)
				} else {
					write(createFilename(cert.Subject.CommonName), cert)
				}
			}
		}
	}
}

// interactiveFlags provides a "wizard" mode so the flags don't have to be
// provided on the command line
func interactiveFlags() {

	inputChoice("Protocol", []string{"(H)ttps", "(t)cp"}, []string{"h", "t"}, "h", fType)
	if *fType == "h" || *fType == "H" || strings.ToLower(*fType) == "https" {
		*fType = "https"
	} else if *fType == "t" || *fType == "T" || strings.ToLower(*fType) == "tcp" {
		*fType = "tcp"
	}

	targetDone := false
	for !targetDone {
		if *fType == "https" {
			inputString("URL", false, fURL)
			if !strings.HasPrefix(*fURL, "https://") {
				fmt.Println("Invalid URL; must start with https://")
			} else {
				targetDone = true
			}
		} else {
			inputString("Host", false, fHost)
			inputInt("Port", fPort)
			targetDone = true
		}
	}

	*fDir = "."
	done := false
	for !done {
		fmt.Println()
		fmt.Println("Request")
		fmt.Printf("    P)rotocol: [%s]    T)imeout: [%s]    V)erify: [%t]    C)hain: [%t]    F)ormat: [%s]\n", *fType, *fTimeout, *fVerify, *fChain, *fFormat)
		if *fType == "https" {
			fmt.Printf("    M)ethod:   [%-4s]     U)RL: [%s]\n", *fMethod, *fURL)
			fmt.Printf("    Pro(x)y: [%s]\n", *fProxy)
			fmt.Printf("    Client Ce(r)t: [%s]\n", *fClientCert)
			fmt.Printf("    Client K)ey: [%s]\n", *fClientKey)
		} else {
			fmt.Printf("    H)ost: [%s]    P(o)rt: [%d]\n", *fHost, *fPort)
		}
		fmt.Println("Output")
		fmt.Printf("    N)ame:   [%s]    D)ir: [%s]\n", *fName, *fDir)
		fmt.Println()

		opt := ""
		fmt.Print("Option to change? ")
		fmt.Scanln(&opt)
		switch strings.TrimSpace(strings.ToLower(opt)) {
		case "c":
			inputBool("Include chain", fChain)
		case "d":
			inputString("Output dir", true, fDir)
			if *fDir != "" {
				*fName = ""
			}
		case "f":
			inputChoice("Output format", []string{"P)em", "d)er"}, []string{"p", "d"}, "p", fFormat)
			if *fFormat == "p" {
				*fFormat = "pem"
			} else {
				*fFormat = "der"
			}
		case "h":
			inputString("Host", true, fHost)
		case "k":
			inputString("Client key", true, fClientKey)
		case "m":
			inputString("HTTP method", false, fMethod)
		case "n":
			inputString("Output filename", true, fName)
			if *fName != "" {
				*fDir = ""
			}
		case "o":
			inputInt("Port", fPort)
		case "p":
			inputChoice("Protocol", []string{"(H)ttps", "(t)cp"}, []string{"h", "t"}, "h", fType)
			if *fType == "h" || *fType == "H" || strings.ToLower(*fType) == "https" {
				*fType = "https"
			} else if *fType == "t" || *fType == "T" || strings.ToLower(*fType) == "tcp" {
				*fType = "tcp"
			}
		case "r":
			inputString("Client certificate", true, fClientCert)
		case "t":
			inputString("Timeout", false, fTimeout)
		case "u":
			inputString("URL", true, fURL)
		case "v":
			inputBool("Verify", fVerify)
		case "x":
			inputString("Proxy", true, fProxy)
		case "":
			done = true
		default:
			fmt.Println("Invalid option")
		}
	}
}

func inputBool(name string, target *bool) {
	done := false
	for !done {
		var val string
		fmt.Printf("%s (y/n): ", name)
		_, err := fmt.Scanln(&val)
		if err != nil {
			fmt.Println("ERROR: input value required. Try again.")
		} else {
			val = strings.TrimSpace(strings.ToLower(val))
			if val == "y" || val == "yes" || val == "true" {
				*target = true
				done = true
			} else if val == "n" || val == "no" || val == "false" {
				*target = false
				done = true
			} else {
				fmt.Println("ERROR: invalid response. Enter 'y', 'yes', 'true', 'n', 'no', or 'false'.")
			}
		}
	}
}

func inputInt(name string, target *int) {
	done := false
	for !done {
		var val int
		fmt.Printf("%s: ", name)
		_, err := fmt.Scanln(&val)
		if err != nil {
			fmt.Println("ERROR: integer input value required. Try again.")
		} else {
			*target = val
			done = true
		}
	}
}

func inputString(name string, allowEmpty bool, target *string) {
	done := false
	scanner := bufio.NewScanner(os.Stdin)
	for !done {
		fmt.Printf("%s: ", name)

		scanner.Scan()
		line := scanner.Text()

		if line == "" && !allowEmpty {
			fmt.Println("ERROR: input value required. Try again.")
		} else {
			*target = line
			done = true
		}
	}
}

func inputChoice(name string, labels, opts []string, defaultOpt string, target *string) {
	done := false
	scanner := bufio.NewScanner(os.Stdin)
	for !done {
		fmt.Printf("%s [", name)
		for i, label := range labels {
			if i > 0 {
				fmt.Print(", ")
			}
			fmt.Print(label)
		}
		fmt.Print("]: ")

		scanner.Scan()
		line := scanner.Text()
		if line == "" && defaultOpt == "" {
			fmt.Println("ERROR: input value required. Try again.")
		} else {
			if line == "" {
				line = defaultOpt
			}

			line = strings.ToLower(strings.TrimSpace(line))
			for i, opt := range opts {
				if line == opt {
					*target = opts[i]
					done = true
					break
				}
			}
			if !done {
				fmt.Println("ERROR: invalid choice. Try again.")
			}
		}
	}
}

// validateFlags ensures that all required command line flags are present
// and that all flags have valid values
func validateFlags() {
	hasErr := false
	var err error

	if *fType == "" || (*fType != "https" && *fType != "tcp") {
		fmt.Println("-type must be \"https\" or \"tcp\"")
		hasErr = true
	}

	switch *fType {
	case "https":
		if *fURL == "" {
			fmt.Println("-url must be provided for https connection")
			hasErr = true
		}
		if *fProxy != "" {
			proxyURL, err = url.Parse(*fProxy)
			if err != nil {
				fmt.Println("-proxy is not a valid URL")
				hasErr = true
			}
		}
	case "tcp":
		if *fHost == "" || *fPort <= 0 {
			fmt.Println("-host and -port must be provided for tcp connection")
			hasErr = true
		}
	}

	if *fName == "" && *fDir == "" {
		fmt.Println("-out filename or -dir path must be provided")
		hasErr = true
	}

	if *fFormat != "pem" && *fFormat != "der" {
		fmt.Println("-format must be \"pem\" or \"der\"")
		hasErr = true
	}

	timeout, err = time.ParseDuration(*fTimeout)
	if err != nil {
		fmt.Println("-timeout is not a valid duration")
		hasErr = true
	}

	if (*fClientCert != "" && *fClientKey == "") || (*fClientKey != "" && *fClientKey == "") {
		fmt.Println("-clientCert and -clientKey must both be specified")
		hasErr = true
	}

	if hasErr {
		flag.Usage()
		os.Exit(1)
	}
}

// connectTCP makes a direct TCP connection to a host:port address
func connectTCP() (tls.ConnectionState, io.Closer) {
	conf := &tls.Config{
		InsecureSkipVerify: !*fVerify,
	}
	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", *fHost, *fPort), conf)
	if err != nil {
		fmt.Printf("failed to retrieve cert using direct TCP: %s\n", err.Error())
		os.Exit(2)
	}
	return conn.ConnectionState(), conn
}

// connectHTTPS makes an HTTPS connection (potentially going through a proxy)
func connectHTTPS() (tls.ConnectionState, io.Closer) {
	t := &http.Transport{
		TLSHandshakeTimeout:   timeout,
		DisableKeepAlives:     true,
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: timeout,
		Proxy:                 http.ProxyFromEnvironment,
	}
	http.DefaultTransport = t

	if *fProxy != "" {
		t.Proxy = http.ProxyURL(proxyURL)
	}

	if !*fVerify {
		t.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	if *fClientCert != "" {
		cert, err := tls.LoadX509KeyPair(*fClientCert, *fClientKey)
		if err != nil {
			fmt.Printf("failed to read client certificate/key: %s\n", err.Error())
			os.Exit(2)
		}
		conf := t.TLSClientConfig
		if conf == nil {
			conf = &tls.Config{}
			t.TLSClientConfig = conf
		}
		conf.Certificates = []tls.Certificate{cert}
	}

	req, err := http.NewRequest(*fMethod, *fURL, nil)
	if err != nil {
		fmt.Printf("failed to create https request: %s\n", err.Error())
		os.Exit(2)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Printf("failed to retreive cert using https: %s\n", err.Error())
		os.Exit(2)
	}
	if resp.TLS == nil {
		fmt.Printf("failed to retrieve cert using https (unencrypted connection?)\n")
		resp.Body.Close()
		os.Exit(2)
	}

	return *resp.TLS, resp.Body
}

// createFilename converts a subject CN to an allowed file name in the desired
// target path with the requested extension
func createFilename(subjectCn string) string {
	name := subjectCn
	if strings.HasPrefix(strings.ToLower(name), "cn=") {
		name = name[strings.Index(name, "=")+1:]
	}
	if strings.Contains(name, ",") {
		name = name[0:strings.Index(name, ",")]
	}

	name = fileSafeChars.ReplaceAllString(name, "_")
	if *fFormat == "pem" {
		name += ".pem"
	} else if *fFormat == "der" {
		name += ".der"
	} else {
		name += ".crt"
	}

	return filepath.Join(*fDir, name)
}

// write copies the contents of a certificate to an output file. If the file
// already exists, it will not be overwritten.
func write(filename string, cert *x509.Certificate) {
	fmt.Printf("Subject: %s\n\tdestination: %s\n", cert.Subject.String(), filename)

	out, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0666)
	if err != nil {
		fmt.Printf("failed to open output file: %s\n", err.Error())
		os.Exit(4)
	}
	defer out.Close()

	switch *fFormat {
	case "der":
		_, err = out.Write(cert.Raw)
		if err != nil {
			fmt.Printf("failed to write DER output: %s\n", err.Error())
			os.Exit(5)
		}
	case "pem":
		pemBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}

		err = pem.Encode(out, pemBlock)
		if err != nil {
			fmt.Printf("failed to write PEM output: %s\n", err.Error())
			os.Exit(5)
		}
	}
}
