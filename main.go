// (c) 2019 Rick Arnold. Licensed under the BSD license (see LICENSE).

package main

import (
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
	"strings"
	"time"
)

var (
	fType       = flag.String("type", "https", "connection `protocol` to use (\"https\" or direct \"tcp\")")
	fHost       = flag.String("host", "", "`host` to use when making direct TCP connection")
	fPort       = flag.Int("port", 443, "`port` to use when making a direct TCP connection")
	fURL        = flag.String("url", "", "`url` to use when retrieving https certificate")
	fProxy      = flag.String("proxy", "", "proxy server `url` to use when retreiving https certificate")
	fVerify     = flag.Bool("verify", true, "verify certificates")
	fChain      = flag.Bool("chain", false, "output entire trust chain")
	fName       = flag.String("out", "", "output `filename`")
	fFormat     = flag.String("format", "pem", "output file `type` (\"pem\" or \"der\")")
	fTimeout    = flag.String("timeout", "60s", "connection timeout `duration`")
	fClientCert = flag.String("clientCert", "", "client certificate `file` (pem format)")
	fClientKey  = flag.String("clientKey", "", "client private key `file` (pem format)")
	fMethod     = flag.String("method", "HEAD", "HTTP method (GET, HEAD, OPTIONS, etc.) to use with url")

	timeout  time.Duration
	proxyURL *url.URL
)

func main() {
	flag.Parse()
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
	write(*fName, certs[0])

	// write the cert chain if requested and available
	if *fChain && len(certs) > 1 {
		// create filenames with numeric index based on main output file
		dir := filepath.Dir(*fName)
		ext := filepath.Ext(*fName)
		basename := strings.TrimSuffix(filepath.Base(*fName), ext)

		for i, cert := range certs[1:] {
			write(filepath.Join(dir, fmt.Sprintf("%s-%d%s", basename, (i+1), ext)), cert)
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

	if *fName == "" {
		fmt.Println("-out filename must be provided")
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
