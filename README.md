# getcert

A utility for retrieving server certificates from a web server or direct tcp 
connection.

This is useful for getting copies of certificates to add to trust stores.

# Installing

```
go get -u github.com/rickar/getcert
```

# Using
Run `getcert -help` to display command line options. They are reproduced below:

```
  -chain
    	output entire trust chain
  -clientCert file
    	client certificate file (pem format)
  -clientKey file
    	client private key file (pem format)
  -dir path
    	output cert(s) to path directory using subject CN for filename
  -format type
    	output file type ("pem" or "der") (default "pem")
  -host host
    	host to use when making direct TCP connection
  -interactive
    	interactive mode
  -method string
    	HTTP method (GET, HEAD, OPTIONS, etc.) to use with url (default "HEAD")
  -out filename
    	output filename
  -port port
    	port to use when making a direct TCP connection (default 443)
  -proxy url
    	proxy server url to use when retreiving https certificate
  -timeout duration
    	connection timeout duration (default "60s")
  -type protocol
    	connection protocol to use ("https" or direct "tcp") (default "https")
  -url url
    	url to use when retrieving https certificate
  -verify
    	verify certificates (default true)
```

HTTPS usage requires `-url` and `-out` parameters. Direct TCP usage requires `-host`, `-port`, and `-out` parameters.

## Examples

Export the certificate for github.com to github.cer in PEM format:
```
getcert -url https://github.com -out github.cer
```

Export the entire certificate chain for github.com to github*.cer:
```
getcert -url https://github.com -out github.cer -chain
```

Export an untrusted certificate to untrusted.cer:
```
getcert -url https://untrusted-root.badssl.com/ -out untrusted.cer -verify=false
```

Export the certificate for a non-web server:
```
getcert -type tcp -host smtp.gmail.com -port 465 -out email.cer
```
