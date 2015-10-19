package gois

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"strings"
	"unicode/utf8"

	"github.com/jinzhu/now"
)

//go:generate go run cmd/generate-whois-servers/main.go
//go:generate go fmt servers.go

var timeFormats = []string{
	"02-Jan-2006",
	"2006.01.02",
	"02-Jan-2006 15:04:05 MST",
	"2006-01-02T15:04:05.0Z",
	"2006-01-02T15:04:05Z",
	"2006-01-02T15:04:05-07:00",
}

func init() {
	now.TimeFormats = append(now.TimeFormats, timeFormats...)
}

func longestTLDSuffix(domain string) string {
	longestTld := ""
	for tld := range TLDWhoisServers {
		if strings.HasSuffix(domain, "."+tld) && utf8.RuneCountInString(tld) > utf8.RuneCountInString(longestTld) {
			longestTld = tld
		}
	}
	return longestTld
}

func trimSubdomains(domain, tld string) (trimmedDomain string) {
	noTld := strings.TrimSuffix(domain, "."+tld)
	parts := strings.Split(noTld, ".")
	trimmedDomain = fmt.Sprintf("%s.%s", parts[len(parts)-1], tld)
	return trimmedDomain
}

// Whois returns the public whois information for a domain
func Whois(domain string) (record *Record, err error) {
	tld := longestTLDSuffix(domain)
	server := TLDWhoisServers[tld]

	trimmedDomain := trimSubdomains(domain, tld)
	requestDomain := trimmedDomain
	if server == "whois.verisign-grs.com" {
		requestDomain = "=" + trimmedDomain
	} else if server == "whois.denic.de" {
		requestDomain = "-T dn,ace " + trimmedDomain
	}

	response, err := QueryWhoisServer(requestDomain, server)
	if err != nil {
		return
	}

	record, err = parse(response)
	if err == nil {
		record.Domain = domain
		record.TrimmedDomain = trimmedDomain
	}

	return
}

// QueryWhoisServer queries a particular whois server for information about a domain
func QueryWhoisServer(domain, server string) (response string, err error) {
	conn, err := net.Dial("tcp", server+":43")
	if err != nil {
		return
	}
	defer conn.Close()

	fmt.Fprintf(conn, "%s\r\n", domain)
	if buf, err := ioutil.ReadAll(conn); err == nil {
		response = string(buf)
	}

	return
}

func parse(response string) (record *Record, err error) {
	for _, line := range strings.Split(response, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, ":") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		key, value := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		if strings.ToLower(key) == "created" || strings.ToLower(key) == "creation date" || strings.ToLower(key) == "changed" || strings.ToLower(key) == "domain create date" {
			if parsedDate, parseErr := now.Parse(value); parseErr != nil {
				err = parseErr
			} else {
				record = &Record{CreatedOn: parsedDate, Registered: true}
			}
			return
		}
	}
	return nil, errors.New("Unable to parse whois record")
}
