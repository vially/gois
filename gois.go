package gois

import (
	"errors"
	"fmt"
	"github.com/jinzhu/now"
	"golang.org/x/net/publicsuffix"
	"io/ioutil"
	"net"
	"strings"
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

// Whois returns the public whois information for a domain
func Whois(domain string) (record *Record, err error) {
	tld, _ := publicsuffix.PublicSuffix(domain)
	whoisServer := TLDWhoisServers[tld]

	eTLDPlusOne, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return nil, err
	}

	requestDomain := eTLDPlusOne
	if whoisServer == "whois.verisign-grs.com" {
		requestDomain = "=" + eTLDPlusOne
	} else if whoisServer == "whois.denic.de" {
		requestDomain = "-T dn,ace " + eTLDPlusOne
	}

	response, err := QueryWhoisServer(requestDomain, whoisServer)
	if err != nil {
		return
	}

	record, err = parse(response)
	if err == nil {
		record.Domain = domain
		record.TrimmedDomain = eTLDPlusOne
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
