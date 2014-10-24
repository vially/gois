package gois

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jinzhu/now"
)

// Record holds the information returned by the whois server
type Record struct {
	Domain        string
	TrimmedDomain string
	CreatedOn     time.Time
	Registered    bool
}

func longestTLDSuffix(domain string) string {
	longestTld := ""
	for tld := range TLDWhoisServers {
		if strings.HasSuffix(domain, tld) && utf8.RuneCountInString(tld) > utf8.RuneCountInString(longestTld) {
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
	}

	buf, err := queryWhoisServer(requestDomain, server)
	if err != nil {
		return
	}

	response := string(buf)
	record, err = parse(response)
	if err == nil {
		record.Domain = domain
		record.TrimmedDomain = trimmedDomain
	}

	return
}

func queryWhoisServer(domain, server string) (buf []byte, err error) {
	conn, err := net.Dial("tcp", server+":43")
	if err != nil {
		return
	}
	defer conn.Close()

	fmt.Fprintf(conn, "%s\r\n", domain)
	buf, err = ioutil.ReadAll(conn)

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
		if strings.ToLower(key) == "creation date" {
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
