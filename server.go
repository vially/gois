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

var timeFormats = []string{
	"02-Jan-2006",
	"2006.01.02",
	"02-Jan-2006 15:04:05 MST",
	"2006-01-02T15:04:05.0Z",
	"2006-01-02T15:04:05Z",
	"2006-01-02T15:04:05-07:00",
	"before Jan-2006",
}

var domainRegistrationKeys = []string{
	"created",
	"creation date",
	"changed",
	"domain create date",
	"registered on",
}

func init() {
	now.TimeFormats = append(now.TimeFormats, timeFormats...)
}

type Server interface {
	Query(string) (*Record, error)
}

func ServerForDomain(domain string) (Server, error) {
	tld, _ := publicsuffix.PublicSuffix(domain)
	if server, ok := TLDWhoisServers[tld]; ok {
		return &GenericServer{TLD: tld, Server: server}, nil
	}

	return ServerForTLD(tld)
}

func ServerForTLD(domain string) (Server, error) {
	if !strings.Contains(domain, ".") {
		return nil, errors.New("Unable to find a suitable whois server for TLD: " + domain)
	}
	parts := strings.SplitN(domain, ".", 2)
	tld := parts[1]
	if server, ok := TLDWhoisServers[tld]; ok {
		return &GenericServer{TLD: tld, Server: server}, nil
	}

	return ServerForTLD(tld)
}

type GenericServer struct {
	TLD    string
	Server string
}

func (s *GenericServer) Query(domain string) (*Record, error) {
	eTLDPlusOne, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return nil, err
	}

	queryInput := eTLDPlusOne
	if s.Server == "whois.verisign-grs.com" {
		queryInput = "=" + eTLDPlusOne
	} else if s.Server == "whois.denic.de" {
		queryInput = "-T dn,ace " + eTLDPlusOne
	}

	data, err := s.query(queryInput)
	if err != nil {
		return nil, err
	}

	return s.parse(string(data), domain)
}

func (s *GenericServer) query(domain string) ([]byte, error) {
	conn, err := net.Dial("tcp", s.Server+":43")
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	fmt.Fprintf(conn, "%s\r\n", domain)
	return ioutil.ReadAll(conn)
}

func (s *GenericServer) parse(response, domain string) (record *Record, err error) {
	for _, line := range strings.Split(response, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, ":") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		key, value := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		if isValidRegistrationKey(key) {
			if parsedDate, parseErr := now.Parse(value); parseErr != nil {
				err = parseErr
			} else {
				record = &Record{Domain: domain, CreatedOn: parsedDate, Registered: true}
			}
			return record, nil
		}
	}
	return nil, errors.New("Unable to parse whois record")
}

func isValidRegistrationKey(key string) bool {
	for _, validKey := range domainRegistrationKeys {
		if strings.ToLower(key) == validKey {
			return true
		}
	}
	return false
}
