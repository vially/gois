package gois

import (
	"github.com/jinzhu/now"
)

//go:generate go run cmd/generate-whois-servers/main.go
//go:generate go fmt tld_servers_list.go

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
func Whois(domain string) (*Record, error) {
	server, err := ServerForDomain(domain)
	if err != nil {
		return nil, err
	}

	return server.Query(domain)
}
