package gois

import (
	"time"
)

//go:generate go run cmd/generate-whois-servers/main.go
//go:generate go fmt tld_servers_list.go

// Record holds the information returned by the whois server
type Record struct {
	Domain     string
	CreatedOn  time.Time
	Registered bool
}

// Whois returns the public whois information for a domain
func Whois(domain string) (*Record, error) {
	server, err := ServerForDomain(domain)
	if err != nil {
		return nil, err
	}

	return server.Query(domain)
}

// WhoisBulk concurrently requests whois information for the given domains
func WhoisBulk(domains []string) map[string]*Record {
	done := make(chan *Record)
	results := make(map[string]*Record)
	for _, domain := range domains {
		go func(domain string) {
			result, _ := Whois(domain)
			done <- result
		}(domain)
		results[domain] = nil
	}

	for range domains {
		result := <-done
		if result != nil {
			results[result.Domain] = result
		}
	}

	return results
}
