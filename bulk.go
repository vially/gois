package gois

// WhoisBulk concurrently requests whois information for the given domains
func WhoisBulk(domains []string) map[string]*Record {
	records := make(map[string]*Record)
	results := make(chan *Record)
	executeWhois := func(domain string, results chan<- *Record) {
		result, _ := Whois(domain)
		results <- result
	}

	for _, domain := range domains {
		go executeWhois(domain, results)
	}

	for index := 0; index < len(domains); index++ {
		result := <-results
		domain := domains[index]
		records[domain] = result
	}

	return records
}
