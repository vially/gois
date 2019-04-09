package gois

import (
	"strings"
	"time"

	"github.com/jinzhu/now"
)

var domainRegistrationKeys = map[string][]string{
	"create": {"created", "creation date", "domain create date", "registered on"},
	"update": {"changed", "updated date", "last-update"},
	"expire": {"registry expiry date", "expiry date"},
}

// Record holds the information returned by the whois server
type Record struct {
	Domain     string
	CreatedOn  *time.Time
	UpdatedOn  *time.Time
	ExpiresOn  *time.Time
	Registered bool
	Status     string
}

// NewRecord creates a new record from a list of key/value strings
func NewRecord(domain string, keyValues map[string]string) *Record {
	record := &Record{Domain: domain}
	for key, value := range keyValues {
		for kind, regValues := range domainRegistrationKeys {
			for _, regValue := range regValues {
				if strings.ToLower(key) == regValue {
					if parsedDate, err := now.Parse(value); err == nil {
						switch kind {
						case "create":
							record.CreatedOn = &parsedDate
						case "update":
							record.UpdatedOn = &parsedDate
						case "expire":
							record.ExpiresOn = &parsedDate
						}
						record.Registered = true
					}
				}
			}
		}

		if key == "Domain Status" {
			record.Status = value
		}
	}

	return record
}
