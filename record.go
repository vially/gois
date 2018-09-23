package gois

import (
	"strings"
	"time"

	"github.com/jinzhu/now"
)

var domainRegistrationKeys = []string{
	"created",
	"creation date",
	"changed",
	"domain create date",
	"registered on",
}

// Record holds the information returned by the whois server
type Record struct {
	Domain     string
	CreatedOn  *time.Time
	Registered bool
	Status     string
}

// NewRecord creates a new record from a list of key/value strings
func NewRecord(domain string, keyValues map[string]string) *Record {
	record := &Record{Domain: domain}
	for key, value := range keyValues {
		if isValidRegistrationKey(key) {
			if parsedDate, err := now.Parse(value); err == nil {
				record.CreatedOn = &parsedDate
				record.Registered = true
			}
		} else if key == "Domain Status" {
			record.Status = value
		}
	}

	return record
}

func isValidRegistrationKey(key string) bool {
	for _, validKey := range domainRegistrationKeys {
		if strings.ToLower(key) == validKey {
			return true
		}
	}
	return false
}
