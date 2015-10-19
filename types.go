package gois

import "time"

// Record holds the information returned by the whois server
type Record struct {
	Domain              string
	CreatedOn           time.Time
	Registered          bool
}
