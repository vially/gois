package main

import (
	"fmt"

	"github.com/jinzhu/now"
	"github.com/vially/gois"
)

func main() {
	now.TimeFormats = append(now.TimeFormats, "02-Jan-2006")
	now.TimeFormats = append(now.TimeFormats, "2006-01-02T15:04:05.0Z")
	fmt.Println(gois.WhoisBulk([]string{"example.com", "test.com"}))
}
