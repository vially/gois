package main

import (
	"fmt"
	"github.com/vially/gois"
	"os"
)

func main() {
	if len(os.Args) == 1 {
		fmt.Println("Usage: gois DOMAIN [DOMAIN...]")
		os.Exit(1)
	}

	records := gois.WhoisBulk(os.Args[1:])
	for domain, record := range records {
		fmt.Printf("%s: %v\n", domain, record)
	}
}
