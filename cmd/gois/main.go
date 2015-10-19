package main

import (
	"fmt"
	"github.com/vially/gois"
	"log"
	"os"
)

func main() {
	if len(os.Args) == 1 {
		fmt.Println("Usage: gois DOMAIN")
		os.Exit(1)
	}

	record, err := gois.Whois(os.Args[1])
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Println(record)
}
