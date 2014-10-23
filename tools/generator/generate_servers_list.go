package main

import (
	"bufio"
	"log"
	"os"
	"strings"
	"text/template"
)

func main() {
	file, err := os.Open("whois-servers.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	serversMap := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if line := scanner.Text(); !strings.HasPrefix(line, ";") {
			values := strings.SplitN(line, " ", 2)
			serversMap[values[0]] = values[1]
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	tmpl, err := template.New("test").Parse(`package gois

// TLDWhoisServers is a map containing all the public server records taken from: http://www.nirsoft.net/whois-servers.txt
var TLDWhoisServers = map[string]string{
{{range $key, $value := .}}` + "\t" + `"{{ $key }}": "{{ $value }}",
{{ end }}` + "}\n")

	if err != nil {
		log.Fatal(err)
	}

	if err = tmpl.Execute(os.Stdout, serversMap); err != nil {
		log.Fatal(err)
	}
}
