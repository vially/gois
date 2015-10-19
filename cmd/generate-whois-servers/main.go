package main

import (
	"bufio"
	"log"
	"os"
	"strings"
	"text/template"
"net/http"
)

func main() {
	resp, err := http.Get("http://www.nirsoft.net/whois-servers.txt")
	if err != nil {
		log.Fatalln(err)
	}

	serversMap := make(map[string]string)
	scanner := bufio.NewScanner(resp.Body)
	defer resp.Body.Close()
	for scanner.Scan() {
		if line := scanner.Text(); !strings.HasPrefix(line, ";") {
			values := strings.SplitN(line, " ", 2)
			serversMap[values[0]] = values[1]
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatalln(err)
	}

	serversTemplate, err := template.New("test").Parse(`package gois

// TLDWhoisServers is a map containing all the public server records taken from: http://www.nirsoft.net/whois-servers.txt
var TLDWhoisServers = map[string]string{
{{range $key, $value := .}}` + "\t" + `"{{ $key }}": "{{ $value }}",
{{ end }}` + "}\n")
	if err != nil {
		log.Fatalln(err)
	}

	f, err := os.Create("servers.go")
	if err != nil {
		log.Fatalln(err)
	}
	defer f.Close()

	if err = serversTemplate.Execute(f, serversMap); err != nil {
		log.Fatalln(err)
	}
}
