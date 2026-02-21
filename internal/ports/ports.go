package ports

import (
	_ "embed"
	"encoding/csv"
	"fmt"
	"strings"
)

//go:embed iana-services.csv
var ianaCSV []byte

// serviceMap keys are "port/PROTO" (e.g. "80/TCP") → service name (e.g. "http").
var serviceMap map[string]string

func init() {
	serviceMap = make(map[string]string, 8192)
	r := csv.NewReader(strings.NewReader(string(ianaCSV)))
	r.Read() // skip header row
	for {
		rec, err := r.Read()
		if err != nil {
			break
		}
		// CSV columns: Service Name, Port Number, Transport Protocol, ...
		if len(rec) < 3 || rec[0] == "" || rec[1] == "" || rec[2] == "" {
			continue
		}
		key := rec[1] + "/" + strings.ToUpper(rec[2])
		if _, exists := serviceMap[key]; !exists { // first entry wins
			serviceMap[key] = rec[0]
		}
	}
}

// Lookup returns the IANA service name for the given port and transport protocol
// (e.g. "TCP", "UDP"), or "" if unknown.
func Lookup(port int, proto string) string {
	if port == 0 {
		return ""
	}
	return serviceMap[fmt.Sprintf("%d/%s", port, strings.ToUpper(proto))]
}
