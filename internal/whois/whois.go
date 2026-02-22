package whois

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

// Result holds the fields extracted from whois output.
type Result struct {
	Subnet  string
	NetName string
	ASN     string
	Org     string
}

// Lookup runs `whois <ip>` with a 10-second timeout and returns parsed fields.
// Returns an empty Result if whois is not installed or produces no useful
// output — callers treat an all-empty Result as "nothing to show".
func Lookup(ip string) Result {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "whois", ip).Output()
	if err != nil {
		return Result{}
	}
	return parse(string(out))
}

// parse extracts known fields from whois output, tolerating differences between
// RIPE, ARIN, APNIC, LACNIC, and AFRINIC formats.
func parse(output string) Result {
	lines := strings.Split(output, "\n")
	return Result{
		Subnet:  firstMatch(lines, "inetnum", "NetRange", "CIDR"),
		NetName: firstMatch(lines, "netname", "NetName"),
		ASN:     firstMatch(lines, "aut-num", "OriginAS"),
		Org:     firstMatch(lines, "org-name", "OrgName", "Organization", "org"),
	}
}

// firstMatch returns the trimmed value of the first line whose key
// (case-insensitive) matches one of the supplied keys.
// Returns "" if none match or all values are empty.
func firstMatch(lines []string, keys ...string) string {
	for _, line := range lines {
		for _, key := range keys {
			prefix := strings.ToLower(key) + ":"
			lower := strings.ToLower(line)
			if strings.HasPrefix(lower, prefix) {
				val := strings.TrimSpace(line[len(key)+1:])
				if val != "" && !strings.HasPrefix(val, "#") {
					return val
				}
			}
		}
	}
	return ""
}
