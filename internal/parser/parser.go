package parser

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// LogEntry represents a parsed iptables log line.
type LogEntry struct {
	Timestamp time.Time
	Hostname  string
	Prefix    string // e.g. "UFW BLOCK", "DROP", custom chain prefix
	In        string // IN interface
	Out       string // OUT interface
	Src       string // source IP
	Dst       string // destination IP
	Proto     string // TCP / UDP / ICMP
	SrcPort   int    // SPT
	DstPort   int    // DPT
	TTL       int
	Len       int
	Raw       string // original line (for detail view)
}

// Action returns the action derived from the prefix (DROP, ACCEPT, REJECT, etc.)
func (e LogEntry) Action() string {
	prefix := strings.ToUpper(e.Prefix)
	switch {
	case strings.Contains(prefix, "DROP") || strings.Contains(prefix, "BLOCK"):
		return "DROP"
	case strings.Contains(prefix, "ACCEPT"):
		return "ACCEPT"
	case strings.Contains(prefix, "REJECT"):
		return "REJECT"
	default:
		if e.Prefix != "" {
			return e.Prefix
		}
		return "UNKNOWN"
	}
}

// String returns a human-readable summary of all fields.
func (e LogEntry) String() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "Timestamp : %s\n", e.Timestamp.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(&sb, "Hostname  : %s\n", e.Hostname)
	fmt.Fprintf(&sb, "Prefix    : %s\n", e.Prefix)
	fmt.Fprintf(&sb, "Action    : %s\n", e.Action())
	fmt.Fprintf(&sb, "In        : %s\n", e.In)
	fmt.Fprintf(&sb, "Out       : %s\n", e.Out)
	fmt.Fprintf(&sb, "Src       : %s\n", e.Src)
	fmt.Fprintf(&sb, "Dst       : %s\n", e.Dst)
	fmt.Fprintf(&sb, "Proto     : %s\n", e.Proto)
	if e.SrcPort != 0 {
		fmt.Fprintf(&sb, "SrcPort   : %d\n", e.SrcPort)
	}
	if e.DstPort != 0 {
		fmt.Fprintf(&sb, "DstPort   : %d\n", e.DstPort)
	}
	if e.TTL != 0 {
		fmt.Fprintf(&sb, "TTL       : %d\n", e.TTL)
	}
	if e.Len != 0 {
		fmt.Fprintf(&sb, "Len       : %d\n", e.Len)
	}
	fmt.Fprintf(&sb, "\nRaw:\n%s\n", e.Raw)
	return sb.String()
}

// logLineRe matches the core structure of an iptables kernel log line.
// Groups: (1) timestamp  (2) hostname  (3) prefix  (4) IN  (5) OUT
//
//	(6) SRC  (7) DST  (8) PROTO  (9) SPT?  (10) DPT?
var logLineRe = regexp.MustCompile(
	`^(\w{3}\s+\d+\s+[\d:]+)\s+(\S+)\s+kernel:.*?\[?([^\]]*?)\]?\s+IN=(\S*)\s+OUT=(\S*)` +
		`.*?SRC=(\S+)\s+DST=(\S+).*?PROTO=(\S+)` +
		`(?:.*?SPT=(\d+))?(?:.*?DPT=(\d+))?`,
)

// ttlRe and lenRe extract TTL and LEN from anywhere in the line.
var (
	ttlRe = regexp.MustCompile(`TTL=(\d+)`)
	lenRe = regexp.MustCompile(`\bLEN=(\d+)`)
)

// ParseLine parses a single iptables log line.
// Returns nil and an error if the line does not match the expected format.
func ParseLine(line string) (*LogEntry, error) {
	m := logLineRe.FindStringSubmatch(line)
	if m == nil {
		return nil, fmt.Errorf("line does not match iptables log format")
	}

	ts, err := parseTimestamp(m[1])
	if err != nil {
		return nil, fmt.Errorf("parse timestamp %q: %w", m[1], err)
	}

	entry := &LogEntry{
		Timestamp: ts,
		Hostname:  m[2],
		Prefix:    strings.TrimSpace(m[3]),
		In:        m[4],
		Out:       m[5],
		Src:       m[6],
		Dst:       m[7],
		Proto:     normalizeProto(m[8]),
		Raw:       line,
	}

	if m[9] != "" {
		entry.SrcPort, _ = strconv.Atoi(m[9])
	}
	if m[10] != "" {
		entry.DstPort, _ = strconv.Atoi(m[10])
	}
	if ttl := ttlRe.FindStringSubmatch(line); ttl != nil {
		entry.TTL, _ = strconv.Atoi(ttl[1])
	}
	if ln := lenRe.FindStringSubmatch(line); ln != nil {
		entry.Len, _ = strconv.Atoi(ln[1])
	}

	return entry, nil
}

// protoNames maps IP protocol numbers (as logged by iptables) to their names.
var protoNames = map[string]string{
	"2": "IGMP",
}

// normalizeProto converts numeric protocol values to their canonical names.
func normalizeProto(p string) string {
	up := strings.ToUpper(p)
	if name, ok := protoNames[up]; ok {
		return name
	}
	return up
}

// parseTimestamp parses syslog-style timestamps like "Jan  2 15:04:05".
// The year is assumed to be the current year.
func parseTimestamp(s string) (time.Time, error) {
	// Normalise multiple spaces to a single space.
	s = strings.Join(strings.Fields(s), " ")
	t, err := time.Parse("Jan 2 15:04:05", s)
	if err != nil {
		return time.Time{}, err
	}
	// Attach the current year and local timezone.
	now := time.Now()
	return time.Date(now.Year(), t.Month(), t.Day(),
		t.Hour(), t.Minute(), t.Second(), 0, time.Local), nil
}
