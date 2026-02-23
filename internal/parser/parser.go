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
	`^(\d{4}-\d{2}-\d{2}T\S+|\w{3}\s+\d+\s+[\d:]+)\s+(\S+)\s+kernel:.*?\[?([^\]]*?)\]?\s+IN=(\S*)\s+OUT=(\S*)` +
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
		Prefix:    strings.Trim(m[3], "[ "),
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
// Source: https://www.iana.org/assignments/protocol-numbers
var protoNames = map[string]string{
	"0":   "HOPOPT",
	"1":   "ICMP",
	"2":   "IGMP",
	"3":   "GGP",
	"4":   "IPv4",
	"5":   "ST",
	"6":   "TCP",
	"7":   "CBT",
	"8":   "EGP",
	"9":   "IGP",
	"10":  "BBN-RCC-MON",
	"11":  "NVP-II",
	"12":  "PUP",
	"14":  "EMCON",
	"15":  "XNET",
	"16":  "CHAOS",
	"17":  "UDP",
	"18":  "MUX",
	"19":  "DCN-MEAS",
	"20":  "HMP",
	"21":  "PRM",
	"22":  "XNS-IDP",
	"23":  "TRUNK-1",
	"24":  "TRUNK-2",
	"25":  "LEAF-1",
	"26":  "LEAF-2",
	"27":  "RDP",
	"28":  "IRTP",
	"29":  "ISO-TP4",
	"30":  "NETBLT",
	"31":  "MFE-NSP",
	"32":  "MERIT-INP",
	"33":  "DCCP",
	"34":  "3PC",
	"35":  "IDPR",
	"36":  "XTP",
	"37":  "DDP",
	"38":  "IDPR-CMTP",
	"39":  "TP++",
	"40":  "IL",
	"41":  "IPv6",
	"42":  "SDRP",
	"43":  "IPv6-Route",
	"44":  "IPv6-Frag",
	"45":  "IDRP",
	"46":  "RSVP",
	"47":  "GRE",
	"48":  "DSR",
	"49":  "BNA",
	"50":  "ESP",
	"51":  "AH",
	"52":  "I-NLSP",
	"54":  "NARP",
	"55":  "Min-IPv4",
	"56":  "TLSP",
	"57":  "SKIP",
	"58":  "IPv6-ICMP",
	"59":  "IPv6-NoNxt",
	"60":  "IPv6-Opts",
	"62":  "CFTP",
	"64":  "SAT-EXPAK",
	"65":  "KRYPTOLAN",
	"66":  "RVD",
	"67":  "IPPC",
	"69":  "SAT-MON",
	"70":  "VISA",
	"71":  "IPCV",
	"72":  "CPNX",
	"73":  "CPHB",
	"74":  "WSN",
	"75":  "PVP",
	"76":  "BR-SAT-MON",
	"77":  "SUN-ND",
	"78":  "WB-MON",
	"79":  "WB-EXPAK",
	"80":  "ISO-IP",
	"81":  "VMTP",
	"82":  "SECURE-VMTP",
	"83":  "VINES",
	"84":  "IPTM",
	"85":  "NSFNET-IGP",
	"86":  "DGP",
	"87":  "TCF",
	"88":  "EIGRP",
	"89":  "OSPF",
	"90":  "Sprite-RPC",
	"91":  "LARP",
	"92":  "MTP",
	"93":  "AX.25",
	"94":  "IPIP",
	"96":  "SCC-SP",
	"97":  "ETHERIP",
	"98":  "ENCAP",
	"100": "GMTP",
	"101": "IFMP",
	"102": "PNNI",
	"103": "PIM",
	"104": "ARIS",
	"105": "SCPS",
	"106": "QNX",
	"107": "A/N",
	"108": "IPComp",
	"109": "SNP",
	"110": "Compaq-Peer",
	"111": "IPX-in-IP",
	"112": "VRRP",
	"113": "PGM",
	"115": "L2TP",
	"116": "DDX",
	"117": "IATP",
	"118": "STP",
	"119": "SRP",
	"120": "UTI",
	"121": "SMP",
	"123": "PTP",
	"124": "ISIS",
	"125": "FIRE",
	"126": "CRTP",
	"127": "CRUDP",
	"128": "SSCOPMCE",
	"129": "IPLT",
	"130": "SPS",
	"131": "PIPE",
	"132": "SCTP",
	"133": "FC",
	"134": "RSVP-E2E-IGNORE",
	"135": "Mobility",
	"136": "UDPLite",
	"137": "MPLS-in-IP",
	"138": "MANET",
	"139": "HIP",
	"140": "Shim6",
	"141": "WESP",
	"142": "ROHC",
	"143": "Ethernet",
}

// normalizeProto converts numeric protocol values to their canonical names.
func normalizeProto(p string) string {
	up := strings.ToUpper(p)
	if name, ok := protoNames[up]; ok {
		return name
	}
	return up
}

// parseTimestamp parses either an ISO 8601 timestamp (ufw.log style,
// e.g. "2026-02-22T00:00:28.257338+01:00") or a syslog-style timestamp
// (e.g. "Jan  2 15:04:05"). For syslog format the year is assumed to be
// the current year.
func parseTimestamp(s string) (time.Time, error) {
	if len(s) > 0 && s[0] >= '0' && s[0] <= '9' {
		t, err := time.Parse(time.RFC3339Nano, s)
		if err != nil {
			return time.Time{}, err
		}
		return t.In(time.Local), nil
	}
	// Syslog format: normalise multiple spaces then parse.
	s = strings.Join(strings.Fields(s), " ")
	t, err := time.Parse("Jan 2 15:04:05", s)
	if err != nil {
		return time.Time{}, err
	}
	now := time.Now()
	return time.Date(now.Year(), t.Month(), t.Day(),
		t.Hour(), t.Minute(), t.Second(), 0, time.Local), nil
}
