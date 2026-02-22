package ui

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/espenotterstad/iptables-log-tui/internal/ports"
)

// Stats holds all running counters for the Stats tab.
type Stats struct {
	Total     int
	ByAction  map[string]int
	ByProto   map[string]int
	ByIface   map[string]int
	BySrcIP   map[string]int
	ByDstPort map[string]int
}

// NewStats creates an initialised Stats.
func NewStats() Stats {
	return Stats{
		ByAction:  make(map[string]int),
		ByProto:   make(map[string]int),
		ByIface:   make(map[string]int),
		BySrcIP:   make(map[string]int),
		ByDstPort: make(map[string]int),
	}
}

// RenderStatsTab renders the Stats tab view.
func RenderStatsTab(s Stats, width int) string {
	var sb strings.Builder

	section := func(title string) {
		sb.WriteString("\n" + StyleLabel.Render(title) + "\n")
		sb.WriteString(StyleDivider.Render(strings.Repeat("─", 40)) + "\n")
	}

	kv := func(k, v string) {
		sb.WriteString(fmt.Sprintf("  %s  %s\n",
			StyleStatLabel.Render(fmt.Sprintf("%-28s", k)),
			StyleStatValue.Render(v),
		))
	}

	section("Overview")
	kv("Total events", fmt.Sprintf("%d", s.Total))

	section("By Action")
	for _, action := range sortedKeys(s.ByAction) {
		kv(action, fmt.Sprintf("%d", s.ByAction[action]))
	}

	section("By Protocol")
	for _, proto := range sortedKeys(s.ByProto) {
		kv(proto, fmt.Sprintf("%d", s.ByProto[proto]))
	}

	section("By Interface")
	for _, iface := range sortedKeys(s.ByIface) {
		kv(iface, fmt.Sprintf("%d", s.ByIface[iface]))
	}

	section("Top 10 Source IPs")
	for i, ip := range topN(s.BySrcIP, 10) {
		kv(fmt.Sprintf("%2d. %s", i+1, ip.key), fmt.Sprintf("%d", ip.count))
	}

	section("Top 10 Destination Ports")
	for i, p := range topN(s.ByDstPort, 10) {
		portNum, _ := strconv.Atoi(p.key)
		// Try TCP first (most common for well-known ports), then UDP.
		name := ports.Lookup(portNum, "TCP")
		if name == "" {
			name = ports.Lookup(portNum, "UDP")
		}
		label := "port " + p.key
		if name != "" {
			label = fmt.Sprintf("port %s (%s)", p.key, name)
		}
		kv(fmt.Sprintf("%2d. %s", i+1, label), fmt.Sprintf("%d", p.count))
	}

	return sb.String()
}

type kc struct{ key string; count int }

func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func topN(m map[string]int, n int) []kc {
	items := make([]kc, 0, len(m))
	for k, v := range m {
		items = append(items, kc{k, v})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].count != items[j].count {
			return items[i].count > items[j].count
		}
		return items[i].key < items[j].key
	})
	if len(items) > n {
		items = items[:n]
	}
	return items
}
