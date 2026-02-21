package ui

import (
	"fmt"
	"strings"
)

// Filters holds the current active filter state.
type Filters struct {
	Action    string // "DROP", "ACCEPT", "" (any)
	Proto     string // "TCP", "UDP", "" (any)
	IPSubstr  string // substring match against Src or Dst
}

// Active returns true if any filter is set.
func (f Filters) Active() bool {
	return f.Action != "" || f.Proto != "" || f.IPSubstr != ""
}

// RenderFilterTab renders the Filters tab view.
func RenderFilterTab(f Filters) string {
	var sb strings.Builder

	sb.WriteString("\n" + StyleLabel.Render("Active Filters") + "\n")
	sb.WriteString(StyleDivider.Render(strings.Repeat("─", 40)) + "\n\n")

	filterRow := func(name, value string) {
		label := fmt.Sprintf("  %-16s", name+":")
		if value == "" {
			value = StyleMuted.Render("(none)")
		} else {
			value = StyleFilter.Render(value)
		}
		sb.WriteString(label + value + "\n")
	}

	filterRow("Action", f.Action)
	filterRow("Protocol", f.Proto)
	filterRow("IP substring", f.IPSubstr)

	sb.WriteString("\n")
	if f.Active() {
		sb.WriteString(StyleHelp.Render("  Press [c] to clear all filters") + "\n")
	} else {
		sb.WriteString(StyleMuted.Render("  No active filters — all entries are shown.") + "\n")
	}

	sb.WriteString("\n" + StyleLabel.Render("Quick-Filter Keys (active in Logs tab)") + "\n")
	sb.WriteString(StyleDivider.Render(strings.Repeat("─", 40)) + "\n\n")
	keys := [][2]string{
		{"d", "Toggle DROP-only"},
		{"a", "Toggle ACCEPT-only"},
		{"t", "Toggle TCP-only"},
		{"u", "Toggle UDP-only"},
		{"/", "Search by IP substring"},
		{"Esc", "Clear filter / close search"},
	}
	for _, k := range keys {
		sb.WriteString(fmt.Sprintf("  %s  %s\n",
			StyleFilter.Render(fmt.Sprintf("[%-4s]", k[0])),
			StyleStatLabel.Render(k[1]),
		))
	}

	return sb.String()
}
