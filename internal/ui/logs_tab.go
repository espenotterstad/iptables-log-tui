package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/espenotterstad/iptables-tui/internal/parser"
	"github.com/espenotterstad/iptables-tui/internal/ports"
)

// Column widths in terminal cells (content + trailing padding).
// The gutter (cursor indicator + space) is NOT included here;
// both the header and every data row are prefixed with exactly gutterWidth
// cells so all columns line up.
const (
	colTime   = 11 // "15:04:05" (8) + 3 gap
	colAction = 9  // "ACCEPT"   (6) + 3 gap
	colProto  = 7  // "ICMP"     (4) + 3 gap
	colSrc    = 18 // IPv4 max   (15) + 3 gap
	colDst    = 18 // same
	colDPT    = 16 // "ms-wbt-server" (13) + 3 gap
)

// arrowRune is the cursor indicator shown on the selected row.
// Its display width is measured at runtime with lipgloss.Width because many
// terminals render it as 2 cells (ambiguous-width Unicode character).
const arrowRune = "▶"

// gutterWidth is the number of terminal cells reserved for the gutter on
// every row (header and data alike).
var gutterWidth = lipgloss.Width(arrowRune) + 1

// RenderLogsTab renders the scrollable log table.
func RenderLogsTab(entries []parser.LogEntry, cursor, width, height int) string {
	var sb strings.Builder

	// ── Column header ───────────────────────────────────────────────────────
	gutter := strings.Repeat(" ", gutterWidth)
	sb.WriteString(gutter + renderHeader())
	sb.WriteByte('\n')
	sb.WriteString(StyleDivider.Render(strings.Repeat("─", width)))
	sb.WriteByte('\n')

	// ── Scrolling window ────────────────────────────────────────────────────
	rowsAvail := height - 4
	if rowsAvail < 1 {
		rowsAvail = 1
	}

	start := scrollStart(len(entries), cursor, rowsAvail)
	end := start + rowsAvail
	if end > len(entries) {
		end = len(entries)
	}

	for i := start; i < end; i++ {
		selected := i == cursor
		var prefix string
		if selected {
			rendered := lipgloss.NewStyle().Foreground(ColorStats).Render(arrowRune)
			trailing := strings.Repeat(" ", gutterWidth-lipgloss.Width(arrowRune))
			prefix = rendered + trailing
		} else {
			prefix = strings.Repeat(" ", gutterWidth)
		}
		sb.WriteString(prefix + renderDataRow(entries[i], selected))
		sb.WriteByte('\n')
	}

	// Pad remaining rows so height stays constant.
	for i := end - start; i < rowsAvail; i++ {
		sb.WriteByte('\n')
	}

	return sb.String()
}

// RenderDetailPage renders a full-screen view of a single log entry.
// It reads only the entry value passed in — it has no access to the live
// filtered slice, so incoming log lines cannot affect what is displayed.
func RenderDetailPage(e parser.LogEntry, width, height int) string {
	var sb strings.Builder

	// ── Header ──────────────────────────────────────────────────────────────
	title := StyleLabel.Render("Entry Detail")
	sb.WriteString(strings.Repeat(" ", gutterWidth) + title + "\n")
	sb.WriteString(StyleDivider.Render(strings.Repeat("─", width)) + "\n")

	// ── Fields ──────────────────────────────────────────────────────────────
	field := func(k, v string) {
		sb.WriteString(
			strings.Repeat(" ", gutterWidth) +
				StyleLabel.Render(fmt.Sprintf("%-11s", k+":")) +
				" " + v + "\n",
		)
	}

	action := e.Action()
	field("Timestamp", e.Timestamp.Format("2006-01-02 15:04:05"))
	field("Hostname", e.Hostname)
	field("Prefix", e.Prefix)
	field("Action", actionStyle(action).Bold(true).Render(action))
	field("In", e.In)
	field("Out", e.Out)
	field("Src", e.Src)
	field("Dst", e.Dst)
	field("Proto", protoStyle(e.Proto).Render(e.Proto))
	if e.SrcPort != 0 {
		label := fmt.Sprintf("%d", e.SrcPort)
		if name := ports.Lookup(e.SrcPort, e.Proto); name != "" {
			label = fmt.Sprintf("%d (%s)", e.SrcPort, name)
		}
		field("SrcPort", label)
	}
	if e.DstPort != 0 {
		label := fmt.Sprintf("%d", e.DstPort)
		if name := ports.Lookup(e.DstPort, e.Proto); name != "" {
			label = fmt.Sprintf("%d (%s)", e.DstPort, name)
		}
		field("DstPort", label)
	}
	if e.TTL != 0 {
		field("TTL", fmt.Sprintf("%d", e.TTL))
	}
	if e.Len != 0 {
		field("Len", fmt.Sprintf("%d", e.Len))
	}

	// ── Raw line ────────────────────────────────────────────────────────────
	sb.WriteByte('\n')
	sb.WriteString(strings.Repeat(" ", gutterWidth) + StyleLabel.Render("Raw:") + "\n")
	// Wrap raw line at terminal width.
	raw := e.Raw
	indent := strings.Repeat(" ", gutterWidth+2)
	for len(raw) > 0 {
		avail := width - gutterWidth - 2
		if avail < 1 {
			avail = 1
		}
		chunk := raw
		if len(chunk) > avail {
			chunk = raw[:avail]
		}
		sb.WriteString(indent + StyleMuted.Render(chunk) + "\n")
		raw = raw[len(chunk):]
	}

	// Pad to the full available height with blank lines.
	// Bubble Tea v1.x uses a cell-by-cell diff renderer: any cell not written
	// in the current frame keeps whatever was rendered in the previous frame.
	// Without this, rows of the live log table that were visible before the
	// detail page opened bleed through below the detail content and keep
	// updating as the tailer appends entries.
	out := sb.String()
	written := strings.Count(out, "\n")
	for written < height {
		out += "\n"
		written++
	}
	return out
}

// renderHeader produces a styled column-header row (no gutter prefix).
func renderHeader() string {
	style := lipgloss.NewStyle().Bold(true).Foreground(ColorHeader)
	return style.Render(
		padCell("TIME", colTime) +
			padCell("ACTION", colAction) +
			padCell("PROTO", colProto) +
			padCell("SRC", colSrc) +
			padCell("DST", colDst) +
			padCell("DPT", colDPT),
	)
}

// portLabel returns the IANA service name for the port if known, else the port
// number as a string. Returns "" for port 0 (not present in the log entry).
func portLabel(port int, proto string) string {
	if port == 0 {
		return ""
	}
	if name := ports.Lookup(port, proto); name != "" {
		return name
	}
	return fmt.Sprintf("%d", port)
}

// renderDataRow renders a single log entry as a table row (no gutter prefix).
func renderDataRow(e parser.LogEntry, selected bool) string {
	action := e.Action()
	timeStr := e.Timestamp.Format(time.TimeOnly)
	dpt := portLabel(e.DstPort, e.Proto)

	if selected {
		return StyleSelected.Render(
			padCell(timeStr, colTime) +
				padCell(action, colAction) +
				padCell(e.Proto, colProto) +
				padCell(e.Src, colSrc) +
				padCell(e.Dst, colDst) +
				padCell(dpt, colDPT),
		)
	}

	timeSt := lipgloss.NewStyle().Foreground(ColorMuted)
	actionSt := actionStyle(action)
	protoSt := protoStyle(e.Proto)
	addrSt := lipgloss.NewStyle()
	portSt := lipgloss.NewStyle().Foreground(lipgloss.Color("252"))

	return timeSt.Render(padCell(timeStr, colTime)) +
		actionSt.Render(padCell(action, colAction)) +
		protoSt.Render(padCell(e.Proto, colProto)) +
		addrSt.Render(padCell(e.Src, colSrc)) +
		addrSt.Render(padCell(e.Dst, colDst)) +
		portSt.Render(padCell(dpt, colDPT))
}

// actionStyle returns the foreground style for an action string.
func actionStyle(action string) lipgloss.Style {
	switch action {
	case "DROP", "REJECT":
		return StyleDrop.Bold(true)
	case "ACCEPT":
		return StyleAccept
	default:
		return lipgloss.NewStyle()
	}
}

// protoStyle returns the foreground style for a protocol string.
func protoStyle(proto string) lipgloss.Style {
	if proto == "ICMP" {
		return StyleICMP
	}
	return lipgloss.NewStyle().Foreground(lipgloss.Color("252"))
}

// padCell left-aligns s within exactly w terminal cells, truncating if needed.
func padCell(s string, w int) string {
	if len(s) > w-1 {
		s = s[:w-4] + "…"
	}
	return fmt.Sprintf("%-*s", w, s)
}

// scrollStart returns the first visible row index.
func scrollStart(total, cursor, rowsAvail int) int {
	if total <= rowsAvail {
		return 0
	}
	start := total - rowsAvail
	if cursor < start {
		start = cursor
	}
	if cursor >= start+rowsAvail {
		start = cursor - rowsAvail + 1
	}
	return start
}

// StyleMuted re-exports for use within this package.
var StyleMuted = lipgloss.NewStyle().Foreground(ColorMuted)
