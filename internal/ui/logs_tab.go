package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/espenotterstad/iptables-tui/internal/parser"
)

// Column widths in terminal cells (content + trailing padding).
// The 2-character gutter (cursor indicator + space) is NOT included here;
// both the header and every data row are prefixed with exactly 2 cells so
// all columns line up.
const (
	colTime   = 11 // "15:04:05" (8) + 3 gap
	colAction = 9  // "ACCEPT"   (6) + 3 gap
	colProto  = 7  // "ICMP"     (4) + 3 gap
	colSrc    = 18 // IPv4 max   (15) + 3 gap
	colDst    = 18 // same
	colDPT    = 7  // "65535"    (5) + 2 gap
)

// gutter is the fixed-width prefix prepended to every row (header and data).
// It reserves space for the cursor indicator so columns always align.
const gutterWidth = 2

// RenderLogsTab renders the full logs tab view (header + rows + detail overlay).
func RenderLogsTab(
	entries []parser.LogEntry,
	cursor int,
	showDetail bool,
	width, height int,
) string {
	var sb strings.Builder

	// ── Column header (with same gutter as data rows) ──────────────────────
	gutter := strings.Repeat(" ", gutterWidth)
	sb.WriteString(gutter + renderHeader())
	sb.WriteByte('\n')
	sb.WriteString(StyleDivider.Render(strings.Repeat("─", width)))
	sb.WriteByte('\n')

	// ── Scrolling window ───────────────────────────────────────────────────
	// Reserve: header(1) + divider(1) + bottom-divider(1) + help(1) = 4 lines.
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
			// ▶ is 1 terminal cell wide; pad to gutterWidth.
			prefix = lipgloss.NewStyle().Foreground(ColorStats).Render("▶") +
				strings.Repeat(" ", gutterWidth-1)
		} else {
			prefix = strings.Repeat(" ", gutterWidth)
		}
		sb.WriteString(prefix + renderDataRow(entries[i], selected))
		sb.WriteByte('\n')
	}

	// Pad remaining rows so the layout height stays constant.
	for i := end - start; i < rowsAvail; i++ {
		sb.WriteByte('\n')
	}

	view := sb.String()

	// ── Detail overlay ─────────────────────────────────────────────────────
	if showDetail && cursor >= 0 && cursor < len(entries) {
		view = overlayDetail(entries[cursor], view, width, height)
	}

	return view
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

// renderDataRow renders a single log entry as a table row (no gutter prefix).
// Each column is coloured independently; the selected row gets a uniform highlight.
func renderDataRow(e parser.LogEntry, selected bool) string {
	action := e.Action()
	timeStr := e.Timestamp.Format(time.TimeOnly)
	dpt := ""
	if e.DstPort != 0 {
		dpt = fmt.Sprintf("%d", e.DstPort)
	}

	if selected {
		// Uniform highlight: render as a single block so the background is continuous.
		return StyleSelected.Render(
			padCell(timeStr, colTime) +
				padCell(action, colAction) +
				padCell(e.Proto, colProto) +
				padCell(e.Src, colSrc) +
				padCell(e.Dst, colDst) +
				padCell(dpt, colDPT),
		)
	}

	// Non-selected: per-column colouring for quick visual parsing.
	timeSt := lipgloss.NewStyle().Foreground(ColorMuted)
	actionSt := actionStyle(action)
	protoSt := protoStyle(e.Proto)
	addrSt := lipgloss.NewStyle() // default terminal colour
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
// Uses len() which is correct for the ASCII content we render (times, IPs, ports).
func padCell(s string, w int) string {
	if len(s) > w-1 {
		s = s[:w-4] + "…" // truncate with ellipsis, keep 1-cell gap
	}
	return fmt.Sprintf("%-*s", w, s)
}

// scrollStart returns the first visible row index given the total entry count,
// cursor position, and available row height.
func scrollStart(total, cursor, rowsAvail int) int {
	if total <= rowsAvail {
		return 0
	}
	// Default: show the newest entries.
	start := total - rowsAvail
	// Scroll up if cursor is above the window.
	if cursor < start {
		start = cursor
	}
	// Scroll down if cursor is below the window.
	if cursor >= start+rowsAvail {
		start = cursor - rowsAvail + 1
	}
	return start
}

// overlayDetail draws a detail viewport centred over the existing view.
func overlayDetail(e parser.LogEntry, background string, width, height int) string {
	detail := buildDetailText(e)
	lines := strings.Split(detail, "\n")

	boxW := width * 3 / 4
	if boxW < 62 {
		boxW = 62
	}
	maxContent := height*2/3 - 2
	if maxContent < 8 {
		maxContent = 8
	}
	if len(lines) < maxContent {
		maxContent = len(lines)
	}

	content := strings.Join(lines[:maxContent], "\n")
	box := StyleOverlayBorder.Width(boxW - 4).Render(content)

	boxLines := strings.Split(box, "\n")
	bgLines := strings.Split(background, "\n")

	topPad := (height - len(boxLines)) / 3
	leftPad := (width - lipgloss.Width(boxLines[0])) / 2
	if leftPad < 0 {
		leftPad = 0
	}
	indent := strings.Repeat(" ", leftPad)

	for i, bl := range boxLines {
		row := topPad + i
		if row < len(bgLines) {
			bgLines[row] = indent + bl
		}
	}
	return strings.Join(bgLines, "\n")
}

// buildDetailText formats all fields of an entry for the overlay.
func buildDetailText(e parser.LogEntry) string {
	var sb strings.Builder
	field := func(k, v string) {
		sb.WriteString(StyleLabel.Render(fmt.Sprintf("%-11s", k+":")) + " " + v + "\n")
	}
	field("Timestamp", e.Timestamp.Format("2006-01-02 15:04:05"))
	field("Hostname", e.Hostname)
	field("Prefix", e.Prefix)
	field("Action", actionStyle(e.Action()).Render(e.Action()))
	field("In", e.In)
	field("Out", e.Out)
	field("Src", e.Src)
	field("Dst", e.Dst)
	field("Proto", protoStyle(e.Proto).Render(e.Proto))
	if e.SrcPort != 0 {
		field("SrcPort", fmt.Sprintf("%d", e.SrcPort))
	}
	if e.DstPort != 0 {
		field("DstPort", fmt.Sprintf("%d", e.DstPort))
	}
	if e.TTL != 0 {
		field("TTL", fmt.Sprintf("%d", e.TTL))
	}
	if e.Len != 0 {
		field("Len", fmt.Sprintf("%d", e.Len))
	}
	sb.WriteString("\n" + StyleMuted.Render("Esc to close"))
	return sb.String()
}

// StyleMuted re-exports for use within this package.
var StyleMuted = lipgloss.NewStyle().Foreground(ColorMuted)

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
