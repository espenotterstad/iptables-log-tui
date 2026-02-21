package ui

import "github.com/charmbracelet/lipgloss"

var (
	// ColorDrop is used for DROP / BLOCK entries.
	ColorDrop = lipgloss.Color("9") // bright red
	// ColorAccept is used for ACCEPT entries.
	ColorAccept = lipgloss.Color("10") // bright green
	// ColorICMP is used for ICMP entries.
	ColorICMP = lipgloss.Color("11") // bright yellow
	// ColorStats is used for counter values in the Stats tab.
	ColorStats = lipgloss.Color("14") // bright cyan
	// ColorMuted is used for de-emphasised text.
	ColorMuted = lipgloss.Color("240")
	// ColorHeader is used for column header text.
	ColorHeader = lipgloss.Color("15") // white

	// StyleTabActive is applied to the currently selected tab label.
	StyleTabActive = lipgloss.NewStyle().
			Bold(true).
			Underline(true).
			Foreground(lipgloss.Color("15"))

	// StyleTabInactive is applied to non-selected tab labels.
	StyleTabInactive = lipgloss.NewStyle().
				Foreground(ColorMuted)

	// StyleTitle is the application title in the top-right corner.
	StyleTitle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("12"))

	// StyleDivider renders a full-width horizontal rule.
	StyleDivider = lipgloss.NewStyle().
			Foreground(ColorMuted)

	// StyleDrop styles a DROP row cell.
	StyleDrop = lipgloss.NewStyle().Foreground(ColorDrop)

	// StyleAccept styles an ACCEPT row cell.
	StyleAccept = lipgloss.NewStyle().Foreground(ColorAccept)

	// StyleICMP styles an ICMP row cell.
	StyleICMP = lipgloss.NewStyle().Foreground(ColorICMP)

	// StyleSelected styles the selected / cursor row.
	StyleSelected = lipgloss.NewStyle().
			Bold(true).
			Background(lipgloss.Color("236")).
			Foreground(lipgloss.Color("15"))

	// StyleLabel is used for field names in the detail overlay.
	StyleLabel = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorStats)

	// StyleHelp is the footer help bar.
	StyleHelp = lipgloss.NewStyle().
			Foreground(ColorMuted)

	// StyleFilter is used to display active filter labels.
	StyleFilter = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("13"))

	// StyleOverlayBorder is the border around the detail overlay.
	StyleOverlayBorder = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(ColorStats).
				Padding(0, 1)

	// StyleStatValue renders stat counter values.
	StyleStatValue = lipgloss.NewStyle().Foreground(ColorStats).Bold(true)

	// StyleStatLabel renders stat counter labels.
	StyleStatLabel = lipgloss.NewStyle().Foreground(lipgloss.Color("252"))
)

// RowStyle returns the appropriate Lip Gloss style for a log entry row based
// on its action and protocol, with an extra selected highlight if needed.
func RowStyle(action, proto string, selected bool) lipgloss.Style {
	var base lipgloss.Style
	switch action {
	case "DROP", "REJECT":
		base = StyleDrop
	case "ACCEPT":
		base = StyleAccept
	default:
		if proto == "ICMP" {
			base = StyleICMP
		} else {
			base = lipgloss.NewStyle()
		}
	}
	if proto == "ICMP" && action != "DROP" && action != "ACCEPT" {
		base = StyleICMP
	}
	if selected {
		base = base.Background(lipgloss.Color("236")).Bold(true)
	}
	return base
}
